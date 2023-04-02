/*
Copyright 2022 Hiroki Shirokura.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ebpf

import (
	"embed"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/slankdev/hyperplane/pkg/goroute2"
	"github.com/slankdev/hyperplane/pkg/util"
)

//go:embed code
var codeFS embed.FS

var files []string

func NewCommandXdp(name, file, section string) *cobra.Command {
	cmd := &cobra.Command{
		Use: name,
	}
	cmd.AddCommand(newCommandXdpAttach("attach", file, section))
	cmd.AddCommand(NewCommandXdpDetach("detach"))
	return cmd
}

func init() {
	// XXX: no support for depth>2
	ents, err := codeFS.ReadDir("code")
	if err != nil {
		panic(err)
	}
	for _, ent := range ents {
		name := ent.Name()
		if ent.IsDir() {
			subpath := fmt.Sprintf("code/%s", name)
			subents, err := codeFS.ReadDir(subpath)
			if err != nil {
				panic(err)
			}
			for _, subent := range subents {
				subname := subent.Name()
				if !subent.IsDir() {
					files = append(files, fmt.Sprintf("code/%s/%s", name, subname))
				}
			}
		} else {
			files = append(files, fmt.Sprintf("code/%s", name))
		}
	}
}

func newCommandXdpAttach(name, file, section string) *cobra.Command {
	var clioptInterface string
	var clioptDebug bool
	var clioptDebugIgnorePacket bool
	var clioptDebugErrorPacket bool
	var clioptForce bool
	var clioptVerbose bool
	var clioptMode string
	var clioptName string
	cmd := &cobra.Command{
		Use: name,
		RunE: func(cmd *cobra.Command, args []string) error {
			// init logger
			logger, _ := zap.NewProduction()
			defer logger.Sync()
			log := logger.Sugar()

			// create temp dir
			if err := os.MkdirAll("/var/run/mfplane", 0777); err != nil {
				return err
			}
			tmppath, err := ioutil.TempDir("/var/run/mfplane", "")
			if err != nil {
				return err
			}
			if err := os.MkdirAll(fmt.Sprintf("%s/bin", tmppath), 0777); err != nil {
				return err
			}
			if clioptVerbose {
				log.Info("create tmp dir", "path", tmppath)
			}

			// copy bpf c code
			for _, file := range files {
				f, err := codeFS.ReadFile(file)
				if err != nil {
					return err
				}
				if err := util.WriteFile(fmt.Sprintf("%s/%s", tmppath, file),
					f); err != nil {
					return err
				}
			}
			if clioptVerbose {
				log.Info("write c files", "path", tmppath)
			}

			// build with some special parameter
			// TODO(slankdev): cflags += " -nostdinc" for less dependency
			cflags := "-target bpf -O2 -g -I /usr/include/x86_64-linux-gnu"
			cflags += " -D NAME=" + clioptName
			if clioptDebug {
				cflags += " -DDEBUG"
			}
			if clioptDebugIgnorePacket {
				cflags += " -DDEBUG_IGNORE_PACKET"
			}
			if clioptDebugErrorPacket {
				cflags += " -DDEBUG_ERROR_PACKET"
			}
			if _, err := util.LocalExecutef(
				"clang %s -c %s/code/%s -o %s/bin/out.o",
				cflags, tmppath, file, tmppath); err != nil {
				return err
			}
			if clioptVerbose {
				log.Info("build c files",
					"main", fmt.Sprintf("%s/code/%s", tmppath, file),
					"out", fmt.Sprintf("%s/bin/out.o", tmppath),
					"cflags", cflags)
			}

			// detach once if force-mode
			if clioptForce {
				if _, err := util.LocalExecutef("ip link set %s %s off",
					clioptInterface, clioptMode); err != nil {
					return err
				}
				if clioptVerbose {
					log.Info("detach once", "netdev", clioptInterface)
				}
			}

			// attach on specified network interface
			if _, err := util.LocalExecutef(
				"ip link set %s %s obj %s/bin/out.o sec %s",
				clioptInterface, clioptMode, tmppath, section); err != nil {
				return err
			}
			if clioptVerbose {
				log.Info("attach once", "netdev", clioptInterface, "section", section)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&clioptName, "name", "n", "updateme000", "")
	cmd.Flags().StringVarP(&clioptInterface, "interface", "i", "", "")
	cmd.Flags().StringVarP(&clioptMode, "mode", "m", "xdpgeneric",
		"xdp  or xdpgeneric")
	cmd.Flags().BoolVarP(&clioptVerbose, "verbose", "v", false, "")
	cmd.Flags().BoolVarP(&clioptDebug, "debug", "d", false, "")
	cmd.Flags().BoolVarP(&clioptForce, "force", "f", false,
		"if attached, once detach and try force attach the bpf code")
	cmd.Flags().BoolVar(&clioptDebugIgnorePacket, "debug-ignore-packet", false, "")
	cmd.Flags().BoolVar(&clioptDebugErrorPacket, "debug-error-packet", false, "")
	return cmd
}

func NewCommandXdpDetach(name string) *cobra.Command {
	var clioptInterface string
	var clioptMode string
	var clioptDebug bool
	var clioptVerbose bool
	cmd := &cobra.Command{
		Use: name,
		RunE: func(cmd *cobra.Command, args []string) error {
			// init logger
			logger, _ := zap.NewProduction()
			defer logger.Sync()
			log := logger.Sugar()

			link, err := goroute2.GetLinkDetail("", clioptInterface)
			if err != nil {
				return err
			}
			if link.Xdp != nil {
				if _, err := util.LocalExecutef(
					"ip link set %s %s off", clioptInterface,
					link.Xdp.Mode.ModeString()); err != nil {
					return err
				}
				if clioptVerbose {
					log.Info("detach once", "netdev", clioptInterface)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&clioptInterface, "interface", "i", "", "")
	cmd.Flags().StringVarP(&clioptMode, "mode", "m", "xdpgeneric",
		"xdp  or xdpgeneric")
	cmd.Flags().BoolVarP(&clioptVerbose, "verbose", "v", false, "")
	cmd.Flags().BoolVarP(&clioptDebug, "debug", "d", false, "")
	return cmd
}

func BatchMapOperation(mapname string, maptype ebpf.MapType,
	f func(m *ebpf.Map) error) error {
	ids, err := GetMapIDsByNameType(mapname, maptype)
	if err != nil {
		return err
	}
	for _, id := range ids {
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			return err
		}
		if err := f(m); err != nil {
			return err
		}
	}
	return nil
}

func UpdatePerCPUArrayAll(m *ebpf.Map, key interface{}, value interface{},
	flags ebpf.MapUpdateFlags) error {
	percpuval := []interface{}{}
	for i := 0; i < runtime.NumCPU(); i++ {
		percpuval = append(percpuval, value)
	}
	return m.Update(key, percpuval, flags)
}

func GetMapIDsByNameType(mapName string, mapType ebpf.MapType) ([]ebpf.MapID, error) {
	ids := []ebpf.MapID{}
	for id := ebpf.MapID(0); ; {
		var err error
		id, err = ebpf.MapGetNextID(ebpf.MapID(id))
		if err != nil {
			break
		}
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			return nil, err
		}
		info, err := m.Info()
		if err != nil {
			return nil, err
		}
		if err := m.Close(); err != nil {
			return nil, err
		}

		if info.Name != mapName || info.Type != mapType {
			continue
		}
		ids = append(ids, id)
	}
	return ids, nil
}

type PerfObject struct {
	MapID  ebpf.MapID
	Record perf.Record
}

func StartReaderPerMap(mapID ebpf.MapID, poCh chan PerfObject) error {
	m, err := ebpf.NewMapFromID(mapID)
	if err != nil {
		return err
	}
	defer m.Close()

	rd, err := perf.NewReader(m, 4096)
	if err != nil {
		return err
	}
	defer rd.Close()

	for {
		rec, err := rd.Read()
		if err != nil {
			return err
		}
		po := PerfObject{
			MapID:  mapID,
			Record: rec,
		}
		poCh <- po
	}
}

func StartReader(name string) (chan PerfObject, error) {
	ids, err := GetMapIDsByNameType(name, ebpf.PerfEventArray)
	if err != nil {
		return nil, err
	}

	poCh := make(chan PerfObject, 10)
	for _, id := range ids {
		go func(id ebpf.MapID) {
			for {
				if err := StartReaderPerMap(id, poCh); err != nil {
					fmt.Printf("FAIL: %s ... ignored", err.Error())
				}
			}
		}(id)
	}

	return poCh, nil
}
