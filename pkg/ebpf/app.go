/*
Copyright 2023 Hiroki Shirokura.
Copyright 2023 Kyoto University.

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
	"os"
	"path/filepath"
	"regexp"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/slankdev/mfplane/pkg/goroute2"
	"github.com/slankdev/mfplane/pkg/util"
)

//go:embed code
var codeFS embed.FS

var files []string

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

func NewCommandXdpAttach(name string) *cobra.Command {
	cmd := &cobra.Command{
		Use: name,
	}
	s := "xdp_ingress"
	cmd.AddCommand(NewCommandXdpAttachOne("common", "common_main.c", s))
	cmd.AddCommand(NewCommandXdpAttachOne("dummy", "dummy_main.c", s))
	cmd.AddCommand(NewCommandXdpAttachOne("test", "test_main.c", s))
	cmd.AddCommand(NewCommandXdpAttachOne("nat", "nat_main.c", s))
	cmd.AddCommand(NewCommandXdpAttachOne("clb", "clb_main.c", s))
	return cmd
}

func NewCommandXdpAttachOne(name, file, section string) *cobra.Command {
	var clioptInterface string
	var clioptDebug bool
	var clioptDebugIgnorePacket bool
	var clioptDebugErrorPacket bool
	var clioptForce bool
	var clioptVerbose bool
	var clioptMode string
	var clioptName string
	var clioptNetns string
	var clioptDefine []string
	cmd := &cobra.Command{
		Use: name,
		RunE: func(cmd *cobra.Command, args []string) error {
			// init logger
			logger, _ := zap.NewProduction()
			defer logger.Sync()
			log := logger.Sugar()
			if clioptVerbose {
				util.SetLocalExecuteSilence(false)
			}

			// Build ebpf program
			tmppath, err := Build(log, file,
				clioptVerbose,
				clioptDebug,
				clioptName,
				clioptDebugIgnorePacket,
				clioptDebugErrorPacket,
				clioptDefine,
			)
			if err != nil {
				return err
			}

			// detach once if force-mode
			if clioptForce {
				if err := XdpDetach(clioptNetns, clioptInterface); err != nil {
					return err
				}
				if clioptVerbose {
					log.Info("detach once", "netdev", clioptInterface)
				}
			}

			// attach on specified network interface
			if err := XdpAttach(clioptNetns, clioptInterface,
				fmt.Sprintf("%s/bin/out.o", tmppath), section,
				clioptMode); err != nil {
				return err
			}
			if clioptVerbose {
				log.Info("attach once", "netdev", clioptInterface, "section", section)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&clioptName, "name", "n", "updateme000", "")
	f.StringVarP(&clioptInterface, "interface", "i", "", "")
	f.StringVarP(&clioptNetns, "netns", "N", "", "")
	f.StringVarP(&clioptMode, "mode", "m", "xdpgeneric", "xdp  or xdpgeneric")
	f.BoolVarP(&clioptVerbose, "verbose", "v", false, "")
	f.BoolVarP(&clioptDebug, "debug", "d", false, "")
	f.BoolVarP(&clioptForce, "force", "f", false,
		"if attached, once detach and try force attach the bpf code")
	f.BoolVar(&clioptDebugIgnorePacket, "debug-ignore-packet", false, "")
	f.BoolVar(&clioptDebugErrorPacket, "debug-error-packet", false, "")
	f.StringArrayVar(&clioptDefine, "define", []string{},
		"i.e. --define DEBUG_FUNCTION_CALL")
	return cmd
}

func NewCommandBpfMap() *cobra.Command {
	cmd := &cobra.Command{
		Use: "map",
	}
	cmd.AddCommand(NewCommandMapList())
	cmd.AddCommand(NewCommandMapUnlink())
	cmd.AddCommand(NewCommandMapSet())
	cmd.AddCommand(NewCommandMapSetAuto())
	cmd.AddCommand(NewCommandMapInspect())
	cmd.AddCommand(NewCommandMapInspectAuto())
	cmd.AddCommand(NewCommandMapFlush())
	return cmd
}

func NewCommandMapList() *cobra.Command {
	var clioptDebug bool
	var clioptVerbose bool
	var clioptPinDir string
	cmd := &cobra.Command{
		Use: "list",
		RunE: func(cmd *cobra.Command, args []string) error {
			mapFiles := []string{}
			files, err := os.ReadDir(clioptPinDir)
			if err != nil {
				return err
			}
			for _, file := range files {
				if !file.IsDir() {
					mapFiles = append(mapFiles, filepath.Join(clioptPinDir, file.Name()))
				}
			}
			table := util.NewTableWriter(os.Stdout)
			table.SetHeader([]string{"name", "id", "type", "file"})
			for _, f := range mapFiles {
				m, err := ebpf.LoadPinnedMap(f, nil)
				if err != nil {
					return err
				}
				info, err := m.Info()
				if err != nil {
					return err
				}
				id, _ := info.ID()
				table.Append([]string{
					info.Name,
					fmt.Sprintf("%d", id),
					info.Type.String(),
					f,
				})
			}
			table.Render()
			return nil
		},
	}
	cmd.Flags().BoolVarP(&clioptVerbose, "verbose", "v", false, "")
	cmd.Flags().BoolVarP(&clioptDebug, "debug", "d", false, "")
	cmd.Flags().StringVarP(&clioptPinDir, "pin", "p",
		"/sys/fs/bpf/xdp/globals", "pinned map root dir")
	return cmd
}

func NewCommandMapUnlink() *cobra.Command {
	var clioptDryRun bool
	var clioptMatch string
	var clioptPinDir string
	cmd := &cobra.Command{
		Use: "unlink",
		RunE: func(cmd *cobra.Command, args []string) error {
			files, err := os.ReadDir(clioptPinDir)
			if err != nil {
				return err
			}

			// Compile match regex
			r, err := regexp.Compile(clioptMatch)
			if err != nil {
				return err
			}

			// Filter map files
			toBeDeleted := []string{}
			for _, file := range files {
				if !file.IsDir() {
					if r.MatchString(file.Name()) {
						toBeDeleted = append(toBeDeleted, file.Name())
					}
				}
			}

			// Delete files
			for _, name := range toBeDeleted {
				fullpath := filepath.Join(clioptPinDir, name)
				fmt.Printf("Deleting %s\n", fullpath)
				if !clioptDryRun {
					if err := os.Remove(fullpath); err != nil {
						return err
					}
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&clioptDryRun, "dry", "d", false, "dry-run mode")
	cmd.Flags().StringVarP(&clioptMatch, "match", "m", "", "regex for map name")
	cmd.Flags().StringVarP(&clioptPinDir, "pin", "p",
		"/sys/fs/bpf/xdp/globals", "pinned map root dir")
	return cmd
}

func NewCommandXdpDetach(name string) *cobra.Command {
	var clioptInterface string
	var clioptMode string
	var clioptNetns string
	var clioptDebug bool
	var clioptVerbose bool
	cmd := &cobra.Command{
		Use: name,
		RunE: func(cmd *cobra.Command, args []string) error {
			// init logger
			logger, _ := zap.NewProduction()
			defer logger.Sync()
			log := logger.Sugar()

			link, err := goroute2.GetLinkDetail(clioptNetns, clioptInterface)
			if err != nil {
				return err
			}
			if link.Xdp != nil {
				if err := XdpDetach(clioptNetns, clioptInterface); err != nil {
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
	cmd.Flags().StringVarP(&clioptNetns, "netns", "N", "", "")
	cmd.Flags().BoolVarP(&clioptVerbose, "verbose", "v", false, "")
	cmd.Flags().BoolVarP(&clioptDebug, "debug", "d", false, "")
	return cmd
}

func BatchPinnedMapOperation(mapfile string,
	f func(m *ebpf.Map) error) error {
	m, err := ebpf.LoadPinnedMap(mapfile, nil)
	if err != nil {
		return err
	}
	if err := f(m); err != nil {
		return err
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

func NewCommandMapSetAuto() *cobra.Command {
	var clioptFile string
	cmd := &cobra.Command{
		Use: "set-auto",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Read input file
			fileContent, err := os.ReadFile(clioptFile)
			if err != nil {
				return err
			}

			// Parse input file
			entries := MapGeneric{}
			if err := util.YamlUnmarshalViaJson(fileContent, &entries); err != nil {
				return err
			}

			// Set maps
			if err := WriteAll(&entries); err != nil {
				return err
			}

			return nil
		},
	}
	cmd.Flags().StringVarP(&clioptFile, "file", "f", "", "")
	return cmd
}

func NewCommandMapInspectAuto() *cobra.Command {
	var clioptPinDir string
	cmd := &cobra.Command{
		Use: "inspect-auto",
		RunE: func(cmd *cobra.Command, args []string) error {
			all, err := ReadAll(clioptPinDir)
			if err != nil {
				return err
			}
			util.Jprintln(all)
			return nil
		},
	}
	cmd.Flags().StringVarP(&clioptPinDir, "pin", "p",
		"/sys/fs/bpf/xdp/globals", "pinned map root dir")
	return cmd
}
