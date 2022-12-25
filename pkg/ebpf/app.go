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
	"strings"

	"github.com/slankdev/hyperplane/pkg/util"
	"github.com/spf13/cobra"
)

//go:embed code
var codeFS embed.FS

var files []string

func NewCommand(name, file string) *cobra.Command {
	cmd := &cobra.Command{
		Use: name,
	}
	cmd.AddCommand(newCommandAttach(file))
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

func newCommandAttach(file string) *cobra.Command {
	var clioptInterface string
	var clioptDebug bool
	cmd := &cobra.Command{
		Use: "attach",
		RunE: func(cmd *cobra.Command, args []string) error {
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

			// copy bpf c code
			for _, file := range files {
				f, err := codeFS.ReadFile(file)
				if err != nil {
					return err
				}
				if err := writeFile(fmt.Sprintf("%s/%s", tmppath, file), f); err != nil {
					return err
				}
			}

			// build with some special parameter
			cflags := "-target bpf -O3 -g -I /usr/include/x86_64-linux-gnu"
			if clioptDebug {
				cflags += " -DDEBUG"
			}
			if _, err := util.LocalExecutef(
				"clang %s -c %s/code/%s -o %s/bin/out.o",
				cflags, tmppath, file, tmppath); err != nil {
				return err
			}

			// TODO(slankdev): implement me
			// attach on specified network interface
			fmt.Printf("bind %s\n", clioptInterface)

			return nil
		},
	}
	cmd.Flags().StringVarP(&clioptInterface, "interface", "i", "", "")
	cmd.Flags().BoolVarP(&clioptDebug, "debug", "d", false, "")
	return cmd
}

func writeFile(filepath string, content []byte) error {
	words := strings.Split(filepath, "/")
	wordsDir := words[:len(words)-1]
	dir := ""
	for _, word := range wordsDir {
		dir = fmt.Sprintf("%s/%s", dir, word)
	}
	if err := os.MkdirAll(dir, 0777); err != nil {
		return err
	}
	if err := ioutil.WriteFile(filepath, content, os.ModePerm); err != nil {
		return err
	}
	return nil
}
