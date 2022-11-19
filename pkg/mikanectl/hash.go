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

package mikanectl

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/slankdev/hyperplane/pkg/maglev"
	"github.com/slankdev/hyperplane/pkg/util"
)

func NewCommandHash() *cobra.Command {
	cmd := &cobra.Command{
		Use: "hash",
	}
	cmd.AddCommand(NewCommandHashPlayground())
	return cmd
}

func NewCommandHashPlayground() *cobra.Command {
	var clioptNumTestdatas int
	var clioptNumBackends int
	var clioptTableSize int
	var clioptVerbose bool
	cmd := &cobra.Command{
		Use: "playground",
		RunE: func(cmd *cobra.Command, args []string) error {
			names := []string{}
			for i := 0; i < clioptNumBackends; i++ {
				names = append(names, fmt.Sprintf("backend-%d", i))
			}

			m, err := maglev.NewMaglev(names, uint64(clioptTableSize))
			if err != nil {
				return err
			}

			test := func(cnt int) []string {
				backends := []string{}
				for i := 0; i < cnt; i++ {
					obj := fmt.Sprintf("ip%d", i)
					backend := m.GetOrDie(obj)
					backends = append(backends, backend)
				}
				return backends
			}

			table1 := m.GetRawTable()
			be1 := test(clioptNumTestdatas)
			m.RemoveOrDie("backend-4")
			table2 := m.GetRawTable()
			be2 := test(clioptNumTestdatas)

			if clioptVerbose {
				table := util.NewTableWriter(os.Stdout)
				table.SetHeader([]string{"slot", "rev1", "rev2", "diff"})
				for idx := range table1 {
					mark := ""
					if table1[idx] != table2[idx] {
						mark = "*"
					}
					table.Append([]string{
						fmt.Sprintf("%05d", idx),
						fmt.Sprintf("%05d", table1[idx]),
						fmt.Sprintf("%05d", table2[idx]),
						mark,
					})
				}
				table.Render()
			}

			cntDiff := 0
			if clioptVerbose {
				fmt.Println("----------")
			}
			for i := 0; i < clioptNumTestdatas; i++ {
				diff := ""
				if be1[i] != be2[i] {
					cntDiff++
					diff = "\tDIFF"
				}
				if clioptVerbose {
					fmt.Printf("ip%d\t%s\t%s%s\n", i, be1[i], be2[i], diff)
				}
			}
			if clioptVerbose {
				fmt.Println("----------")
			}
			fmt.Printf("diff radio %f\n", (float32(cntDiff) / float32(clioptNumTestdatas)))

			return nil
		},
	}
	cmd.Flags().IntVarP(&clioptNumTestdatas, "num-tests", "n", 100, "")
	cmd.Flags().IntVarP(&clioptNumBackends, "num-backends", "b", 16, "")
	cmd.Flags().IntVarP(&clioptTableSize, "table-size", "t", int(maglev.BigM), "")
	cmd.Flags().BoolVarP(&clioptVerbose, "verbose", "v", false, "")
	return cmd
}
