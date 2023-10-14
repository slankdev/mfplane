/*
Copyright 2023 Hiroki Shirokura.

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

package main

import (
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/slankdev/mfplane/pkg/goroute2"
	"github.com/slankdev/mfplane/pkg/util"
)

func main() {
	rand.Seed(time.Now().UnixNano())
	if err := NewCommand().Execute(); err != nil {
		os.Exit(1)
	}
}

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "ip3",
	}
	cmd.AddCommand(NewCommandStat())
	cmd.AddCommand(util.NewCommandVersion())
	cmd.AddCommand(util.NewCmdCompletion(cmd))
	return cmd
}

func NewCommandStat() *cobra.Command {
	cmd := &cobra.Command{
		Use: "stat",
		RunE: func(cmd *cobra.Command, args []string) error {
			tab := util.NewTableWriter(os.Stdout)
			tab.SetHeader([]string{"name", "rx", "tx"})
			statList, err := goroute2.GetLinkStatsList("")
			if err != nil {
				return err
			}
			for _, stat := range statList {
				tab.Append([]string{
					stat.Ifname,
					fmt.Sprintf("%d", stat.Stats64.Rx.Packets),
					fmt.Sprintf("%d", stat.Stats64.Tx.Packets),
				})
			}
			tab.Render()
			return nil
		},
	}
	return cmd
}
