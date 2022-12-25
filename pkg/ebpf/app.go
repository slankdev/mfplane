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
	"fmt"

	"github.com/spf13/cobra"
)

func NewCommand(name, file string) *cobra.Command {
	cmd := &cobra.Command{
		Use: name,
	}
	cmd.AddCommand(newCommandAttach(file))
	return cmd
}

func newCommandAttach(file string) *cobra.Command {
	var clioptInterface string
	cmd := &cobra.Command{
		Use: "attach",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("hello %s %s\n", file, clioptInterface)

			// TODO(slankdev): implement me
			// create temp dir
			// copy lib files
			// copy main.c files
			// build with some special parameter
			// attach on specified network interface

			return nil
		},
	}
	cmd.Flags().StringVarP(&clioptInterface, "interface", "i", "", "")
	return cmd
}
