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
	"io/ioutil"

	"github.com/k0kubun/pp"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/slankdev/hyperplane/pkg/ebpf"
	"github.com/slankdev/hyperplane/pkg/util"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "mikanectl",
	}
	cmd.AddCommand(NewCommandHash())
	cmd.AddCommand(NewCommandBpf())
	cmd.AddCommand(NewCommandMapLoad())
	cmd.AddCommand(NewCommandMapDump())
	cmd.AddCommand(util.NewCommandVersion())
	cmd.AddCommand(util.NewCmdCompletion(cmd))
	return cmd
}

func NewCommandBpf() *cobra.Command {
	cmd := &cobra.Command{
		Use: "bpf",
	}
	cmd.AddCommand(ebpf.NewCommandXdp("nat", "nat_main.c", "xdp-ingress"))
	cmd.AddCommand(ebpf.NewCommandXdp("clb", "clb_main.c", "xdp-ingress"))
	return cmd
}

type Config struct {
	MaxRules    int `yaml:"maxRules"`
	MaxBackends int `yaml:"maxBackends"`
	LocalSids   []struct {
		Sid     string `yaml:"sid"`
		End_MFL *struct {
			Backends []string `yaml:"backends"`
		} `yaml:"End_MFL"`
	} `yaml:"localSids"`
}

func NewCommandMapDump() *cobra.Command {
	cmd := &cobra.Command{
		Use: "map-dump",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}
	return cmd
}

func NewCommandMapLoad() *cobra.Command {
	var clioptFile string
	cmd := &cobra.Command{
		Use: "map-load",
		RunE: func(cmd *cobra.Command, args []string) error {
			bdata, err := ioutil.ReadFile(clioptFile)
			if err != nil {
				return err
			}

			config := Config{}
			if err := yaml.Unmarshal(bdata, &config); err != nil {
				return err
			}

			pp.Println(config)
			return nil
		},
	}
	cmd.Flags().StringVarP(&clioptFile, "file", "f", "", "")
	return cmd
}
