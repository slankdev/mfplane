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

package mfpctl

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/slankdev/mfplane/pkg/ebpf"
	"github.com/slankdev/mfplane/pkg/util"
)

var (
	timeoutDuration = time.Duration(10 * time.Second)
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "mfpctl",
	}
	cmd.AddCommand(NewCommandBpf())
	cmd.AddCommand(NewCommandDaemon())
	cmd.AddCommand(util.NewCommandVersion())
	cmd.AddCommand(util.NewCmdCompletion(cmd))
	cmd.AddCommand(util.NewCmdNetTools("net-tools"))
	return cmd
}

func NewCommandBpf() *cobra.Command {
	cmd := &cobra.Command{
		Use: "bpf",
	}
	cmd.AddCommand(NewCommandBpfXdp())
	cmd.AddCommand(ebpf.NewCommandBpfMap())
	return cmd
}

func NewCommandBpfXdp() *cobra.Command {
	cmd := &cobra.Command{
		Use: "xdp",
	}
	cmd.AddCommand(ebpf.NewCommandXdpDetach("detach"))
	cmd.AddCommand(ebpf.NewCommandXdpAttach("attach"))
	return cmd
}
