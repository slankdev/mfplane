/*
Copyright 2022 Hiroki Shirokura.
Copyright 2022 Wide Project.

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

package util

import (
	"fmt"
	"io"
	"net/http"

	"github.com/spf13/cobra"
)

func NewCmdIfconfigHTTPServer() *cobra.Command {
	var clioptPort int
	cmd := &cobra.Command{
		Use: "ifconfig-http",
		RunE: func(cmd *cobra.Command, args []string) error {
			http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, fmt.Sprintf("%s\n", r.RemoteAddr))
			})
			return http.ListenAndServe(fmt.Sprintf(":%d", clioptPort), nil)
		},
		SilenceUsage: true,
	}
	cmd.Flags().IntVarP(&clioptPort, "port", "p", 8080, "")
	return cmd
}
