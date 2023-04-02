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
	"net"
	"net/http"
	"syscall"

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

func NewCmdNc() *cobra.Command {
	var clioptPort int
	cmd := &cobra.Command{
		Use: "nc",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("starting ...\n")
			return Fn0()
		},
		SilenceUsage: true,
	}
	cmd.Flags().IntVarP(&clioptPort, "port", "p", 8080, "")
	return cmd
}

func Fn() error {
	udpServer, err := net.ListenPacket("udp", ":9999")
	if err != nil {
		return err
	}
	defer udpServer.Close()

	for {
		buf := make([]byte, 1024)
		_, addr, err := udpServer.ReadFrom(buf)
		if err != nil {
			continue
		}
		fmt.Printf("%s: %s", addr, string(buf))
	}

	return nil

}

func Fn0() error {
	addr := net.UDPAddr{
		Port: 9999,
		IP:   net.ParseIP("0.0.0.0"),
	}

	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		fmt.Printf("Error creating UDP server: %v\n", err)
		return err
	}

	// set buffer size using setsockopt
	fd, err := conn.File()
	if err != nil {
		fmt.Printf("Error getting file descriptor: %v\n", err)
		return err
	}

	if err := syscall.SetsockoptInt(int(fd.Fd()), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4096); err != nil {
		fmt.Printf("Error setting buffer size: %v\n", err)
		return err
	}
	if err := syscall.SetsockoptInt(int(fd.Fd()), syscall.SOL_SOCKET, syscall.SO_NO_CHECK, 1); err != nil {
		fmt.Printf("Error setting buffer size: %v\n", err)
		return err
	}

	for {
		buf := make([]byte, 1024)
		_, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Printf("Error reading from UDP: %v\n", err)
			continue
		}
		fmt.Printf("Received message from %s: %s", addr.String(), string(buf))
	}
}
