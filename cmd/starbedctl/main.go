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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/k0kubun/pp"
	"github.com/spf13/cobra"

	"github.com/slankdev/mfplane/pkg/util"
)

type AuthLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthLoginResponse struct {
	AccessToken  string `json:"accessToken"`
	Expire       string `json:"expire"`
	RefreshToken string `json:"refreshToken"`
	User         struct {
		Name     string   `json:"name"`
		Role     string   `json:"role"`
		Projects []string `json:"projects"`
	} `json:"user"`
}

type Infra struct {
	Type        string         `json:"type"`
	Name        string         `json:"name"`
	Version     float32        `json:"version"`
	ProjectName string         `json:"projectName"`
	State       string         `json:"state"`
	Time        string         `json:"time"`
	Nodes       []InfraNode    `json:"nodes"`
	Networks    []InfraNetwork `json:"networks"`
}

type InfraNode map[string]interface{}

// {
//   "name": "HVNode1",
//   "type": "Physical",
//   "os": "ubuntu-server-20.04-kvm-host",
//   "group": null,
//   "nodeName": "w001",
//   "host": null,
//   "facilities": [],
//   "smbios": null,
//   "cpu": null,
//   "mem": null,
//   "state": "setup-physical-os",
//   "interfaces": [
//   	{
//   		"macAddress": "B4:96:91:BA:10:70",
//   		"name": "bus31.0",
//   		"vlanId": 3671,
//   		"ipAddress": "192.168.0.101",
//   		"subnet": 24,
//   		"mtu": null,
//   		"networkName": "Control",
//   		"purpose": "Experiment",
//   		"sshIpAddress": null,
//   		"sshPort": null
//   	}
//   ],
//   "hostNode": null,
//   "resource": {
//   	"group": "W",
//   	"nodeName": "w001",
//   	"powerControl": {
//   		"purposes": [],
//   		"type": "iDRAC",
//   		"port": null,
//   		"macAddress": null,
//   		"ipAddress": "172.16.13.1"
//   	},
//   	"interfaces": [
//   		{
//   			"purposes": [
//   				"Management",
//   				"Pxe"
//   			],
//   			"type": null,
//   			"port": "bus4.0",
//   			"macAddress": "B0:7B:25:DD:CF:74",
//   			"ipAddress": "172.16.3.1"
//   		}
//   	],
//   	"storages": [
//   		{
//   			"path": "pci-0000:65:00.0-scsi-0:2:0:0",
//   			"media": "SSD",
//   			"capacity": "446.64 GiB",
//   			"letters": [],
//   			"purposes": [
//   				"Boot"
//   			],
//   			"letter": "sda"
//   		}
//   	]
//   },
//   "osDefinition": {
//   	"name": "ubuntu-server-20.04-kvm-host",
//   	"title": "Ubuntu Server 20.04 - KVM host",
//   	"details": {
//   		"operatingSystem": "Ubuntu",
//   		"version": "20.04",
//   		"hypervisors": []
//   	},
//   	"description": "Ubuntu Server 20.04をベースに、KVMホストをインストール済みの環境です。",
//   	"size": "7GB",
//   	"installMethod": "pxe-dd",
//   	"imageUrl": "nfs://172.16.64.245/usr/local/starbed_os/os_pool/ubuntu-kvm.gz",
//   	"domainUrl": null,
//   	"scope": null,
//   	"project": null
//   }
//}

type InfraNetwork struct {
	Name  string `json:"name"`
	Vlan  int    `json:"vlan"`
	Nodes []struct {
		Name      string `json:"name"`
		Interface string `json:"interface"`
		IpAddress string `json:"ipAddress"`
		Mtu       int    `json:"mtu"`
	} `json:"nodes"`
}

type JobsResponse []map[string]interface{}

type ResourcesResponse struct {
	Nodes []NodeResource `json:"nodes"`
	Vlans []int          `json:"vlans"`
}

type NodeResource struct {
	Group        string          `json:"group"`
	NodeName     string          `json:"nodeName"`
	PowerControl NodeInterface   `json:"powerControl"`
	Interfaces   []NodeInterface `json:"interfaces"`
	Storages     []NodeStorage   `json:"storages"`
}

type NodeInterface struct {
	IpAddress  string   `json:"ipAddress"`
	MacAccress string   `json:"macAddress"`
	Port       string   `json:"port"`
	Purposes   []string `json:"purposes"`
	Type       string   `json:"type"`
}

type NodeStorage struct {
	Capacity string   `json:"capacity"`
	Letter   string   `json:"letter"`
	Letters  []string `json:"letters"`
	Path     string   `json:"path"`
	Purposes []string `json:"purposes"`
}

func main() {
	rand.Seed(time.Now().UnixNano())
	if err := NewCommand().Execute(); err != nil {
		os.Exit(1)
	}
}

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "starbedctl",
	}
	cmd.AddCommand(NewCommandAuth())
	cmd.AddCommand(NewCommandResource())
	cmd.AddCommand(NewCommandJob())
	cmd.AddCommand(NewCommandInfraManagement())
	cmd.AddCommand(util.NewCommandVersion())
	cmd.AddCommand(util.NewCmdCompletion(cmd))
	return cmd
}

func NewCommandResource() *cobra.Command {
	cmd := &cobra.Command{
		Use: "resource",
	}
	cmd.AddCommand(NewCommandResourceList())
	cmd.AddCommand(NewCommandResourcePower())
	return cmd
}

func NewCommandResourcePower() *cobra.Command {
	cmd := &cobra.Command{
		Use: "power",
	}
	cmd.AddCommand(NewCommandResourcePowerOn())
	cmd.AddCommand(NewCommandResourcePowerOff())
	cmd.AddCommand(NewCommandResourcePowerCheck())
	return cmd
}

func NewCommandJob() *cobra.Command {
	cmd := &cobra.Command{
		Use: "job",
	}
	cmd.AddCommand(NewCommandJobList())
	return cmd
}

func NewCommandInfraManagement() *cobra.Command {
	cmd := &cobra.Command{
		Use: "infra",
	}
	cmd.AddCommand(NewCommandInfraValidate())
	cmd.AddCommand(NewCommandInfraApply())
	cmd.AddCommand(NewCommandInfraManagementList())
	cmd.AddCommand(NewCommandInfraManagementShow())
	return cmd
}

func NewCommandInfraManagementList() *cobra.Command {
	var filename string
	cmd := &cobra.Command{
		Use: "list",
		RunE: func(cmd *cobra.Command, args []string) error {
			i, err := infraList()
			if err != nil {
				return err
			}
			pp.Println(i)
			return nil
		},
	}
	cmd.Flags().StringVarP(&filename, "file", "f", "", "")
	return cmd
}

func NewCommandInfraManagementShow() *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use: "show",
		RunE: func(cmd *cobra.Command, args []string) error {
			i, err := infraShow(name)
			if err != nil {
				return err
			}
			pp.Println(i)
			return nil
		},
	}
	cmd.Flags().StringVarP(&name, "name", "n", "", "")
	return cmd
}

func infraList() ([]string, error) {
	token, err := tokenIssue()
	if err != nil {
		return nil, err
	}

	endpoint := os.Getenv("STARBED_ENDPOINT")
	req, err := http.NewRequest("GET",
		fmt.Sprintf("%s/api/mfplane-23/infras", endpoint), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	http.DefaultTransport = &http.Transport{Proxy: nil}
	client := new(http.Client)
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d",
			res.StatusCode)
	}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	//println(string(b))
	//println(len(string(b)))
	resData := []string{}
	if err := json.Unmarshal(b, &resData); err != nil {
		return nil, err
	}
	return resData, nil
}

func infraShow(name string) (*Infra, error) {
	token, err := tokenIssue()
	if err != nil {
		return nil, err
	}

	endpoint := os.Getenv("STARBED_ENDPOINT")
	req, err := http.NewRequest("GET",
		fmt.Sprintf("%s/api/mfplane-23/infra/%s", endpoint, name), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	http.DefaultTransport = &http.Transport{Proxy: nil}
	client := new(http.Client)
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d",
			res.StatusCode)
	}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	//println(string(b))
	//println(len(string(b)))
	resData := Infra{}
	if err := json.Unmarshal(b, &resData); err != nil {
		return nil, err
	}
	return &resData, nil
}

func NewCommandInfraValidate() *cobra.Command {
	var filename string
	cmd := &cobra.Command{
		Use: "validate",
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO(slankdev)
			token, err := tokenIssue()
			if err != nil {
				return err
			}
			fmt.Println(token)
			return nil
		},
	}
	cmd.Flags().StringVarP(&filename, "file", "f", "", "")
	return cmd
}

func NewCommandInfraApply() *cobra.Command {
	var filename string
	cmd := &cobra.Command{
		Use: "apply",
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO(slankdev)
			token, err := tokenIssue()
			if err != nil {
				return err
			}
			fmt.Println(token)
			return nil
		},
	}
	cmd.Flags().StringVarP(&filename, "file", "f", "", "")
	return cmd
}

func NewCommandAuth() *cobra.Command {
	cmd := &cobra.Command{
		Use: "auth",
		RunE: func(cmd *cobra.Command, args []string) error {
			token, err := tokenIssue()
			if err != nil {
				return err
			}
			fmt.Println(token)
			return nil
		},
	}
	return cmd
}

func NewCommandJobList() *cobra.Command {
	cmd := &cobra.Command{
		Use: "list",
		RunE: func(cmd *cobra.Command, args []string) error {
			j, err := jobList()
			if err != nil {
				println("1")
				return err
			}
			pp.Println(j)
			return nil
		},
	}
	return cmd
}

func NewCommandResourceList() *cobra.Command {
	cmd := &cobra.Command{
		Use: "list",
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := resourceList()
			if err != nil {
				println("1")
				return err
			}

			names := []string{}
			for _, node := range r.Nodes {
				names = append(names, node.NodeName)
			}
			p, err := powerStatusCheck(names)
			if err != nil {
				println("2")
				return err
			}

			//pp.Println(r)
			table := util.NewTableWriter(os.Stdout)
			table.SetHeader([]string{"Name", "Power"})
			for _, node := range r.Nodes {
				power := "n/a"
				if v, ok := p[node.NodeName]; ok {
					power = v
				}
				table.Append([]string{node.NodeName, power})
			}
			table.Render()
			return nil
		},
	}
	return cmd
}

func NewCommandResourcePowerCheck() *cobra.Command {
	var nodeNames []string
	cmd := &cobra.Command{
		Use: "check",
		RunE: func(cmd *cobra.Command, args []string) error {
			p0, err := powerStatusCheck(nodeNames)
			if err != nil {
				return err
			}
			pp.Println(p0)
			return nil
		},
	}
	cmd.Flags().StringArrayVarP(&nodeNames, "name", "n", []string{},
		"node-name like w001")
	return cmd
}

func NewCommandResourcePowerOn() *cobra.Command {
	var nodeName string
	cmd := &cobra.Command{
		Use: "on",
		RunE: func(cmd *cobra.Command, args []string) error {
			return powerStatusOn(nodeName)
		},
	}
	cmd.Flags().StringVarP(&nodeName, "name", "n", "", "node-name like w001")
	return cmd
}

func NewCommandResourcePowerOff() *cobra.Command {
	var nodeName string
	cmd := &cobra.Command{
		Use: "off",
		RunE: func(cmd *cobra.Command, args []string) error {
			return powerStatusOff(nodeName)
		},
	}
	cmd.Flags().StringVarP(&nodeName, "name", "n", "", "node-name like w001")
	return cmd
}

func jobList() (*JobsResponse, error) {
	token, err := tokenIssue()
	if err != nil {
		return nil, err
	}

	endpoint := os.Getenv("STARBED_ENDPOINT")
	req, err := http.NewRequest("GET",
		fmt.Sprintf("%s/api/mfplane-23/jobs", endpoint), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	http.DefaultTransport = &http.Transport{Proxy: nil}
	client := new(http.Client)
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d",
			res.StatusCode)
	}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	//println(string(b))
	//println(len(string(b)))
	resData := JobsResponse{}
	if err := json.Unmarshal(b, &resData); err != nil {
		return nil, err
	}
	return &resData, nil
}

func powerStatusCheck(nodeNames []string,
) (map[string]string, error) {
	token, err := tokenIssue()
	if err != nil {
		return nil, err
	}

	reqBodyBytes, err := json.Marshal(nodeNames)
	if err != nil {
		return nil, err
	}

	endpoint := os.Getenv("STARBED_ENDPOINT")
	req, err := http.NewRequest("POST",
		fmt.Sprintf("%s/api/mfplane-23/power/", endpoint),
		bytes.NewBuffer(reqBodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	http.DefaultTransport = &http.Transport{Proxy: nil}
	client := new(http.Client)
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d",
			res.StatusCode)
	}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	resData := map[string]string{}
	if err := json.Unmarshal(b, &resData); err != nil {
		return nil, err
	}
	return resData, nil
}

func powerStatusOn(name string) error {
	token, err := tokenIssue()
	if err != nil {
		return err
	}

	method := "PUT"
	endpoint := os.Getenv("STARBED_ENDPOINT")
	req, err := http.NewRequest(method,
		fmt.Sprintf("%s/api/mfplane-23/power/%s", endpoint, name),
		bytes.NewBuffer([]byte("{}")))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	http.DefaultTransport = &http.Transport{Proxy: nil}
	client := new(http.Client)
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d",
			res.StatusCode)
	}
	return nil
}

func powerStatusOff(name string) error {
	token, err := tokenIssue()
	if err != nil {
		return err
	}

	method := "DELETE"
	endpoint := os.Getenv("STARBED_ENDPOINT")
	req, err := http.NewRequest(method,
		fmt.Sprintf("%s/api/mfplane-23/power/%s", endpoint, name),
		bytes.NewBuffer([]byte("{}")))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	http.DefaultTransport = &http.Transport{Proxy: nil}
	client := new(http.Client)
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d",
			res.StatusCode)
	}
	return nil
}

// http_proxy=""
// curl -vvv -s -X GET
// -H "Authorization: Bearer $(./bin/starbedctl auth)"
// http://vmuser013/api/mfplane-23/resources
func resourceList() (*ResourcesResponse, error) {
	token, err := tokenIssue()
	if err != nil {
		return nil, err
	}

	endpoint := os.Getenv("STARBED_ENDPOINT")
	req, err := http.NewRequest("GET",
		fmt.Sprintf("%s/api/mfplane-23/resources", endpoint), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	http.DefaultTransport = &http.Transport{Proxy: nil}
	client := new(http.Client)
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d",
			res.StatusCode)
	}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	//println(string(b))
	//println(len(string(b)))
	resData := ResourcesResponse{}
	if err := json.Unmarshal(b, &resData); err != nil {
		return nil, err
	}
	return &resData, nil
}

// $ export STARBED_ENDPOINT=http://hoge.io
// $ export STARBED_USERNAME=myname
// $ export STARBED_PASSWORD=mypass
// $ export http_proxy=""
// $ curl -s -vvv -X POST -H "Content-Type: application/json"
// $STARBED_ENDPOINT/api/auth/login
// -d '{"username":"'$STARBED_USERNAME'","password":"'$STARBED_PASSWORD'"}'
func tokenIssue() (string, error) {
	endpoint := os.Getenv("STARBED_ENDPOINT")
	username := os.Getenv("STARBED_USERNAME")
	password := os.Getenv("STARBED_PASSWORD")

	// NOTE(slankdev): http_proxy env forcely disable
	http.DefaultTransport = &http.Transport{Proxy: nil}
	body := AuthLoginRequest{
		Username: username,
		Password: password,
	}
	bodyJson, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	res, err := http.Post(
		fmt.Sprintf("%s/api/auth/login", endpoint),
		"application/json", bytes.NewBuffer(bodyJson))
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code %d",
			res.StatusCode)
	}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	resData := AuthLoginResponse{}
	if err := json.Unmarshal(b, &resData); err != nil {
		return "", err
	}
	// pp.Println(resData)
	return resData.AccessToken, nil
}
