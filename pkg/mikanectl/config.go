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

type ConfigLocalSid_End_MFL struct {
	Vip                   string             `yaml:"vip"`
	NatPortHashBit        uint16             `yaml:"natPortHashBit"`
	USidBlock             string             `yaml:"uSidBlock"`
	USidBlockLength       int                `yaml:"uSidBlockLength"`
	USidFunctionLength    int                `yaml:"uSidFunctionLength"`
	USidFunctionRevisions []FunctionRevision `yaml:"uSidFunctionRevisions"`
}

type FunctionRevision struct {
	Backends []string `yaml:"backends"`
}

type ConfigLocalSid_End_MFN_NAT struct {
	Vip            string   `yaml:"vip"`
	NatPortHashBit uint16   `yaml:"natPortHashBit"`
	Sources        []string `yaml:"sources"`
}

type ConfigLocalSid struct {
	Sid         string                      `yaml:"sid"`
	End_MFL     *ConfigLocalSid_End_MFL     `yaml:"End_MFL"`
	End_MFN_NAT *ConfigLocalSid_End_MFN_NAT `yaml:"End_MFN_NAT"`
}

type ConfigFib4EncapSeg6 struct {
	Mode string   `yaml:"mode"`
	Segs []string `yaml:"segs"`
}

type ConfigFib4 struct {
	Prefix string `yaml:"prefix"`
	Action struct {
		EncapSeg6 *ConfigFib4EncapSeg6 `yaml:"encapSeg6"`
	} `yaml:"action"`
}

type Config struct {
	NamePrefix  string           `yaml:"namePrefix"`
	MaxRules    int              `yaml:"maxRules"`
	MaxBackends int              `yaml:"maxBackends"`
	EncapSource string           `yaml:"encapSource"`
	LocalSids   []ConfigLocalSid `yaml:"localSids"`
	Fib4        []ConfigFib4     `yaml:"fib4"`
}
