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

package ebpf

import "fmt"

type AddrPort struct {
	Addr  [4]uint8 `json:"addr"`
	Port  uint16   `json:"port"`
	Proto uint8    `json:"proto"`
}

type AddrPortStats struct {
	Addr      [4]uint8 `json:"addr"`
	Port      uint16   `json:"port"`
	Proto     uint8    `json:"proto"`
	Pkts      uint64   `json:"pkts"`
	Bytes     uint64   `json:"bytes"`
	CreatedAt uint64   `json:"created_at"`
	UpdatedAt uint64   `json:"update_at"`
}

type Trie4Key struct {
	Prefixlen uint32   `json:"prefixlen"`
	Addr      [4]uint8 `json:"addr"`
}

type Trie4Val struct {
	Action uint16       `json:"action"`
	Segs   [6][16]uint8 `json:"segs"`
}

type Trie6Key struct {
	Prefixlen uint32    `json:"prefixlen"`
	Addr      [16]uint8 `json:"addr"`
}

type SnatSource struct {
	Prefixlen uint32 `json:"prefixlen"`
	Addr      uint32 `json:"addr"`
}

type Trie6Val struct {
	Action             EndAction       `json:"action"`
	BackendBlockIndex  uint16          `json:"backend_block_index"`
	Vip                [4]uint8        `json:"vip"`
	NatPortBashBit     uint16          `json:"nat_port_hash_bit"`
	UsidBlockLength    uint16          `json:"usid_block_length"`
	UsidFunctionLength uint16          `json:"usid_function_length"`
	StatsTotalBytes    uint64          `json:"stats_total_bytes"`
	StatsTotalPkts     uint64          `json:"stats_total_pkts"`
	StatsRedirBytes    uint64          `json:"stats_redir_bytes"`
	StatsRedirPkts     uint64          `json:"stats_redir_pkts"`
	NatMapping         uint8           `json:"nat_mapping"`
	NatFiltering       uint8           `json:"nat_filtering"`
	Sources            [256]SnatSource `json:"sources"`
}

type EndAction uint16

func (ea EndAction) String() string {
	switch ea {
	case 123:
		return "End.Mfl.Nat"
	case 456:
		return "End.Mfn.Nat"
	default:
		return fmt.Sprintf("unknown(%d)", ea)
	}
}

type VipKey struct {
	Vip [4]uint8 `json:"vip"`
}

type VipVal struct {
	BackendBlockIndex uint16 `json:"backend_block_index"`
	NatPortHashBit    uint16 `json:"nat_port_hash_bit"`
}

type FlowProcessor struct {
	Addr            [16]uint8 `json:"addr"`
	StatsTotalBytes uint64    `json:"stats_total_bytes"`
	StatsTotalPkts  uint64    `json:"stats_total_pkts"`
}
