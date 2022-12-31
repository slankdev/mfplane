/*
Copyright 2022 Hiroki Shirokura.
Copyright 2022 Keio University.
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

import (
	"runtime"

	"github.com/cilium/ebpf"
)

const (
	mapName = "flow_stats"
	mapType = ebpf.PerCPUHash

	metricsMapName = "metrics"
	metricsMapType = ebpf.PerCPUHash
)

type AddrPort struct {
	Addr [4]uint8 `json:"addr"`
	Port uint16   `json:"port"`
}

type AddrPortStats struct {
	Addr [4]uint8 `json:"addr"`
	Port uint16   `json:"port"`
	Pkts uint64   `json:"pkts"`
}

type TrieKey struct {
	Prefixlen uint32    `json:"prefixlen"`
	Addr      [16]uint8 `json:"addr"`
}

type TrieVal struct {
	Action            uint16   `json:"action"`
	BackendBlockIndex uint16   `json:"backend_block_index"`
	Vip               [4]uint8 `json:"vip"`
	NatPortBashBit    uint16   `json:"nat_port_hash_bit"`
}

type Trie4Key struct {
	Prefixlen uint32   `json:"prefixlen"`
	Addr      [4]uint8 `json:"addr"`
}

type Trie4Val struct {
	Action uint16       `json:"action"`
	Segs   [6][16]uint8 `json:"segs"`
}

type FlowKey struct {
	Hash uint32 `json:"hash"`
}

type FlowProcessor struct {
	Addr [16]uint8 `json:"addr"`
}

type VipKey struct {
	Vip [4]uint8 `json:"vip"`
}

type VipVal struct {
	BackendBlockIndex uint16 `json:"backend_block_index"`
	DynamicBitLength  uint16 `json:"dynamic_bit_length"`
}

func GetMapIDsByNameType(mapName string, mapType ebpf.MapType) ([]ebpf.MapID, error) {
	ids := []ebpf.MapID{}
	for id := ebpf.MapID(0); ; {
		var err error
		id, err = ebpf.MapGetNextID(ebpf.MapID(id))
		if err != nil {
			break
		}
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			return nil, err
		}
		info, err := m.Info()
		if err != nil {
			return nil, err
		}
		if err := m.Close(); err != nil {
			return nil, err
		}

		if info.Name != mapName || info.Type != mapType {
			continue
		}
		ids = append(ids, id)
	}
	return ids, nil
}

type StatsMetricsKey struct {
	IngressIfindex uint32 `json:"ingress_ifindex"`
	EgressIfindex  uint32 `json:"egress_ifindex"`
}

type StatsMetricsVal struct {
	SynPkts                 uint32 `json:"syn_pkts"`
	TotalPkts               uint32 `json:"total_pkts"`
	TotalBytes              uint32 `json:"total_bytes"`
	OverflowPkts            uint32 `json:"overflow_pkts"`
	OverflowBytes           uint32 `json:"overflow_bytes"`
	TotalLatencyNanoseconds uint32 `json:"latency_nano_sum"`
}

func GetStats() (map[StatsMetricsKey]StatsMetricsVal, error) {
	ids, err := GetMapIDsByNameType(metricsMapName, metricsMapType)
	if err != nil {
		return nil, err
	}

	ret := map[StatsMetricsKey]StatsMetricsVal{}
	for _, id := range ids {
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			return nil, err
		}

		key := StatsMetricsKey{}
		perCpuVals := []StatsMetricsVal{}
		entries := m.Iterate()
		for entries.Next(&key, &perCpuVals) {
			val := StatsMetricsVal{}
			for _, perCpuVal := range perCpuVals {
				val.SynPkts += perCpuVal.SynPkts
				val.OverflowPkts += perCpuVal.OverflowPkts
				val.OverflowBytes += perCpuVal.OverflowBytes
				val.TotalPkts += perCpuVal.TotalPkts
				val.TotalBytes += perCpuVal.TotalBytes
				val.TotalLatencyNanoseconds += perCpuVal.TotalLatencyNanoseconds
			}
			ret[key] = val
		}
	}

	return ret, nil
}

func BatchMapOperation(mapname string, maptype ebpf.MapType,
	f func(m *ebpf.Map) error) error {
	ids, err := GetMapIDsByNameType(mapname, maptype)
	if err != nil {
		return err
	}
	for _, id := range ids {
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			return err
		}
		if err := f(m); err != nil {
			return err
		}
	}
	return nil
}

func UpdatePerCPUArrayAll(m *ebpf.Map, key interface{}, value interface{},
	flags ebpf.MapUpdateFlags) error {
	percpuval := []interface{}{}
	for i := 0; i < runtime.NumCPU(); i++ {
		percpuval = append(percpuval, value)
	}
	return m.Update(key, percpuval, flags)
}
