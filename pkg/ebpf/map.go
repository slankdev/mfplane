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
	"math"

	"github.com/cilium/ebpf"
)

const (
	mapName = "flow_stats"
	mapType = ebpf.PerCPUHash

	metricsMapName = "metrics"
	metricsMapType = ebpf.PerCPUHash
)

type TrieKey struct {
	Prefixlen uint32    `json:"prefixlen"`
	Addr      [16]uint8 `json:"addr"`
}

type TrieVal struct {
	Action uint8 `json:"action"`
}

type Fib6 struct {
	Val FlowVal
}

// func (v *FlowVal) Merge(src FlowVal) {
// 	v.FlowPkts += src.FlowPkts
// 	v.FlowBytes += src.FlowBytes
// 	if v.FlowStartMilliSecond == 0 {
// 		v.FlowStartMilliSecond = math.MaxUint64
// 	}
// 	if src.FlowStartMilliSecond != 0 &&
// 		src.FlowStartMilliSecond <= v.FlowStartMilliSecond {
// 		v.FlowStartMilliSecond = src.FlowStartMilliSecond
// 	}
// 	if src.FlowEndMilliSecond != 0 &&
// 		src.FlowEndMilliSecond >= v.FlowEndMilliSecond {
// 		v.FlowEndMilliSecond = src.FlowEndMilliSecond
// 	}
// 	if src.Finished != 0 {
// 		v.Finished = 1
// 	}
// }

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

type FlowKey struct {
	IngressIfindex uint32
	EgressIfindex  uint32
	Saddr          uint32
	Daddr          uint32
	Sport          uint16
	Dport          uint16
	Proto          uint8
	Mark           uint32
}

type FlowVal struct {
	FlowPkts             uint32 `json:"cnt"`
	FlowBytes            uint32 `json:"data_bytes"`
	FlowStartMilliSecond uint64 `json:"flow_start_msec"`
	FlowEndMilliSecond   uint64 `json:"flow_end_msec"`
	Finished             uint8  `json:"finished"`
}

type Flow struct {
	Key FlowKey
	Val FlowVal
}

func (v *FlowVal) Merge(src FlowVal) {
	v.FlowPkts += src.FlowPkts
	v.FlowBytes += src.FlowBytes
	if v.FlowStartMilliSecond == 0 {
		v.FlowStartMilliSecond = math.MaxUint64
	}
	if src.FlowStartMilliSecond != 0 &&
		src.FlowStartMilliSecond <= v.FlowStartMilliSecond {
		v.FlowStartMilliSecond = src.FlowStartMilliSecond
	}
	if src.FlowEndMilliSecond != 0 &&
		src.FlowEndMilliSecond >= v.FlowEndMilliSecond {
		v.FlowEndMilliSecond = src.FlowEndMilliSecond
	}
	if src.Finished != 0 {
		v.Finished = 1
	}
}

func Dump() ([]Flow, error) {
	ids, err := GetMapIDsByNameType(mapName, mapType)
	if err != nil {
		return nil, err
	}

	flows := []Flow{}
	for _, id := range ids {
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			return nil, err
		}

		key := FlowKey{}
		perCpuVals := []FlowVal{}
		entries := m.Iterate()
		for entries.Next(&key, &perCpuVals) {
			val := FlowVal{}
			for _, perCpuVal := range perCpuVals {
				val.Merge(perCpuVal)
			}
			flows = append(flows, Flow{key, val})
		}
		if err := entries.Err(); err != nil {
			return nil, err
		}
		if err := m.Close(); err != nil {
			return nil, err
		}
	}
	return flows, nil
}

func Delete(key FlowKey) error {
	ids, err := GetMapIDsByNameType(mapName, mapType)
	if err != nil {
		return err
	}
	for _, id := range ids {
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			return err
		}
		if err := m.Delete(key); err != nil {
			return err
		}
		if err := m.Close(); err != nil {
			return err
		}
	}
	return nil
}

func DeleteFinished() error {
	ids, err := GetMapIDsByNameType(mapName, mapType)
	if err != nil {
		return err
	}
	for _, id := range ids {
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			return err
		}
		key := FlowKey{}
		perCpuVals := []FlowVal{}
		entries := m.Iterate()
		for entries.Next(&key, &perCpuVals) {
			for _, perCpuVal := range perCpuVals {
				if perCpuVal.Finished > 0 {
					if err := m.Delete(key); err != nil {
						return err
					}
					break
				}
			}
		}
		if err := m.Close(); err != nil {
			return err
		}
	}
	return nil
}

func DeleteAll() error {
	ids, err := GetMapIDsByNameType(mapName, mapType)
	if err != nil {
		return err
	}
	for _, id := range ids {
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			return err
		}
		key := FlowKey{}
		perCpuVals := []FlowVal{}
		entries := m.Iterate()
		for entries.Next(&key, &perCpuVals) {
			if err := m.Delete(key); err != nil {
				return err
			}
		}
		if err := m.Close(); err != nil {
			return err
		}
	}
	return nil
}
