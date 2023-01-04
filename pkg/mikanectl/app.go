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
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net"
	"os"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/slankdev/hyperplane/pkg/ebpf"
	"github.com/slankdev/hyperplane/pkg/maglev"
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
	cmd.AddCommand(NewCommandMapDumpNat())
	cmd.AddCommand(NewCommandMapDumpNatOld())
	cmd.AddCommand(NewCommandMapClearNat())
	cmd.AddCommand(util.NewCommandVersion())
	cmd.AddCommand(util.NewCmdCompletion(cmd))
	cmd.AddCommand(util.NewCmdIfconfigHTTPServer())
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

func NewCommandMapDump() *cobra.Command {
	var clioptNamePrefix string
	cmd := &cobra.Command{
		Use: "map-dump",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("[encapSrouce]\n")
			if err := ebpf.BatchMapOperation(clioptNamePrefix+"_encap_source",
				ciliumebpf.PerCPUArray,
				func(m *ciliumebpf.Map) error {
					key := uint32(0)
					percpuval := [][16]uint8{}
					entries := m.Iterate()
					for entries.Next(&key, &percpuval) {
						ip := net.IP(percpuval[0][:])
						fmt.Printf("%s\n", ip)
					}
					return nil
				}); err != nil {
				return err
			}

			fmt.Printf("\n[fib6]\n")
			if err := ebpf.BatchMapOperation(clioptNamePrefix+"_fib6",
				ciliumebpf.LPMTrie,
				func(m *ciliumebpf.Map) error {
					key := ebpf.Trie6Key{}
					val := ebpf.Trie6Val{}
					entries := m.Iterate()
					for entries.Next(&key, &val) {
						ip := net.IP(key.Addr[:])
						fmt.Printf("%s/%d %+v\n", ip, key.Prefixlen, val)
					}
					return nil
				}); err != nil {
				return err
			}

			fmt.Printf("\n[vip]\n")
			if err := ebpf.BatchMapOperation(clioptNamePrefix+"_vip_table",
				ciliumebpf.PerCPUHash,
				func(m *ciliumebpf.Map) error {
					key := ebpf.VipKey{}
					percpuval := []ebpf.VipVal{}
					entries := m.Iterate()
					for entries.Next(&key, &percpuval) {
						ip := net.IP(key.Vip[:])
						fmt.Printf("%s %+v\n", ip, percpuval[0])
					}
					return nil
				}); err != nil {
				return err
			}

			fmt.Printf("\n[procs]\n")
			if err := ebpf.BatchMapOperation(clioptNamePrefix+"_procs",
				ciliumebpf.PerCPUArray,
				func(m *ciliumebpf.Map) error {
					var key uint32
					percpuval := []ebpf.FlowProcessor{}
					entries := m.Iterate()
					for entries.Next(&key, &percpuval) {
						fmt.Printf("%d %s\n", key, net.IP(percpuval[0].Addr[:]))
					}
					return nil
				}); err != nil {
				return err
			}

			return nil
		},
	}
	cmd.Flags().StringVarP(&clioptNamePrefix, "name", "n", "l1", "")
	return cmd
}

func FullIPv6(ip net.IP) string {
	dst := make([]byte, hex.EncodedLen(len(ip)))
	_ = hex.Encode(dst, ip)
	return string(dst[0:4]) + ":" +
		string(dst[4:8]) + ":" +
		string(dst[8:12]) + ":" +
		string(dst[12:16]) + ":" +
		string(dst[16:20]) + ":" +
		string(dst[20:24]) + ":" +
		string(dst[24:28]) + ":" +
		string(dst[28:])
}

func BitShiftRight8(u8 [16]uint8) [16]uint8 {
	ret := [16]uint8{}
	for i := 15; i >= 0; i-- {
		if i == 0 {
			ret[i] = 0
		} else {
			ret[i] = u8[i-1]
		}
	}
	return ret
}

func CopyFromTo(dst, src *net.IP, octFrom, octTo int) {
	dst8 := [16]uint8{}
	src8 := [16]uint8{}
	copy(dst8[:], *dst)
	copy(src8[:], *src)
	for i := octFrom; i <= octTo; i++ {
		dst8[i] = src8[i]
	}
	copy(*dst, dst8[:])
}

func compute(end_MFL ConfigLocalSid_End_MFL, nBackends int) ([]net.IP, error) {
	// Unsupport case
	if end_MFL.USidBlockLength%8 != 0 {
		return nil, fmt.Errorf("not supported (uSidBlockLength %% 8 != 0)")
	}
	if end_MFL.USidFunctionLength%8 != 0 {
		return nil, fmt.Errorf("not supported (uSidFunctionLength %% 8 != 0)")
	}

	slots := make([]net.IP, nBackends)
	for idx := range slots {
		slots[idx] = net.ParseIP(end_MFL.USidBlock)
	}

	// Fill uSID Function Blocks
	for revIdx := range end_MFL.USidFunctionRevisions {
		backends := end_MFL.USidFunctionRevisions[revIdx].Backends
		uSidBlockOctedOffset := end_MFL.USidBlockLength / 8
		uSidBlockOctedSize := end_MFL.USidFunctionLength / 8
		mh, err := maglev.NewMaglev(backends,
			uint64(nBackends))
		if err != nil {
			return nil, err
		}
		mhTable := mh.GetRawTable()
		for idx := 0; idx < len(mhTable); idx++ {
			backendip := net.ParseIP(backends[mhTable[idx]])
			u8 := [16]uint8{}
			copy(u8[:], backendip)

			// bit shift
			for j := 0; j < uSidBlockOctedOffset; j++ {
				u8 = BitShiftRight8(u8)
			}
			for i := 0; i < revIdx; i++ {
				for j := 0; j < uSidBlockOctedSize; j++ {
					u8 = BitShiftRight8(u8)
				}
			}

			// Accumurate resulting bit fields
			copy(backendip, u8[:])
			CopyFromTo(&slots[idx], &backendip,
				uSidBlockOctedOffset+uSidBlockOctedSize*revIdx,
				uSidBlockOctedOffset+uSidBlockOctedSize-1+uSidBlockOctedSize*revIdx,
			)
		}
	}
	return slots, nil
}

func localSid_End_MFL(backendBlockIndex int, localSid ConfigLocalSid,
	config Config) error {
	// Install backend-block
	if err := ebpf.BatchMapOperation(config.NamePrefix+"_procs",
		ciliumebpf.PerCPUArray,
		func(m *ciliumebpf.Map) error {
			// Fill uSID Block Bits
			slots, err := compute(*localSid.End_MFL, config.MaxBackends)
			if err != nil {
				return err
			}

			// Print uSID MF-hash
			for idx := range slots {
				fmt.Printf("%03d  %s\n", idx, FullIPv6(slots[idx]))
				key := uint32(config.MaxBackends*backendBlockIndex + idx)
				val := ebpf.FlowProcessor{}
				copy(val.Addr[:], slots[idx])

				if err := ebpf.UpdatePerCPUArrayAll(m, &key, &val,
					ciliumebpf.UpdateAny); err != nil {
					return err
				}
			}

			return nil
		}); err != nil {
		return err
	}

	// Install fib6
	_, ipnet, err := net.ParseCIDR(localSid.Sid)
	if err != nil {
		return err
	}
	if err := ebpf.BatchMapOperation(config.NamePrefix+"_fib6",
		ciliumebpf.LPMTrie,
		func(m *ciliumebpf.Map) error {
			key := ebpf.Trie6Key{}
			copy(key.Addr[:], ipnet.IP)
			key.Prefixlen = uint32(util.Plen(ipnet.Mask))
			val := ebpf.Trie6Val{
				Action:             123, // TODO(slankdev)
				BackendBlockIndex:  uint16(backendBlockIndex),
				NatPortBashBit:     localSid.End_MFL.NatPortHashBit,
				UsidBlockLength:    uint16(localSid.End_MFL.USidBlockLength),
				UsidFunctionLength: uint16(localSid.End_MFL.USidFunctionLength),
			}
			if err := m.Update(key, val, ciliumebpf.UpdateAny); err != nil {
				return err
			}
			return nil
		}); err != nil {
		return err
	}

	// Install vip_table
	vipdata := net.ParseIP(localSid.End_MFL.Vip)
	if err := ebpf.BatchMapOperation(config.NamePrefix+"_vip_table",
		ciliumebpf.PerCPUHash,
		func(m *ciliumebpf.Map) error {
			key := ebpf.VipKey{}
			copy(key.Vip[:], vipdata[12:])
			val := ebpf.VipVal{
				BackendBlockIndex: uint16(backendBlockIndex),
				NatPortHashBit:    localSid.End_MFL.NatPortHashBit,
			}
			if err := ebpf.UpdatePerCPUArrayAll(m, key, val,
				ciliumebpf.UpdateAny); err != nil {
				return err
			}
			return nil
		}); err != nil {
		return err
	}
	return nil
}

func localSid_End_MFN_NAT(backendBlockIndex int, localSid ConfigLocalSid, config Config) error {
	// Install fib6
	_, ipnet, err := net.ParseCIDR(localSid.Sid)
	if err != nil {
		return err
	}
	ipaddr := net.ParseIP(localSid.End_MFN_NAT.Vip)
	ipaddrb := [4]uint8{}
	copy(ipaddrb[:], ipaddr[12:])

	if err := ebpf.BatchMapOperation(config.NamePrefix+"_fib6",
		ciliumebpf.LPMTrie,
		func(m *ciliumebpf.Map) error {
			// craft snat_sources
			sources := [256]ebpf.SnatSource{}
			for idx, srcpStr := range localSid.End_MFN_NAT.Sources {
				_, srcp, err := net.ParseCIDR(srcpStr)
				if err != nil {
					return err
				}
				source := ebpf.SnatSource{}
				source.Prefixlen = uint32(util.Plen(srcp.Mask))
				source.Addr = util.ConvertIPToUint32(srcp.IP)
				sources[idx] = source
			}

			key := ebpf.Trie6Key{}
			copy(key.Addr[:], ipnet.IP)
			key.Prefixlen = uint32(util.Plen(ipnet.Mask))
			val := ebpf.Trie6Val{
				Action:             456, // TODO(slankdev)
				Vip:                ipaddrb,
				NatPortBashBit:     localSid.End_MFN_NAT.NatPortHashBit,
				UsidBlockLength:    uint16(localSid.End_MFN_NAT.USidBlockLength),
				UsidFunctionLength: uint16(localSid.End_MFN_NAT.USidFunctionLength),
				Sources:            sources,
			}
			if err := m.Update(key, val, ciliumebpf.UpdateAny); err != nil {
				return err
			}
			return nil
		}); err != nil {
		return err
	}
	return nil
}

func ensureLocalSid(backendBlockIndex int, localSid ConfigLocalSid, config Config) error {
	cnt := 0
	if localSid.End_MFL != nil {
		cnt++
	}
	if localSid.End_MFN_NAT != nil {
		cnt++
	}
	if cnt != 1 {
		return fmt.Errorf("invalid sid config (%s)", localSid.Sid)
	}

	switch {
	case localSid.End_MFL != nil:
		return localSid_End_MFL(backendBlockIndex, localSid, config)
	case localSid.End_MFN_NAT != nil:
		return localSid_End_MFN_NAT(backendBlockIndex, localSid, config)
	}
	return nil
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

			// set Local SIDs
			for backendBlockIndex, localSid := range config.LocalSids {
				if err := ensureLocalSid(backendBlockIndex, localSid,
					config); err != nil {
					return err
				}
			}

			// set FIB4
			if err := ebpf.BatchMapOperation(config.NamePrefix+"_fib4",
				ciliumebpf.LPMTrie,
				func(m *ciliumebpf.Map) error {
					for _, fib4 := range config.Fib4 {
						_, ipnet, err := net.ParseCIDR(fib4.Prefix)
						if err != nil {
							return err
						}

						if len(fib4.Action.EncapSeg6.Segs) > 6 {
							return fmt.Errorf("segment list too long")
						}
						segs := [6][16]uint8{}
						for idx, seg := range fib4.Action.EncapSeg6.Segs {
							netip := net.ParseIP(seg)
							netipb := [16]uint8{}
							copy(netipb[:], netip)
							segs[idx] = netipb
						}

						// Fill key and val
						key := ebpf.Trie4Key{}
						key.Prefixlen = uint32(util.Plen(ipnet.Mask))
						copy(key.Addr[:], ipnet.IP)
						val := ebpf.Trie4Val{}
						val.Segs = segs
						if err := m.Update(&key, &val, ciliumebpf.UpdateAny); err != nil {
							return err
						}
					}
					return nil
				}); err != nil {
				return err
			}

			// Set tunsrc
			if err := ebpf.BatchMapOperation(config.NamePrefix+"_encap_source",
				ciliumebpf.PerCPUArray,
				func(m *ciliumebpf.Map) error {
					key := uint32(0)
					ipaddr := net.ParseIP(config.EncapSource)
					ipaddrb := [16]uint8{}
					copy(ipaddrb[:], ipaddr)
					if err := ebpf.UpdatePerCPUArrayAll(m, &key, &ipaddrb,
						ciliumebpf.UpdateAny); err != nil {
						return err
					}
					return nil
				},
			); err != nil {
				return nil
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&clioptFile, "file", "f", "", "")
	return cmd
}

type CacheEntry struct {
	Protocol              uint8
	AddrInternal          uint32
	AddrExternal          uint32
	PortInternal          uint16
	PortExternal          uint16
	CreatedAt             uint64
	UpdatedAt             uint64
	StatsReceivedPkts     uint64
	StatsReceivedBytes    uint64
	StatsTransmittedPkts  uint64
	StatsTransmittedBytes uint64
}

type Cache struct {
	entries []CacheEntry
}

func (c *Cache) statsIncrement(proto uint8, iAddr, eAddr uint32,
	iPort, ePort uint16, createdAt, updatedAt uint64, rxPkts, txPkts uint64,
	rxBytes, txBytes uint64) {
	match := false
	for idx, cache := range c.entries {
		if cache.AddrInternal == iAddr && cache.AddrExternal == eAddr &&
			cache.PortInternal == iPort && cache.PortExternal == ePort &&
			cache.Protocol == proto {
			c.entries[idx].StatsReceivedPkts += rxPkts
			c.entries[idx].StatsTransmittedPkts += txPkts
			c.entries[idx].StatsReceivedBytes += rxBytes
			c.entries[idx].StatsTransmittedBytes += txBytes
			if createdAt < cache.CreatedAt {
				c.entries[idx].CreatedAt = createdAt
			}
			if updatedAt > cache.UpdatedAt {
				c.entries[idx].UpdatedAt = updatedAt
			}
			match = true
			break
		}
	}
	if !match {
		c.entries = append(c.entries, CacheEntry{
			Protocol:              proto,
			AddrInternal:          iAddr,
			AddrExternal:          eAddr,
			PortInternal:          iPort,
			PortExternal:          ePort,
			CreatedAt:             createdAt,
			UpdatedAt:             updatedAt,
			StatsReceivedPkts:     rxPkts,
			StatsReceivedBytes:    rxBytes,
			StatsTransmittedPkts:  txPkts,
			StatsTransmittedBytes: txBytes,
		})
	}
}

func NewCommandMapDumpNat() *cobra.Command {
	var clioptMapNamePrefix string
	cmd := &cobra.Command{
		Use: "map-dump-nat",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Bi-directional Cache tmp data
			cache := Cache{}

			// Parse NAT-Out Caches
			if err := ebpf.BatchMapOperation(clioptMapNamePrefix+"_nat_out_tabl",
				ciliumebpf.LRUHash,
				func(m *ciliumebpf.Map) error {
					key := ebpf.AddrPort{}
					val := ebpf.AddrPortStats{}
					entries := m.Iterate()
					for entries.Next(&key, &val) {
						cache.statsIncrement(key.Proto,
							util.ConvertIPToUint32(net.IP(key.Addr[:])),
							util.ConvertIPToUint32(net.IP(val.Addr[:])),
							util.BS16(key.Port), util.BS16(val.Port), val.CreatedAt,
							val.UpdatedAt, 0, val.Pkts, 0, val.Bytes)
					}
					return nil
				}); err != nil {
				return err
			}

			// Parse NAT-Ret Caches
			if err := ebpf.BatchMapOperation(clioptMapNamePrefix+"_nat_ret_tabl",
				ciliumebpf.LRUHash,
				func(m *ciliumebpf.Map) error {
					key := ebpf.AddrPort{}
					val := ebpf.AddrPortStats{}
					entries := m.Iterate()
					for entries.Next(&key, &val) {
						cache.statsIncrement(key.Proto,
							util.ConvertIPToUint32(net.IP(val.Addr[:])),
							util.ConvertIPToUint32(net.IP(key.Addr[:])),
							util.BS16(val.Port),
							util.BS16(key.Port),
							val.CreatedAt, val.UpdatedAt,
							val.Pkts, 0, val.Bytes, 0)
					}
					return nil
				}); err != nil {
				return err
			}

			// Print Result
			table := util.NewTableWriter(os.Stdout)
			table.SetHeader([]string{"proto", "internal", "external",
				"tx(p:b)", "rx(p:b)",
				"created", "updated"})
			for _, ent := range cache.entries {
				const timefmt = "2006.01.02:15:04:05"
				cat, err := util.KtimeSecToTime(ent.CreatedAt)
				if err != nil {
					return err
				}
				uat, err := util.KtimeSecToTime(ent.UpdatedAt)
				if err != nil {
					return err
				}

				iAddr := util.ConvertUint32ToIP(ent.AddrInternal)
				eAddr := util.ConvertUint32ToIP(ent.AddrExternal)
				table.Append([]string{
					fmt.Sprintf("%d", ent.Protocol),
					fmt.Sprintf("%s:%d", iAddr, ent.PortInternal),
					fmt.Sprintf("%s:%d", eAddr, ent.PortExternal),
					fmt.Sprintf("%d:%d", ent.StatsTransmittedPkts, ent.StatsTransmittedBytes),
					fmt.Sprintf("%d:%d", ent.StatsReceivedPkts, ent.StatsReceivedBytes),
					cat.Format(timefmt),
					uat.Format(timefmt),
				})
			}
			table.Render()
			return nil
		},
	}
	cmd.Flags().StringVarP(&clioptMapNamePrefix, "name", "n", "n1", "")
	return cmd
}

func NewCommandMapDumpNatOld() *cobra.Command {
	var clioptMapName string
	cmd := &cobra.Command{
		Use: "map-dump-nat-old",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("%s\n", clioptMapName)

			if err := ebpf.BatchMapOperation(clioptMapName,
				ciliumebpf.LRUHash,
				func(m *ciliumebpf.Map) error {
					key := ebpf.AddrPort{}
					val := ebpf.AddrPortStats{}
					entries := m.Iterate()
					for entries.Next(&key, &val) {
						keyAddr := net.IP(key.Addr[:])
						valAddr := net.IP(val.Addr[:])
						fmt.Printf("%d:%s:%d -> %s:%d %d\n",
							key.Proto,
							keyAddr, util.BS16(key.Port),
							valAddr, util.BS16(val.Port), val.Pkts)
					}
					return nil
				}); err != nil {
				return err
			}

			return nil
		},
	}
	cmd.Flags().StringVarP(&clioptMapName, "map", "m", "n0_nat_out_table", "")
	return cmd
}

func NewCommandMapClearNat() *cobra.Command {
	var clioptMapName string
	cmd := &cobra.Command{
		Use: "map-clear-nat",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ebpf.BatchMapOperation(clioptMapName,
				ciliumebpf.LRUHash,
				func(m *ciliumebpf.Map) error {
					// resolve keys
					keys := []ebpf.AddrPort{}
					key := ebpf.AddrPort{}
					val := ebpf.AddrPortStats{}
					entries := m.Iterate()
					for entries.Next(&key, &val) {
						keys = append(keys, key)
					}

					// delete all keys
					for _, key := range keys {
						if err := m.Delete(key); err != nil {
							return err
						}
					}
					return nil
				}); err != nil {
				return err
			}

			return nil
		},
	}
	cmd.Flags().StringVarP(&clioptMapName, "map", "m", "n1_nat_out_table", "")
	return cmd
}
