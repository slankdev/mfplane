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
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

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
	cmd.AddCommand(NewCommandDaemonNat())
	cmd.AddCommand(NewCommandMapLoad())
	cmd.AddCommand(NewCommandMapDump())
	cmd.AddCommand(NewCommandMapDumpNat())
	cmd.AddCommand(NewCommandMapInstallNat())
	cmd.AddCommand(NewCommandMapDumpNatOld())
	cmd.AddCommand(NewCommandMapClearNat())
	cmd.AddCommand(util.NewCommandVersion())
	cmd.AddCommand(util.NewCmdCompletion(cmd))
	cmd.AddCommand(util.NewCmdIfconfigHTTPServer())
	cmd.AddCommand(util.NewCmdNc())
	return cmd
}

func NewCommandBpf() *cobra.Command {
	cmd := &cobra.Command{
		Use: "bpf",
	}
	cmd.AddCommand(ebpf.NewCommandXdpDetach("detach"))
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

func BitShiftLeft8(u8 [16]uint8) [16]uint8 {
	ret := [16]uint8{}
	for i := 0; i <= 15; i++ {
		if i == 15 {
			ret[i] = 0
		} else {
			ret[i] = u8[i+1]
		}
	}
	return ret
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

func (e CacheEntry) CleanupMapEntri(namePrefix string) error {
	// Delete from nat-out
	if err := ebpf.BatchMapOperation(namePrefix+"_nat_out_tabl",
		ciliumebpf.LRUHash,
		func(m *ciliumebpf.Map) error {
			ip := util.ConvertUint32ToIP(e.AddrInternal)
			ipb := [4]byte{}
			copy(ipb[:], ip)
			key := ebpf.AddrPort{
				Proto: e.Protocol,
				Addr:  ipb,
				Port:  util.BS16(e.PortInternal),
			}
			if err := m.Delete(key); err != nil {
				fmt.Printf("DEBUG: delete key failed (1) ... ignore\n")
				//return err
			}
			return nil
		}); err != nil {
		return err
	}

	// Delete from nat-ret
	if err := ebpf.BatchMapOperation(namePrefix+"_nat_ret_tabl",
		ciliumebpf.LRUHash,
		func(m *ciliumebpf.Map) error {
			ip := util.ConvertUint32ToIP(e.AddrExternal)
			ipb := [4]byte{}
			copy(ipb[:], ip)
			key := ebpf.AddrPort{
				Proto: e.Protocol,
				Addr:  ipb,
				Port:  util.BS16(e.PortExternal),
			}
			if err := m.Delete(key); err != nil {
				fmt.Printf("DEBUG: delete key failed (2) ... ignore\n")
				//return err
			}
			return nil
		}); err != nil {
		return err
	}

	return nil
}

func (e CacheEntry) IsExpired() (bool, error) {
	timeoutDuration := time.Duration(1000 * time.Second)
	now := time.Now()
	updatedAt, err := util.KtimeSecToTime(e.UpdatedAt)
	if err != nil {
		return false, err
	}
	diff := now.Sub(updatedAt)
	return diff > timeoutDuration, nil
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

func getLatestCache(namePrefix string) (*Cache, error) {
	// Bi-directional Cache tmp data
	cache := Cache{}

	// Parse NAT-Out Caches
	if err := ebpf.BatchMapOperation(namePrefix+"_nat_out_tabl",
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
		return nil, err
	}

	// Parse NAT-Ret Caches
	if err := ebpf.BatchMapOperation(namePrefix+"_nat_ret_tabl",
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
		return nil, err
	}

	return &cache, nil
}

func NewCommandMapInstallNat() *cobra.Command {
	var clioptNamePrefix string
	var clioptFlow string
	cmd := &cobra.Command{
		Use: "map-install-nat-cache",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Parse CLI Input
			println(clioptFlow)
			words := strings.Split(clioptFlow, ":")
			if len(words) != 5 {
				return fmt.Errorf("invalid format %s", clioptFlow)
			}

			// Parse Porotocol
			protoS := words[0]
			protoI, err := strconv.Atoi(protoS)
			proto := uint8(protoI)
			if err != nil {
				return err
			}

			// Parse Internal IP Address
			iaddrS := words[1]
			iaddrNI := net.ParseIP(iaddrS)
			iaddr := [4]uint8{}
			copy(iaddr[:], iaddrNI[12:])

			// Parse Internal Port Number
			iportS := words[2]
			iportI, err := strconv.Atoi(iportS)
			iport := util.BS16(uint16(iportI))
			if err != nil {
				return err
			}

			// Parse External IP Address
			eaddrS := words[3]
			eaddrNI := net.ParseIP(eaddrS)
			eaddr := [4]uint8{}
			copy(eaddr[:], eaddrNI[12:])

			// Parse External Port Number
			eportS := words[4]
			eportI, err := strconv.Atoi(eportS)
			eport := util.BS16(uint16(eportI))
			if err != nil {
				return err
			}

			// Get current time as ktimeSec
			nowKtime, err := util.TimeToKtimeSec(time.Now())
			if err != nil {
				return err
			}

			// nat-out
			if err := ebpf.BatchMapOperation(clioptNamePrefix+"_nat_out_tabl",
				ciliumebpf.LRUHash,
				func(m *ciliumebpf.Map) error {
					key := ebpf.AddrPort{
						Proto: uint8(proto),
						Addr:  iaddr,
						Port:  iport,
					}
					val := ebpf.AddrPortStats{
						Proto:     uint8(proto),
						Addr:      eaddr,
						Port:      eport,
						CreatedAt: nowKtime,
						UpdatedAt: nowKtime,
					}
					if err := m.Update(key, val, ciliumebpf.UpdateNoExist); err != nil {
						return err
					}
					return nil
				}); err != nil {
				return err
			}

			// nat-ret
			if err := ebpf.BatchMapOperation(clioptNamePrefix+"_nat_ret_tabl",
				ciliumebpf.LRUHash,
				func(m *ciliumebpf.Map) error {
					key := ebpf.AddrPort{
						Proto: uint8(proto),
						Addr:  eaddr,
						Port:  eport,
					}
					val := ebpf.AddrPortStats{
						Proto:     uint8(proto),
						Addr:      iaddr,
						Port:      iport,
						CreatedAt: nowKtime,
						UpdatedAt: nowKtime,
					}
					if err := m.Update(key, val, ciliumebpf.UpdateNoExist); err != nil {
						return err
					}
					return nil
				}); err != nil {
				return err
			}

			return nil
		},
	}
	cmd.Flags().StringVarP(&clioptNamePrefix, "name", "n", "n1", "")
	cmd.Flags().StringVarP(&clioptFlow, "flow", "f", "6:10.0.0.1:1024:142.0.0.1:1600", "")
	return cmd
}

func NewCommandMapDumpNat() *cobra.Command {
	var clioptMapNamePrefix string
	cmd := &cobra.Command{
		Use: "map-dump-nat",
		RunE: func(cmd *cobra.Command, args []string) error {
			cache, err := getLatestCache(clioptMapNamePrefix)
			if err != nil {
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

var (
	Name string
)

func httpHandler(w http.ResponseWriter, r *http.Request) {
	//println("call")
	q0 := r.FormValue("q")
	q1, err := base64.StdEncoding.DecodeString(q0)
	if err != nil {
		io.WriteString(w, "ERROR1\n")
		return
	}
	words := strings.Split(string(q1), "/")
	if len(words) != 5 {
		io.WriteString(w, "ERROR2\n")
		return
	}
	sidStr := words[0]
	protStr := words[1]
	addrStr := words[2]
	portStr := words[3]
	isoutStr := words[4]

	sid := net.ParseIP(sidStr)
	prot, err := strconv.Atoi(protStr)
	if err != nil {
		io.WriteString(w, "ERROR3\n")
		return
	}
	addr := util.ConvertIPToUint32(net.ParseIP(addrStr))
	port, err := strconv.Atoi(portStr)
	if err != nil {
		io.WriteString(w, "ERROR4\n")
		return
	}
	isout, err := strconv.Atoi(isoutStr)
	if err != nil {
		io.WriteString(w, "ERROR4.1\n")
		return
	}
	// pp.Println(sid, prot, addr, port)

	cache, err := getLatestCache(Name)
	if err != nil {
		io.WriteString(w, "ERROR5\n")
		return
	}

	// Match Internal to External map
	for _, ent := range cache.entries {
		if isout == 1 {
			if ent.Protocol != uint8(prot) ||
				ent.AddrInternal != addr ||
				ent.PortInternal != uint16(port) {
				continue
			}
		} else {
			if ent.Protocol != uint8(prot) ||
				ent.AddrExternal != addr ||
				ent.PortExternal != uint16(port) {
				continue
			}
		}

		out, err := json.MarshalIndent(ent, "", "  ")
		if err != nil {
			io.WriteString(w, "ERROR6\n")
			return
		}
		io.WriteString(w, string(out)+"\n")
		return
	}

	// Check More Previous node
	head := [16]uint8{}
	u8 := [16]uint8{}
	copy(u8[:], sid)
	copy(head[:], sid)
	u8 = BitShiftLeft8(u8)
	u8 = BitShiftLeft8(u8)
	u8[0] = head[0]
	u8[1] = head[1]
	copy(sid, u8[:])
	//fmt.Printf("%s\n", sid)
	host := [16]uint8{}
	copy(host[:], sid)
	for i := 3; i < 16; i++ {
		host[i] = 0
	}
	hostip := net.IP(host[:])
	//fmt.Printf("sid: %s\n", sid)
	//fmt.Printf("host: %s\n", hostip.To16())

	if u8[2] == 0 && u8[3] == 0 {
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, "{\"msg\": \"END\"}\n")
		return
	}

	nextParam := fmt.Sprintf("%s/%s/%s/%s/%s",
		sid, protStr, addrStr, portStr, isoutStr)
	nextParam = base64.StdEncoding.EncodeToString([]byte(nextParam))
	//fmt.Printf("param: %s\n", nextParam)
	//fmt.Printf("host: %s\n", hostip.To16())

	url := fmt.Sprintf("http://[%s]:8080/?q=%s", hostip, nextParam)
	//println(url)
	resp, err := http.Get(url)
	if err != nil {
		io.WriteString(w, "ERROR7\n")
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		io.WriteString(w, "ERROR8\n")
		return
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

func NewCommandDaemonNat() *cobra.Command {
	var clioptPort int
	var clioptNamePrefixes []string
	cmd := &cobra.Command{
		Use: "daemon-nat",
		RunE: func(cmd *cobra.Command, args []string) error {
			go func() {
				Name = clioptNamePrefixes[0]
				http.HandleFunc("/", httpHandler)
				http.ListenAndServe(fmt.Sprintf(":%d", clioptPort), nil)
			}()
			go threadEventHandler(clioptNamePrefixes[0])
			t(clioptNamePrefixes)
			return nil
		},
	}
	cmd.Flags().StringArrayVarP(&clioptNamePrefixes,
		"name", "n", []string{"n1"}, "")
	cmd.Flags().IntVarP(&clioptPort, "port", "p", 8080, "")
	return cmd
}

func threadEventHandler(name string) {
	perfEvent, err := ebpf.StartReader(name + "_events")
	if err != nil {
		panic(err)
	}
	defer close(perfEvent)

	for {
		// Parse event data
		pe := <-perfEvent
		var sidBytes [16]uint8
		var addrBytes [4]uint8
		var port uint16
		var proto uint8
		var isOut uint8
		buf := bytes.NewBuffer(pe.Record.RawSample)
		binary.Read(buf, binary.BigEndian, &sidBytes)
		binary.Read(buf, binary.BigEndian, &addrBytes)
		binary.Read(buf, binary.BigEndian, &port)
		binary.Read(buf, binary.BigEndian, &proto)
		binary.Read(buf, binary.BigEndian, &isOut)
		for i := 3; i < 16; i++ {
			sidBytes[i] = 0
		}
		sid := net.IP(sidBytes[:])
		addr := net.IP(addrBytes[:])

		// Resolve session caches from remote N-node recursivery
		nextParam := fmt.Sprintf("%s/%d/%s/%d/%d", sid, proto, addr, port, isOut)
		nextParam = base64.StdEncoding.EncodeToString([]byte(nextParam))
		url := fmt.Sprintf("http://[%s]:8080/?q=%s", sid, nextParam)
		resp, err := http.Get(url)
		if err != nil {
			fmt.Printf("E: %+v\n", err)
			continue
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("E: %+v\n", err)
			resp.Body.Close()
			continue
		}
		// fmt.Printf("LOG: %s\n", nextParam)
		// fmt.Printf("OUT: %s\n\n", string(body))

		// Install NAT Cache
		ent := CacheEntry{}
		if err := json.Unmarshal(body, &ent); err != nil {
			fmt.Printf("E: %+v\n", err)
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

		var iAddrByte [4]uint8
		var eAddrByte [4]uint8
		iAddrIP := util.ConvertUint32ToIP(ent.AddrInternal)
		eAddrIP := util.ConvertUint32ToIP(ent.AddrExternal)
		copy(iAddrByte[:], iAddrIP)
		copy(eAddrByte[:], eAddrIP)

		// nat-out
		if err := ebpf.BatchMapOperation(name+"_nat_out_tabl",
			ciliumebpf.LRUHash,
			func(m *ciliumebpf.Map) error {
				key := ebpf.AddrPort{
					Proto: uint8(ent.Protocol),
					Addr:  iAddrByte,
					Port:  util.BS16((ent.PortInternal)),
				}
				val := ebpf.AddrPortStats{
					Proto:     uint8(proto),
					Addr:      eAddrByte,
					Port:      util.BS16(uint16(ent.PortExternal)),
					CreatedAt: ent.CreatedAt,
					UpdatedAt: ent.UpdatedAt,
				}
				if err := m.Update(key, val, ciliumebpf.UpdateNoExist); err != nil {
					return err
				}
				return nil
			}); err != nil {
			fmt.Printf("E: %+v\n", err)
			continue
		}

		// nat-ret
		if err := ebpf.BatchMapOperation(name+"_nat_ret_tabl",
			ciliumebpf.LRUHash,
			func(m *ciliumebpf.Map) error {
				key := ebpf.AddrPort{
					Proto: uint8(proto),
					Addr:  eAddrByte,
					Port:  util.BS16(uint16(ent.PortExternal)),
				}
				val := ebpf.AddrPortStats{
					Proto:     uint8(ent.Protocol),
					Addr:      iAddrByte,
					Port:      util.BS16((ent.PortInternal)),
					CreatedAt: ent.CreatedAt,
					UpdatedAt: ent.UpdatedAt,
				}
				if err := m.Update(key, val, ciliumebpf.UpdateNoExist); err != nil {
					return err
				}
				return nil
			}); err != nil {
			fmt.Printf("E: %+v\n", err)
			continue
		}
	}
}

func t(names []string) {
	ticker1 := time.NewTicker(time.Second)
	ticker2 := time.NewTicker(time.Second)

	for {
		select {
		case <-ticker1.C:
			for _, name := range names {
				// Get cache
				cache, err := getLatestCache(name)
				if err != nil {
					fmt.Printf("ERROR1: %s\n", err.Error())
					continue
				}

				// Walk and cleanup cache entry
				for _, ent := range cache.entries {
					expired, err := ent.IsExpired()
					if err != nil {
						fmt.Printf("ERROR2: %s\n", err.Error())
						continue
					}
					if expired {
						if err := ent.CleanupMapEntri(name); err != nil {
							fmt.Printf("ERROR3: %s\n", err.Error())
							continue
						}
						// TODO(slankdev): make LOG here
					}
				}
			}

		case <-ticker2.C:
			continue
		}
	}
}
