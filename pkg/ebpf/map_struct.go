package ebpf

import (
	"fmt"
	"net"
	"reflect"
	"syscall"

	"github.com/slankdev/mfplane/pkg/util"
)

type StructAddrPort struct {
	Addr  [4]uint8
	Port  uint16
	Proto uint8
}

func (val *StructAddrPort) ToRender() (KVRender, error) {
	r := StructAddrPortRender{}
	r.Addr = fmt.Sprintf("%s", net.IP(val.Addr[:]))
	r.Port = val.Port
	r.Proto = val.Proto
	return &r, nil
}

type StructAddrPortRender struct {
	Addr  string `json:"addr"` // ipv4 addr
	Port  uint16 `json:"port"`
	Proto uint8  `json:"proto"`
}

func (r *StructAddrPortRender) ToRaw() (KVRaw, error) {
	key := StructAddrPort{}
	ip := net.ParseIP(r.Addr)
	if ip == nil {
		return nil, fmt.Errorf("%s is invalid as ip-addr", r.Addr)
	}
	copy(key.Addr[:], ip[12:])
	key.Port = r.Port
	key.Proto = r.Proto
	return &key, nil
}

var (
	// struct addr_port
	_ KVRaw    = &StructAddrPort{}
	_ KVRender = &StructAddrPortRender{}
)

type StructAddrPortStats struct {
	Addr      [4]uint8
	Port      uint16
	Proto     uint8
	Reserve   uint8
	Pkts      uint64
	Bytes     uint64
	CreatedAt uint64
	UpdatedAt uint64
	Flags     uint64
	Timer     StructBpfTimer
}

type StructBpfTimer struct {
	Reserv1 uint64 `json:"reserv1"`
	Reserv2 uint64 `json:"reserv2"`
}

const (
	TCP_STATE_CLOSING   uint64 = (1 << 0)
	TCP_STATE_ESTABLISH uint64 = (1 << 1)
)

func (raw *StructAddrPortStats) ToRender() (KVRender, error) {
	render := StructAddrPortStatsRender{}
	render.Addr = fmt.Sprintf("%s", net.IP(raw.Addr[:]))
	render.Port = raw.Port
	render.Proto = raw.Proto
	render.Pkts = raw.Pkts
	render.Bytes = raw.Bytes
	render.CreatedAt = raw.CreatedAt
	render.UpdatedAt = raw.UpdatedAt
	if raw.Flags&TCP_STATE_CLOSING != 0 {
		render.Flags.TcpStateClosing = true
	}
	if raw.Flags&TCP_STATE_ESTABLISH != 0 {
		render.Flags.TcpStateEstablish = true
	}
	return &render, nil
}

type AddrPortStatsFlags struct {
	TcpStateClosing   bool `json:"tcp_state_closing"`
	TcpStateEstablish bool `json:"tcp_state_establish"`
}

func (render *AddrPortStatsFlags) Uint64() uint64 {
	raw := uint64(0)
	if render.TcpStateClosing {
		raw |= TCP_STATE_CLOSING
	}
	if render.TcpStateEstablish {
		raw |= TCP_STATE_ESTABLISH
	}
	return raw
}

type StructAddrPortStatsRender struct {
	Addr      string             `json:"addr"` // ipv4
	Port      uint16             `json:"port"`
	Proto     uint8              `json:"proto"`
	Pkts      uint64             `json:"pkts"`
	Bytes     uint64             `json:"bytes"`
	CreatedAt uint64             `json:"created_at"`
	UpdatedAt uint64             `json:"update_at"`
	Flags     AddrPortStatsFlags `json:"flags"`
}

func (render *StructAddrPortStatsRender) ToRaw() (KVRaw, error) {
	raw := StructAddrPortStats{}
	ip := net.ParseIP(render.Addr)
	if ip == nil {
		return nil, fmt.Errorf("%s is invalid as ip-addr", render.Addr)
	}
	copy(raw.Addr[:], ip[12:])
	raw.Port = render.Port
	raw.Proto = render.Proto
	raw.Pkts = render.Pkts
	raw.Bytes = render.Bytes
	raw.CreatedAt = render.CreatedAt
	raw.UpdatedAt = render.UpdatedAt
	raw.Flags = render.Flags.Uint64()
	return &raw, nil
}

var (
	// struct addr_port_stats
	_ KVRaw    = &StructAddrPortStats{}
	_ KVRender = &StructAddrPortStatsRender{}
)

type StructTrie4Key struct {
	Prefixlen uint32
	Addr      [4]uint8
}

func (raw *StructTrie4Key) ToRender() (KVRender, error) {
	render := StructTrie4KeyRender{}
	render.Prefix = fmt.Sprintf("%s/%d", net.IP(raw.Addr[:]), raw.Prefixlen)
	return &render, nil
}

type StructTrie4KeyRender struct {
	Prefix string `json:"prefix"`
}

func (render *StructTrie4KeyRender) ToRaw() (KVRaw, error) {
	raw := StructTrie4Key{}
	_, ipnet, err := net.ParseCIDR(render.Prefix)
	if err != nil {
		return nil, err
	}
	copy(raw.Addr[:], ipnet.IP)
	raw.Prefixlen = uint32(util.Plen(ipnet.Mask))
	return &raw, nil
}

var (
	// struct trie4_key
	_ KVRaw    = &StructTrie4Key{}
	_ KVRender = &StructTrie4KeyRender{}
)

const (
	TRIE4_VAL_ACTION_END_MFNN    = 0
	TRIE4_VAL_ACTION_L3_XCONNECT = 2
)

type StructTrieValNexthop struct {
	NhFamily uint16
	NhAddr4  [4]uint8
	NhAddr6  [16]uint8
}

type StructTrie4Val struct {
	Action            uint16
	BackendBlockIndex uint16
	NatPortHashBit    uint16
	L3XConnNhCount    uint16
	L3XConnNh         [16]StructTrieValNexthop
}

func (raw *StructTrie4Val) ToRender() (KVRender, error) {
	render := StructTrie4ValRender{}
	switch raw.Action {
	case TRIE4_VAL_ACTION_END_MFNN:
		render.EndMNFL4 = &EndMFN{
			BackendBlockIndex: raw.BackendBlockIndex,
			NatPortHashBit:    raw.NatPortHashBit,
		}
	case TRIE4_VAL_ACTION_L3_XCONNECT:
		l3x := L3XConnect{}
		for i := 0; i < int(raw.L3XConnNhCount); i++ {
			nh := raw.L3XConnNh[i]
			nhRender := StructTrieValNexthopRender{}
			switch nh.NhFamily {
			case syscall.AF_INET:
				nhRender.NhAddr4 = net.IP(nh.NhAddr4[:]).String()
			case syscall.AF_INET6:
				nhRender.NhAddr6 = net.IP(nh.NhAddr6[:]).String()
			default:
				return nil, fmt.Errorf("invalid nh family %d", nh.NhFamily)
			}
			l3x.Nexthops = append(l3x.Nexthops, nhRender)
		}
		render.L3XConnect = &l3x
	default:
		return nil, fmt.Errorf("invalid format")
	}
	return &render, nil
}

const (
	TRIE6_VAL_ACTION_UNSPEC      = 0
	TRIE6_VAL_ACTION_L3_XCONNECT = 1
	TRIE6_VAL_ACTION_END_MFNL    = 123
	TRIE6_VAL_ACTION_END_MFNN    = 456
)

type StructTrieValNexthopRender struct {
	NhAddr4 string `json:"nh_addr4,omitemtpy"`
	NhAddr6 string `json:"nh_addr6,omitempty"`
}

type EndMFNL4 struct {
	BackendBlockIndex uint16 `json:"backend_block_index"`
	NatPortHashBit    uint16 `json:"nat_port_hash_bit"`
}

type StructTrie4ValRender struct {
	EndMNFL4   *EndMFN     `json:"end_mfn_l,omitempty"`
	L3XConnect *L3XConnect `json:"l3xconnect,omitempty"`
}

func (render *StructTrie4ValRender) ToRaw() (KVRaw, error) {
	cnt := 0
	raw := StructTrie4Val{}
	if render.EndMNFL4 != nil {
		cnt++
		raw.Action = TRIE4_VAL_ACTION_END_MFNN
		raw.BackendBlockIndex = render.EndMNFL4.BackendBlockIndex
		raw.NatPortHashBit = render.EndMNFL4.NatPortHashBit
	}
	if render.L3XConnect != nil {
		cnt++
		raw.Action = TRIE4_VAL_ACTION_L3_XCONNECT
		if len(render.L3XConnect.Nexthops) > 16 {
			return nil, fmt.Errorf("too long")
		}
		raw.L3XConnNhCount = uint16(len(render.L3XConnect.Nexthops))
		for i, nh := range render.L3XConnect.Nexthops {
			nhcnt := 0
			if nh.NhAddr4 != "" {
				nhcnt++
				addr4 := net.ParseIP(nh.NhAddr4)
				if addr4 == nil {
					return nil, fmt.Errorf("%s is invalid as ip-addr", nh.NhAddr4)
				}
				copy(raw.L3XConnNh[i].NhAddr4[:], addr4[12:])
				raw.L3XConnNh[i].NhFamily = syscall.AF_INET
			}
			if nh.NhAddr6 != "" {
				nhcnt++
				addr6 := net.ParseIP(nh.NhAddr6)
				if addr6 == nil {
					return nil, fmt.Errorf("%s is invalid as ip-addr", nh.NhAddr4)
				}
				copy(raw.L3XConnNh[i].NhAddr6[:], addr6[0:])
				raw.L3XConnNh[i].NhFamily = syscall.AF_INET6
			}
			if nhcnt != 1 {
				return nil, fmt.Errorf("invalid format")
			}
		}
	}
	return &raw, nil
}

var (
	// struct trie4_val
	_ KVRaw    = &StructTrie4Val{}
	_ KVRender = &StructTrie4ValRender{}
)

type StructTrie6Key struct {
	Prefixlen uint32
	Addr      [16]uint8
}

func (raw *StructTrie6Key) ToRender() (KVRender, error) {
	render := StructTrie6KeyRender{}
	render.Prefix = fmt.Sprintf("%s/%d", net.IP(raw.Addr[:]), raw.Prefixlen)
	return &render, nil
}

type StructTrie6KeyRender struct {
	Prefix string `json:"prefix"`
}

func (render *StructTrie6KeyRender) ToRaw() (KVRaw, error) {
	_, ipnet, err := net.ParseCIDR(render.Prefix)
	if err != nil {
		return nil, err
	}
	raw := StructTrie6Key{}
	copy(raw.Addr[:], ipnet.IP)
	raw.Prefixlen = uint32(util.Plen(ipnet.Mask))
	return &raw, nil
}

var (
	_ KVRaw    = &StructTrie6Key{}
	_ KVRender = &StructTrie6KeyRender{}
)

type StructTrie6ValSnatSource struct {
	Prefixlen uint32
	Addr      uint32
}

type StructTrie6Val struct {
	Action             uint16                        `json:"action"`
	BackendBlockIndex  uint16                        `json:"backend_block_index"`
	Vip                [32][4]uint8                  `json:"vip"`
	NatPortBashBit     uint16                        `json:"nat_port_hash_bit"`
	UsidBlockLength    uint16                        `json:"usid_block_length"`
	UsidFunctionLength uint16                        `json:"usid_function_length"`
	StatsTotalBytes    uint64                        `json:"stats_total_bytes"`
	StatsTotalPkts     uint64                        `json:"stats_total_pkts"`
	StatsRedirBytes    uint64                        `json:"stats_redir_bytes"`
	StatsRedirPkts     uint64                        `json:"stats_redir_pkts"`
	NatMapping         uint8                         `json:"nat_mapping"`
	NatFiltering       uint8                         `json:"nat_filtering"`
	Sources            [256]StructTrie6ValSnatSource `json:"sources"`

	// L3 Cross-Connect
	L3XConnNhCount uint16                   `json:"l3_xcon_nh_count"`
	L3XConnNh      [16]StructTrieValNexthop `json:"l3xconnect"`
}

func (raw *StructTrie6Val) ToRender() (KVRender, error) {
	// End.MFN.L
	// End.MFN.N
	endmfn := EndMFN{}
	endmfn.BackendBlockIndex = raw.BackendBlockIndex
	endmfn.NatPortHashBit = raw.NatPortBashBit
	endmfn.UsidBlockLength = raw.UsidBlockLength
	endmfn.UsidFunctionLength = raw.UsidFunctionLength
	endmfn.StatsTotalBytes = raw.StatsTotalBytes
	endmfn.StatsTotalPkts = raw.StatsTotalPkts
	endmfn.StatsRedirBytes = raw.StatsRedirBytes
	endmfn.StatsRedirPkts = raw.StatsRedirPkts
	endmfn.NatMapping = raw.NatMapping
	endmfn.NatFiltering = raw.NatFiltering
	for i := range raw.Vip {
		if !reflect.DeepEqual(raw.Vip[i], [4]uint8{0, 0, 0, 0}) {
			endmfn.Vip = append(endmfn.Vip, fmt.Sprintf("%s", net.IP(raw.Vip[i][:])))
		}
	}
	for idx := 0; idx < len(raw.Sources); idx++ {
		src := raw.Sources[idx]
		if src.Addr == 0 && src.Prefixlen == 0 {
			continue
		}
		endmfn.Sources = append(endmfn.Sources, StructTrie6ValRenderSnatSource{
			Prefix: fmt.Sprintf("%s/%d",
				util.ConvertUint32ToIP(raw.Sources[idx].Addr),
				raw.Sources[idx].Prefixlen),
		})
	}

	// L3 Cross-Connect
	l3x := L3XConnect{}
	for i := 0; i < int(raw.L3XConnNhCount); i++ {
		nh := raw.L3XConnNh[i]
		nhRender := StructTrieValNexthopRender{}
		switch nh.NhFamily {
		case syscall.AF_INET:
			nhRender.NhAddr4 = net.IP(nh.NhAddr4[:]).String()
		case syscall.AF_INET6:
			nhRender.NhAddr6 = net.IP(nh.NhAddr6[:]).String()
		default:
			return nil, fmt.Errorf("invalid nh family %d", nh.NhFamily)
		}
		l3x.Nexthops = append(l3x.Nexthops, nhRender)
	}

	render := StructTrie6ValRender{}
	switch raw.Action {
	case TRIE6_VAL_ACTION_END_MFNL:
		render.EndMNFL = &endmfn
	case TRIE6_VAL_ACTION_END_MFNN:
		render.EndMNFN = &endmfn
	case TRIE6_VAL_ACTION_L3_XCONNECT:
		render.L3XConnect = &l3x
	default:
		return nil, fmt.Errorf("invalid action %d", raw.Action)
	}
	return &render, nil
}

type StructTrie6ValRenderSnatSource struct {
	Prefix string `json:"prefix"`
}

type L3XConnect struct {
	Nexthops []StructTrieValNexthopRender `json:"nexthops"`
}

type EndMFN struct {
	BackendBlockIndex  uint16                           `json:"backend_block_index"`
	Vip                []string                         `json:"vip"`
	NatPortHashBit     uint16                           `json:"nat_port_hash_bit"`
	UsidBlockLength    uint16                           `json:"usid_block_length"`
	UsidFunctionLength uint16                           `json:"usid_function_length"`
	StatsTotalBytes    uint64                           `json:"stats_total_bytes"`
	StatsTotalPkts     uint64                           `json:"stats_total_pkts"`
	StatsRedirBytes    uint64                           `json:"stats_redir_bytes"`
	StatsRedirPkts     uint64                           `json:"stats_redir_pkts"`
	NatMapping         uint8                            `json:"nat_mapping"`
	NatFiltering       uint8                            `json:"nat_filtering"`
	Sources            []StructTrie6ValRenderSnatSource `json:"sources"`
}

type StructTrie6ValRender struct {
	EndMNFL    *EndMFN     `json:"end_mfn_l,omitempty"`
	EndMNFN    *EndMFN     `json:"end_mfn_n,omitempty"`
	L3XConnect *L3XConnect `json:"l3xconnect,omitempty"`
}

func (render *StructTrie6ValRender) ToRaw() (KVRaw, error) {
	cnt := 0
	raw := StructTrie6Val{}
	if render.EndMNFL != nil {
		cnt++
		raw.Action = TRIE6_VAL_ACTION_END_MFNL
		raw.BackendBlockIndex = render.EndMNFL.BackendBlockIndex
		raw.NatPortBashBit = render.EndMNFL.NatPortHashBit
		raw.UsidBlockLength = render.EndMNFL.UsidBlockLength
		raw.UsidFunctionLength = render.EndMNFL.UsidFunctionLength
		raw.StatsTotalBytes = render.EndMNFL.StatsTotalBytes
		raw.StatsTotalPkts = render.EndMNFL.StatsTotalPkts
		raw.StatsRedirBytes = render.EndMNFL.StatsRedirBytes
		raw.StatsRedirPkts = render.EndMNFL.StatsRedirPkts
		raw.NatMapping = render.EndMNFL.NatMapping
		raw.NatFiltering = render.EndMNFL.NatFiltering
		if len(render.EndMNFL.Vip) > len(raw.Vip) {
			return nil, fmt.Errorf("render.EndMNFL.Vip too long now=%d expect=%d",
				len(render.EndMNFL.Vip), len(raw.Vip))
		}
		for idx, vip := range render.EndMNFL.Vip {
			vipdata := net.ParseIP(vip)
			copy(raw.Vip[idx][:], vipdata[12:])
		}
		for idx, src := range render.EndMNFL.Sources {
			_, ipnet, err := net.ParseCIDR(src.Prefix)
			if err != nil {
				return nil, err
			}
			raw.Sources[idx].Addr = util.ConvertIPToUint32(ipnet.IP)
			raw.Sources[idx].Prefixlen = uint32(util.Plen(ipnet.Mask))
		}
	}
	if render.EndMNFN != nil {
		cnt++
		raw.Action = TRIE6_VAL_ACTION_END_MFNN
		raw.BackendBlockIndex = render.EndMNFN.BackendBlockIndex
		raw.NatPortBashBit = render.EndMNFN.NatPortHashBit
		raw.UsidBlockLength = render.EndMNFN.UsidBlockLength
		raw.UsidFunctionLength = render.EndMNFN.UsidFunctionLength
		raw.StatsTotalBytes = render.EndMNFN.StatsTotalBytes
		raw.StatsTotalPkts = render.EndMNFN.StatsTotalPkts
		raw.StatsRedirBytes = render.EndMNFN.StatsRedirBytes
		raw.StatsRedirPkts = render.EndMNFN.StatsRedirPkts
		raw.NatMapping = render.EndMNFN.NatMapping
		raw.NatFiltering = render.EndMNFN.NatFiltering
		if len(render.EndMNFN.Vip) > len(raw.Vip) {
			return nil, fmt.Errorf("render.EndMNFL.Vip too long now=%d expect=%d",
				len(render.EndMNFL.Vip), len(raw.Vip))
		}
		for idx, vip := range render.EndMNFN.Vip {
			vipdata := net.ParseIP(vip)
			copy(raw.Vip[idx][:], vipdata[12:])
		}
		for idx, src := range render.EndMNFN.Sources {
			_, ipnet, err := net.ParseCIDR(src.Prefix)
			if err != nil {
				return nil, err
			}
			raw.Sources[idx].Addr = util.ConvertIPToUint32(ipnet.IP)
			raw.Sources[idx].Prefixlen = uint32(util.Plen(ipnet.Mask))
		}
	}
	if render.L3XConnect != nil {
		cnt++
		raw.Action = TRIE6_VAL_ACTION_L3_XCONNECT
		raw.L3XConnNhCount = uint16(len(render.L3XConnect.Nexthops))
		for i, nh := range render.L3XConnect.Nexthops {
			if i >= 16 {
				return nil, fmt.Errorf("render.L3XConnNh is too long (len=%d)", len(render.L3XConnect.Nexthops))
			}
			nhcnt := 0
			if nh.NhAddr4 != "" {
				nhcnt++
				addr4 := net.ParseIP(nh.NhAddr4)
				if addr4 == nil {
					return nil, fmt.Errorf("%s is invalid as ip-addr", nh.NhAddr4)
				}
				copy(raw.L3XConnNh[i].NhAddr4[:], addr4[12:])
				raw.L3XConnNh[i].NhFamily = syscall.AF_INET
			}
			if nh.NhAddr6 != "" {
				nhcnt++
				addr6 := net.ParseIP(nh.NhAddr6)
				if addr6 == nil {
					return nil, fmt.Errorf("%s is invalid as ip-addr", nh.NhAddr4)
				}
				copy(raw.L3XConnNh[i].NhAddr6[:], addr6[0:])
				raw.L3XConnNh[i].NhFamily = syscall.AF_INET6
			}
			if nhcnt != 1 {
				return nil, fmt.Errorf("invalid format nb-nh must be 1 but %d", cnt)
			}
		}
	}
	if cnt != 1 {
		return nil, fmt.Errorf("invalid action cnt=%d", cnt)
	}

	return &raw, nil
}

var (
	_ KVRaw    = &StructTrie6Val{}
	_ KVRender = &StructTrie6ValRender{}
)

type StructEncapSource struct {
	Addr [16]uint8
}

func (raw *StructEncapSource) ToRender() (KVRender, error) {
	r := StructEncapSourceRender{}
	r.Addr = fmt.Sprintf("%s", net.IP(raw.Addr[:]))
	return &r, nil
}

func (raw *StructEncapSource) Summarize(list []StructEncapSource) {
	raw.Addr = list[0].Addr
}

type StructEncapSourceRender struct {
	Addr string `json:"addr"`
}

func (render *StructEncapSourceRender) ToRaw() (KVRaw, error) {
	raw := StructEncapSource{}
	ip := net.ParseIP(render.Addr)
	if ip == nil {
		return nil, fmt.Errorf("%s is invalid as ip-addr", render.Addr)
	}
	copy(raw.Addr[:], ip[:])
	return &raw, nil
}

var (
	// struct encap_source
	_ KVRaw    = &StructEncapSource{}
	_ KVRender = &StructEncapSourceRender{}
)

type StructOverlayFib4Key struct {
	VrfID uint32   `json:"vrf_id"`
	Addr  [4]uint8 `json:"addr"`
}

func (raw *StructOverlayFib4Key) ToRender() (KVRender, error) {
	render := StructOverlayFib4KeyRender{}
	render.VrfID = raw.VrfID
	render.Addr = fmt.Sprintf("%s", net.IP(raw.Addr[:]))
	return &render, nil
}

type StructOverlayFib4KeyRender struct {
	VrfID uint32 `json:"vrf_id"`
	Addr  string `json:"addr"` // ipv4 addr
}

func (render *StructOverlayFib4KeyRender) ToRaw() (KVRaw, error) {
	ip := net.ParseIP(render.Addr)
	if ip == nil {
		return nil, fmt.Errorf("%s is invalid as ip-addr", render.Addr)
	}
	raw := StructOverlayFib4Key{}
	raw.VrfID = render.VrfID
	copy(raw.Addr[:], ip[12:])
	return &raw, nil
}

var (
	// struct overlay_fib4_key
	_ KVRaw    = &StructOverlayFib4Key{}
	_ KVRender = &StructOverlayFib4KeyRender{}
)

type StructOverlayFib4Val struct {
	Flags uint32       `json:"flags"`
	Segs  [6][16]uint8 `json:"segs"`
}

func (raw *StructOverlayFib4Val) ToRender() (KVRender, error) {
	render := StructOverlayFib4ValRender{}
	render.Flags = raw.Flags
	for i := 0; i < len(raw.Segs); i++ {
		seg := net.IP(raw.Segs[i][:])
		zero := net.ParseIP("::")
		if !zero.Equal(seg) {
			render.Segs = append(render.Segs, seg.String())
		}
	}
	return &render, nil
}

func (raw *StructOverlayFib4Val) Summarize(list []StructOverlayFib4Val) {
	raw.Flags = list[0].Flags
	raw.Segs = list[0].Segs
}

type StructOverlayFib4ValRender struct {
	Flags uint32   `json:"flags"`
	Segs  []string `json:"segs"` // ipv6 addr array
}

func (render *StructOverlayFib4ValRender) ToRaw() (KVRaw, error) {
	raw := StructOverlayFib4Val{}
	raw.Flags = render.Flags
	if len(render.Segs) > len(raw.Segs) {
		return nil, fmt.Errorf("max size is %d, current %d",
			len(raw.Segs), len(render.Segs))
	}
	for i := 0; i < len(render.Segs); i++ {
		valIP := net.ParseIP(render.Segs[i])
		if valIP == nil {
			return nil, fmt.Errorf("%s is invalid as ip-addr", render.Segs[i])
		}
		copy(raw.Segs[i][:], valIP[:])
	}
	return &raw, nil
}

var (
	// struct overlay_fib4_val
	_ KVRaw    = &StructOverlayFib4Val{}
	_ KVRender = &StructOverlayFib4ValRender{}
)

type StructFlowProcessor struct {
	Addr            [16]uint8
	StatsTotalBytes uint64
	StatsTotalPkts  uint64
}

func (v *StructFlowProcessor) ToRender() (KVRender, error) {
	r := StructFlowProcessorRender{}
	r.Addr = fmt.Sprintf("%s", net.IP(v.Addr[:]))
	r.StatsTotalBytes = v.StatsTotalBytes
	r.StatsTotalPkts = v.StatsTotalPkts
	return &r, nil
}

func (raw *StructFlowProcessor) Summarize(list []StructFlowProcessor) {
	raw.Addr = list[0].Addr
	for _, v := range list {
		raw.StatsTotalBytes += v.StatsTotalBytes
		raw.StatsTotalPkts += v.StatsTotalPkts
	}
}

type StructFlowProcessorRender struct {
	Addr            string `json:"addr"`
	StatsTotalBytes uint64 `json:"stats_total_bytes"`
	StatsTotalPkts  uint64 `json:"stats_total_pkts"`
}

func (render *StructFlowProcessorRender) ToRaw() (KVRaw, error) {
	raw := StructFlowProcessor{}
	ip := net.ParseIP(render.Addr)
	if ip == nil {
		return nil, fmt.Errorf("%s is invalid as ip-addr", render.Addr)
	}
	copy(raw.Addr[:], ip[:])
	raw.StatsTotalBytes = render.StatsTotalBytes
	raw.StatsTotalPkts = render.StatsTotalPkts
	return &raw, nil
}

var (
	// struct flow_processor
	_ KVRaw    = &StructFlowProcessor{}
	_ KVRender = &StructFlowProcessorRender{}
)

type StructArrayKey32 struct {
	Index uint32 `json:"index"`
}

func (raw *StructArrayKey32) ToRender() (KVRender, error) {
	render := StructArrayKey32Render{}
	render.Index = raw.Index
	return &render, nil
}

type StructArrayKey32Render struct {
	Index uint32 `json:"index"`
}

func (render *StructArrayKey32Render) ToRaw() (KVRaw, error) {
	raw := StructArrayKey32{}
	raw.Index = render.Index
	return &raw, nil
}

var (
	// uint32
	_ KVRaw    = &StructArrayKey32{}
	_ KVRender = &StructArrayKey32Render{}
)

type StructNeighKey struct {
	Family uint32
	Addr4  [4]uint8
	Addr6  [16]uint8
}

func (raw *StructNeighKey) ToRender() (KVRender, error) {
	render := StructNeighKeyRender{}
	switch raw.Family {
	case syscall.AF_INET:
		render.Addr4 = net.IP(raw.Addr4[:]).String()
	case syscall.AF_INET6:
		render.Addr6 = net.IP(raw.Addr6[:]).String()
	default:
		return nil, fmt.Errorf("invalid family %d", raw.Family)

	}
	return &render, nil
}

type StructNeighKeyRender struct {
	Addr4 string `json:"addr4,omitempty"`
	Addr6 string `json:"addr6,omitempty"`
}

func (render *StructNeighKeyRender) ToRaw() (KVRaw, error) {
	raw := StructNeighKey{}
	cnt := 0
	if render.Addr4 != "" {
		cnt++
		addr4 := net.ParseIP(render.Addr4)
		if addr4 == nil {
			return nil, fmt.Errorf("%s is invalid as ip-addr", render.Addr4)
		}
		copy(raw.Addr4[:], addr4[12:])
		raw.Family = syscall.AF_INET
	}
	if render.Addr6 != "" {
		cnt++
		addr6 := net.ParseIP(render.Addr6)
		if addr6 == nil {
			return nil, fmt.Errorf("%s is invalid as ip-addr", render.Addr4)
		}
		copy(raw.Addr6[:], addr6[0:])
		raw.Family = syscall.AF_INET6
	}
	if cnt != 1 {
		return nil, fmt.Errorf("invalid format nb-keys must be 1 but %d", cnt)
	}
	return &raw, nil
}

var (
	// struct neigh_key
	_ KVRaw    = &StructNeighKey{}
	_ KVRender = &StructNeighKeyRender{}
)

type StructNeighVal struct {
	Flags uint32
	Mac   [6]uint8
}

func (raw *StructNeighVal) ToRender() (KVRender, error) {
	render := StructNeighValRender{}
	render.Flags = raw.Flags
	render.Mac = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		raw.Mac[0], raw.Mac[1], raw.Mac[2], raw.Mac[3], raw.Mac[4], raw.Mac[5])
	return &render, nil
}

func (raw *StructNeighVal) Summarize(list []StructNeighVal) {
	raw.Flags = list[0].Flags
	raw.Mac = list[0].Mac
}

type StructNeighValRender struct {
	Flags uint32 `json:"flags"`
	Mac   string `json:"mac"`
}

func (render *StructNeighValRender) ToRaw() (KVRaw, error) {
	mac, err := net.ParseMAC(render.Mac)
	if err != nil {
		return nil, err
	}
	raw := StructNeighVal{}
	raw.Flags = render.Flags
	copy(raw.Mac[:], mac)
	return &raw, nil
}

var (
	// struct neigh_key
	_ KVRaw    = &StructNeighVal{}
	_ KVRender = &StructNeighValRender{}
)

type StructCounterVal struct {
	XdpActionTxPkts                       uint64
	XdpActionTxBytes                      uint64
	XdpActionDropPkts                     uint64
	XdpActionDropBytes                    uint64
	XdpActionAbortPkts                    uint64
	XdpActionAbortBytes                   uint64
	XdpActionPassPkts                     uint64
	XdpActionPassBytes                    uint64
	MfRedirectPkts                        uint64
	MfRedirectBytes                       uint64
	MfRedirectOutPkts                     uint64
	MfRedirectRetPkts                     uint64
	Fib4Miss                              uint64
	Fib6Miss                              uint64
	NeighMiss                             uint64
	NatOutMiss                            uint64
	NatRetMiss                            uint64
	NatEndpointIndependentMappingConflict uint64
	NatReuseClosedSession                 uint64
	NatMapUpdateFailed                    uint64
	PerfEventFailed                       uint64
	NatSessionCreate                      uint64
	NatSessionDelete                      uint64
	NatTimerStartOut                      uint64
	NatTimerStartRet                      uint64
	NatTimerCallbackOutCalled             uint64
	NatTimerCallbackRetCalled             uint64
}

type StructCounterValRender StructCounterVal

func (raw *StructCounterVal) ToRender() (KVRender, error) {
	render := StructCounterValRender(*raw)
	return &render, nil
}

func (render *StructCounterValRender) ToRaw() (KVRaw, error) {
	raw := StructCounterVal(*render)
	return &raw, nil
}

func (raw *StructCounterVal) Summarize(list []StructCounterVal) {
	*raw = StructCounterVal{}
	for _, item := range list {
		raw.XdpActionTxPkts += item.XdpActionTxPkts
		raw.XdpActionTxBytes += item.XdpActionTxBytes
		raw.XdpActionDropPkts += item.XdpActionDropPkts
		raw.XdpActionDropBytes += item.XdpActionDropBytes
		raw.XdpActionAbortPkts += item.XdpActionAbortPkts
		raw.XdpActionAbortBytes += item.XdpActionAbortBytes
		raw.XdpActionPassPkts += item.XdpActionPassPkts
		raw.XdpActionPassBytes += item.XdpActionPassBytes
		raw.MfRedirectPkts += item.MfRedirectPkts
		raw.MfRedirectBytes += item.MfRedirectBytes
		raw.MfRedirectOutPkts += item.MfRedirectOutPkts
		raw.MfRedirectRetPkts += item.MfRedirectRetPkts
		raw.Fib4Miss += item.Fib4Miss
		raw.Fib6Miss += item.Fib6Miss
		raw.NeighMiss += item.NeighMiss
		raw.NatOutMiss += item.NatOutMiss
		raw.NatRetMiss += item.NatRetMiss
		raw.NatEndpointIndependentMappingConflict += item.NatEndpointIndependentMappingConflict
		raw.NatReuseClosedSession += item.NatReuseClosedSession
		raw.NatMapUpdateFailed += item.NatMapUpdateFailed
		raw.PerfEventFailed += item.PerfEventFailed
		raw.NatSessionCreate += item.NatSessionCreate
		raw.NatSessionDelete += item.NatSessionDelete
		raw.NatTimerStartOut += item.NatTimerStartOut
		raw.NatTimerStartRet += item.NatTimerStartRet
		raw.NatTimerCallbackOutCalled += item.NatTimerCallbackOutCalled
		raw.NatTimerCallbackRetCalled += item.NatTimerCallbackRetCalled
	}
}

var (
	// struct neigh_key
	_ KVRaw    = &StructCounterVal{}
	_ KVRender = &StructCounterValRender{}
)
