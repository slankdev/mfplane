package ebpf

import (
	"fmt"
	"net"

	"github.com/slankdev/mfplane/pkg/util"
)

type StructAddrPort struct {
	Addr  [4]uint8 `json:"addr"`
	Port  uint16   `json:"port"`
	Proto uint8    `json:"proto"`
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
	Addr      [4]uint8 `json:"addr"`
	Port      uint16   `json:"port"`
	Proto     uint8    `json:"proto"`
	Pkts      uint64   `json:"pkts"`
	Bytes     uint64   `json:"bytes"`
	CreatedAt uint64   `json:"created_at"`
	UpdatedAt uint64   `json:"update_at"`
	Flags     uint64   `json:"flags"`
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
	Prefixlen uint32   `json:"prefixlen"`
	Addr      [4]uint8 `json:"addr"`
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

type StructTrie4Val struct {
	BackendBlockIndex uint16 `json:"backend_block_index"`
	NatPortHashBit    uint16 `json:"nat_port_hash_bit"`
}

func (raw *StructTrie4Val) ToRender() (KVRender, error) {
	render := StructTrie4ValRender{}
	render.BackendBlockIndex = raw.BackendBlockIndex
	render.NatPortHashBit = raw.NatPortHashBit
	return &render, nil
}

type StructTrie4ValRender struct {
	BackendBlockIndex uint16 `json:"backend_block_index"`
	NatPortHashBit    uint16 `json:"nat_port_hash_bit"`
}

func (render *StructTrie4ValRender) ToRaw() (KVRaw, error) {
	raw := StructTrie4Val{}
	raw.BackendBlockIndex = render.BackendBlockIndex
	raw.NatPortHashBit = render.NatPortHashBit
	return &raw, nil
}

var (
	// struct trie4_val
	_ KVRaw    = &StructTrie4Val{}
	_ KVRender = &StructTrie4ValRender{}
)

type StructTrie6Key struct {
	Prefixlen uint32    `json:"prefixlen"`
	Addr      [16]uint8 `json:"addr"`
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
	Prefixlen uint32 `json:"prefixlen"`
	Addr      uint32 `json:"addr"`
}

type StructTrie6Val struct {
	Action             uint16                        `json:"action"`
	BackendBlockIndex  uint16                        `json:"backend_block_index"`
	Vip                [4]uint8                      `json:"vip"`
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
}

func (raw *StructTrie6Val) ToRender() (KVRender, error) {
	render := StructTrie6ValRender{}
	render.Action = raw.Action
	render.BackendBlockIndex = raw.BackendBlockIndex
	render.NatPortHashBit = raw.NatPortBashBit
	render.UsidBlockLength = raw.UsidBlockLength
	render.UsidFunctionLength = raw.UsidFunctionLength
	render.StatsTotalBytes = raw.StatsTotalBytes
	render.StatsTotalPkts = raw.StatsTotalPkts
	render.StatsRedirBytes = raw.StatsRedirBytes
	render.StatsRedirPkts = raw.StatsRedirPkts
	render.NatMapping = raw.NatMapping
	render.NatFiltering = raw.NatFiltering
	render.Vip = fmt.Sprintf("%s", net.IP(raw.Vip[:]))
	for idx := 0; idx < len(raw.Sources); idx++ {
		src := raw.Sources[idx]
		if src.Addr == 0 && src.Prefixlen == 0 {
			continue
		}
		render.Sources = append(render.Sources, StructTrie6ValRenderSnatSource{
			Prefix: fmt.Sprintf("%s/%d",
				util.ConvertUint32ToIP(raw.Sources[idx].Addr),
				raw.Sources[idx].Prefixlen),
		})
	}
	return &render, nil
}

type StructTrie6ValRenderSnatSource struct {
	Prefix string `json:"prefix"`
}

type StructTrie6ValRender struct {
	Action             uint16                           `json:"action"`
	BackendBlockIndex  uint16                           `json:"backend_block_index"`
	Vip                string                           `json:"vip"`
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

func (render *StructTrie6ValRender) ToRaw() (KVRaw, error) {
	raw := StructTrie6Val{}
	raw.Action = render.Action
	raw.BackendBlockIndex = render.BackendBlockIndex
	raw.NatPortBashBit = render.NatPortHashBit
	raw.UsidBlockLength = render.UsidBlockLength
	raw.UsidFunctionLength = render.UsidFunctionLength
	raw.StatsTotalBytes = render.StatsTotalBytes
	raw.StatsTotalPkts = render.StatsTotalPkts
	raw.StatsRedirBytes = render.StatsRedirBytes
	raw.StatsRedirPkts = render.StatsRedirPkts
	raw.NatMapping = render.NatMapping
	raw.NatFiltering = render.NatFiltering
	vipdata := net.ParseIP(render.Vip)
	copy(raw.Vip[:], vipdata[12:])
	for idx, src := range render.Sources {
		_, ipnet, err := net.ParseCIDR(src.Prefix)
		if err != nil {
			return nil, err
		}
		raw.Sources[idx].Addr = util.ConvertIPToUint32(ipnet.IP)
		raw.Sources[idx].Prefixlen = uint32(util.Plen(ipnet.Mask))
	}
	return &raw, nil
}

var (
	_ KVRaw    = &StructTrie6Val{}
	_ KVRender = &StructTrie6ValRender{}
)

type StructEncapSource struct {
	Addr [16]uint8 `json:"addr"`
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
	Addr            [16]uint8 `json:"addr"`
	StatsTotalBytes uint64    `json:"stats_total_bytes"`
	StatsTotalPkts  uint64    `json:"stats_total_pkts"`
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
