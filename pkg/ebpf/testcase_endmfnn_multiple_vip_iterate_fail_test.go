package ebpf

import (
	"net"
	"sort"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/slankdev/mfplane/pkg/util"
)

type EndMfnNatMultipleVipIterateFailTestCase struct{}

func (tc EndMfnNatMultipleVipIterateFailTestCase) ProgInfo() (string, []string) {
	return "common_main.c", []string{
		"DEBUG_NAT_CONFLICT",
		"DEBUG_FUNCTION_CALL",
		"SNAT_RANDOM_BIT_ZERO",
		"SNAT_VIPS_LOOP_COUNT=32",
	}
}

func (tc EndMfnNatMultipleVipIterateFailTestCase) GenerateInput() ([]byte, error) {
	// Ethernet
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       util.MustParseMAC("52:54:00:00:00:01"),
		DstMAC:       util.MustParseMAC("52:54:00:00:00:02"),
		EthernetType: layers.EthernetTypeIPv6,
	}

	// IPv6
	ipv6Layer := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolIPv6Routing,
		HopLimit:   64,
		SrcIP:      net.ParseIP("2001:db8::1"),
		DstIP:      net.ParseIP("fc00:3100::"),
	}

	// SRH
	segmentList := []net.IP{
		net.ParseIP("fc00:3100::"),
	}
	seg6Layer := &util.Srv6Layer{
		NextHeader:   uint8(layers.IPProtocolIPv4),
		HdrExtLen:    uint8((8+16*len(segmentList))/8 - 1),
		RoutingType:  4, // SRH
		SegmentsLeft: uint8(len(segmentList)),
		LastEntry:    uint8(len(segmentList) - 1),
		Flags:        0,
		Tag:          0,
		Segments:     segmentList,
	}

	// IPv4
	ipv4Layer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.ParseIP("10.0.1.10"),
		DstIP:    net.ParseIP("20.0.0.1"),
		Protocol: layers.IPProtocolUDP,
	}

	// UDP
	udpLayer := &layers.UDP{
		SrcPort: 10000,
		DstPort: 443,
	}
	if err := udpLayer.SetNetworkLayerForChecksum(ipv4Layer); err != nil {
		return nil, err
	}

	// Craft
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ethernetLayer,
		ipv6Layer,
		seg6Layer,
		ipv4Layer,
		udpLayer,
		gopacket.Payload([]byte("Hello, MF-Plane!")),
	); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (tc EndMfnNatMultipleVipIterateFailTestCase) GenerateOutput() (int, []byte, error) {
	return XDP_DROP, nil, nil
}

func (tc EndMfnNatMultipleVipIterateFailTestCase) OutputPostProcess(b []byte) ([]byte, error) {
	return nil, nil
}

func (tc EndMfnNatMultipleVipIterateFailTestCase) PreTestMapContext() *ProgRunMapContext {
	c := ProgRunMapContext{
		Fib6Render: Fib6Render{
			Items: []Fib6RenderItem{
				{
					Key: StructTrie6KeyRender{
						Prefix: "fc00:3100::/32",
					},
					Val: StructTrie6ValRender{
						EndMNFN: &EndMFN{
							BackendBlockIndex: 0,
							Vip: []string{
								"142.0.0.1",
								"142.0.0.3",
							},
							NatPortHashBit:     255,
							UsidBlockLength:    16,
							UsidFunctionLength: 16,
							StatsTotalBytes:    6850,
							StatsTotalPkts:     51,
							StatsRedirBytes:    0,
							StatsRedirPkts:     0,
							NatMapping:         0,
							NatFiltering:       0,
							Sources: []StructTrie6ValRenderSnatSource{
								{Prefix: "10.0.1.0/24"},
							},
						},
					},
				},
			},
		},
		Fib4Render: Fib4Render{
			Items: []Fib4RenderItem{
				{
					Key: StructTrie4KeyRender{
						Prefix: "20.0.0.1/32",
					},
					Val: StructTrie4ValRender{
						L3XConnect: &L3XConnect{
							Nexthops: []StructTrieValNexthopRender{
								{NhAddr4: "30.0.0.1"},
							},
						},
					},
				},
			},
		},
		NeighRender: NeighRender{
			Items: []NeighRenderItem{
				{
					Key: StructNeighKeyRender{
						Addr4: "30.0.0.1",
					},
					Val: StructNeighValRender{
						Mac: "52:54:00:11:00:01",
					},
				},
			},
		},
		NatRetRender: NatRetRender{
			Items: []NatRetRenderItem{
				{
					Key: StructAddrPortRender{
						Addr:  "142.0.0.1",
						Port:  0x007c,
						Proto: 17,
					},
					Val: StructAddrPortStatsRender{
						Addr:      "10.0.2.10",
						Port:      4135,
						Proto:     17,
						Pkts:      1234,
						Bytes:     11223344,
						CreatedAt: 0,
						UpdatedAt: 0,
					},
				},
				{
					Key: StructAddrPortRender{
						Addr:  "142.0.0.3",
						Port:  0x007c,
						Proto: 17,
					},
					Val: StructAddrPortStatsRender{
						Addr:      "10.0.3.10",
						Port:      4135,
						Proto:     17,
						Pkts:      1234,
						Bytes:     11223344,
						CreatedAt: 0,
						UpdatedAt: 0,
					},
				},
			},
		},
	}
	return &c
}

func (tc EndMfnNatMultipleVipIterateFailTestCase) PostTestMapContextPreprocess(mc *ProgRunMapContext) {
	mc.CounterRender = CounterRender{}
	mc.Fib4Render = Fib4Render{}
	mc.Fib6Render = Fib6Render{}
	mc.NeighRender = NeighRender{}
	mc.LbBackendRender = LbBackendRender{}
	mc.EncapSourceRender = EncapSourceRender{}
	mc.OverlayFib4Render = OverlayFib4Render{}
	mc.NatOutRender = NatOutRender{}
	for i := 0; i < len(mc.NatRetRender.Items); i++ {
		mc.NatRetRender.Items[i].Val.CreatedAt = 0
		mc.NatRetRender.Items[i].Val.UpdatedAt = 0
		mc.NatRetRender.Items[i].Key.Port = mc.NatRetRender.Items[i].Key.Port & 0x00ff // mf-nat
	}

	items2 := mc.NatRetRender.Items
	sort.Slice(items2, func(i, j int) bool {
		if items2[i].Key.Addr != items2[j].Key.Addr {
			return items2[i].Key.Addr < items2[j].Key.Addr
		}
		if items2[i].Key.Port != items2[j].Key.Port {
			return items2[i].Key.Port < items2[j].Key.Port
		}
		if items2[i].Key.Proto != items2[j].Key.Proto {
			return items2[i].Key.Proto < items2[j].Key.Proto
		}
		return false
	})
}

func (tc EndMfnNatMultipleVipIterateFailTestCase) PostTestMapContextExpect() *ProgRunMapContext {
	c := ProgRunMapContext{
		NatRetRender: NatRetRender{
			Items: []NatRetRenderItem{
				{
					Key: StructAddrPortRender{
						Addr:  "142.0.0.1",
						Port:  0x007c,
						Proto: 17,
					},
					Val: StructAddrPortStatsRender{
						Addr:      "10.0.2.10",
						Port:      4135,
						Proto:     17,
						Pkts:      1234,
						Bytes:     11223344,
						CreatedAt: 0,
						UpdatedAt: 0,
					},
				},
				{
					Key: StructAddrPortRender{
						Addr:  "142.0.0.3",
						Port:  0x007c,
						Proto: 17,
					},
					Val: StructAddrPortStatsRender{
						Addr:      "10.0.3.10",
						Port:      4135,
						Proto:     17,
						Pkts:      1234,
						Bytes:     11223344,
						CreatedAt: 0,
						UpdatedAt: 0,
					},
				},
			},
		},
	}
	return &c
}

func TestEndMfnNatMultipleVipIterateFailTestCase(t *testing.T) {
	ExecuteTestCase(EndMfnNatMultipleVipIterateFailTestCase{}, t)
}
