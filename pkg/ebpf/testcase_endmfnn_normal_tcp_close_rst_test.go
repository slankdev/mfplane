package ebpf

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/slankdev/mfplane/pkg/util"
)

type EndMfnNormalTcpCloseRstTestCase struct{}

func (tc EndMfnNormalTcpCloseRstTestCase) GenerateInput() ([]byte, error) {
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
		SrcIP:    net.ParseIP("20.0.0.1"),
		DstIP:    net.ParseIP("142.0.0.1"),
		Protocol: layers.IPProtocolTCP,
	}

	// TCP
	tcpLayer := &layers.TCP{
		SrcPort: 443,
		DstPort: 0x6700,
		RST:     true,
	}
	if err := tcpLayer.SetNetworkLayerForChecksum(ipv4Layer); err != nil {
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
		tcpLayer,
	); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (tc EndMfnNormalTcpCloseRstTestCase) GenerateOutput() (int, []byte, error) {
	// Ethernet
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       util.MustParseMAC("52:54:00:00:00:02"),
		DstMAC:       util.MustParseMAC("52:54:00:22:00:01"),
		EthernetType: layers.EthernetTypeIPv6,
	}

	// IPv6
	ipv6Layer := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolIPv6Routing,
		HopLimit:   64,
		SrcIP:      net.ParseIP("2001:db8::1"),
		DstIP:      net.ParseIP("fc00:1101::"),
	}

	// SRH
	segmentList := []net.IP{
		net.ParseIP("fc00:1101::"),
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
		SrcIP:    net.ParseIP("20.0.0.1"),
		DstIP:    net.ParseIP("10.0.1.10"),
		Protocol: layers.IPProtocolTCP,
	}

	// TCP
	tcpLayer := &layers.TCP{
		SrcPort: 443,
		DstPort: 0x2710,
		RST:     true,
	}
	if err := tcpLayer.SetNetworkLayerForChecksum(ipv4Layer); err != nil {
		return 0, nil, err
	}

	// Craft
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ethernetLayer,
		ipv6Layer,
		seg6Layer,
		ipv4Layer,
		tcpLayer,
	); err != nil {
		return 0, nil, err
	}

	return XDP_TX, buf.Bytes(), nil
}

func (tc EndMfnNormalTcpCloseRstTestCase) OutputPostProcess(b []byte) ([]byte, error) {
	return b, nil
}

func (tc EndMfnNormalTcpCloseRstTestCase) PreTestMapContext() *ProgRunMapContext {
	c := ProgRunMapContext{
		Fib6Render: Fib6Render{
			Items: []Fib6RenderItem{
				{
					Key: StructTrie6KeyRender{
						Prefix: "fc00:3100::/32",
					},
					Val: StructTrie6ValRender{
						EndMNFN: &EndMFN{
							BackendBlockIndex:  0,
							Vip:                "142.0.0.1",
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
				{
					Key: StructTrie6KeyRender{
						Prefix: "fc00:1101::/32",
					},
					Val: StructTrie6ValRender{
						L3XConnect: &L3XConnect{
							Nexthops: []StructTrieValNexthopRender{
								{NhAddr6: "fe80::1"},
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
						Addr6: "fe80::1",
					},
					Val: StructNeighValRender{
						Mac: "52:54:00:22:00:01",
					},
				},
			},
		},
		OverlayFib4Render: OverlayFib4Render{
			Items: []OverlayFib4RenderItem{
				{
					Key: StructOverlayFib4KeyRender{
						VrfID: 1,
						Addr:  "10.0.1.10",
					},
					Val: StructOverlayFib4ValRender{
						Flags: 0,
						Segs: []string{
							"fc00:1101::",
						},
					},
				},
			},
		},
		NatOutRender: NatOutRender{
			Items: []NatOutRenderItem{
				{
					Key: StructAddrPortRender{
						Addr:  "10.0.1.10",
						Port:  4135,
						Proto: 6,
					},
					Val: StructAddrPortStatsRender{
						Addr:      "142.0.0.1",
						Port:      0x0067,
						Proto:     6,
						Pkts:      1,
						Bytes:     118,
						CreatedAt: 0,
						UpdatedAt: 0,
						Flags: AddrPortStatsFlags{
							TcpStateClosing:   false,
							TcpStateEstablish: true,
						},
					},
				},
			},
		},
		NatRetRender: NatRetRender{
			Items: []NatRetRenderItem{
				{
					Key: StructAddrPortRender{
						Addr:  "142.0.0.1",
						Port:  0x0067,
						Proto: 6,
					},
					Val: StructAddrPortStatsRender{
						Addr:      "10.0.1.10",
						Port:      4135,
						Proto:     6,
						Pkts:      1,
						Bytes:     118,
						CreatedAt: 0,
						UpdatedAt: 0,
						Flags: AddrPortStatsFlags{
							TcpStateClosing:   false,
							TcpStateEstablish: true,
						},
					},
				},
			},
		},
	}
	return &c
}

func (tc EndMfnNormalTcpCloseRstTestCase) PostTestMapContextPreprocess(mc *ProgRunMapContext) {
	mc.LbBackendRender = LbBackendRender{}
	mc.EncapSourceRender = EncapSourceRender{}
	mc.Fib4Render = Fib4Render{}
	mc.Fib6Render = Fib6Render{}
	mc.NeighRender = NeighRender{}
	mc.OverlayFib4Render = OverlayFib4Render{}
	for i := 0; i < len(mc.NatOutRender.Items); i++ {
		mc.NatOutRender.Items[i].Val.UpdatedAt = 0
	}
	for i := 0; i < len(mc.NatRetRender.Items); i++ {
		mc.NatRetRender.Items[i].Val.UpdatedAt = 0
	}
	return
}

func (tc EndMfnNormalTcpCloseRstTestCase) PostTestMapContextExpect() *ProgRunMapContext {
	c := ProgRunMapContext{
		NatOutRender: NatOutRender{
			Items: []NatOutRenderItem{
				{
					Key: StructAddrPortRender{
						Addr:  "10.0.1.10",
						Port:  4135,
						Proto: 6,
					},
					Val: StructAddrPortStatsRender{
						Addr:      "142.0.0.1",
						Port:      0x0067,
						Proto:     6,
						Pkts:      1,
						Bytes:     118,
						CreatedAt: 0,
						UpdatedAt: 0,
						Flags: AddrPortStatsFlags{
							TcpStateClosing:   true,
							TcpStateEstablish: true,
						},
					},
				},
			},
		},
		NatRetRender: NatRetRender{
			Items: []NatRetRenderItem{
				{
					Key: StructAddrPortRender{
						Addr:  "142.0.0.1",
						Port:  0x0067,
						Proto: 6,
					},
					Val: StructAddrPortStatsRender{
						Addr:      "10.0.1.10",
						Port:      4135,
						Proto:     6,
						Pkts:      2,
						Bytes:     236,
						CreatedAt: 0,
						UpdatedAt: 0,
						Flags: AddrPortStatsFlags{
							TcpStateClosing:   true,
							TcpStateEstablish: true,
						},
					},
				},
			},
		},
	}
	return &c
}

func TestEndMfnNormalTcpCloseRstTestCase(t *testing.T) {
	ExecuteTestCase(EndMfnNormalTcpCloseRstTestCase{}, t)
}
