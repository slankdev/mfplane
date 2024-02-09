package ebpf

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/slankdev/mfplane/pkg/util"
)

type EndMfnNormalTcpOpenValidTestCase struct{}

func (tc EndMfnNormalTcpOpenValidTestCase) ProgInfo() (string, []string) {
	return "common_main.c", []string{
		"DEBUG_FUNCTION_CALL",
		"DEBUG_MF_REDIRECT",
	}
}

func (tc EndMfnNormalTcpOpenValidTestCase) GenerateInput() ([]byte, error) {
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
		Protocol: layers.IPProtocolTCP,
	}

	// TCP
	tcpLayer := &layers.TCP{
		SrcPort: 10000,
		DstPort: 443,
		SYN:     true,
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

func (tc EndMfnNormalTcpOpenValidTestCase) GenerateOutput() (int, []byte, error) {
	// Ethernet
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       util.MustParseMAC("52:54:00:00:00:02"),
		DstMAC:       util.MustParseMAC("52:54:00:11:00:01"),
		EthernetType: layers.EthernetTypeIPv4,
	}

	// IPv4
	ipv4Layer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.ParseIP("142.0.0.1"),
		DstIP:    net.ParseIP("20.0.0.1"),
		Protocol: layers.IPProtocolTCP,
	}

	// TCP
	tcpLayer := &layers.TCP{
		SrcPort: 0x6700,
		DstPort: 443,
		SYN:     true,
	}
	if err := tcpLayer.SetNetworkLayerForChecksum(ipv4Layer); err != nil {
		return 0, nil, err
	}

	// Craft
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ethernetLayer,
		ipv4Layer,
		tcpLayer,
	); err != nil {
		return 0, nil, err
	}

	return XDP_TX, buf.Bytes(), nil
}

func (tc EndMfnNormalTcpOpenValidTestCase) OutputPostProcess(b []byte) ([]byte, error) {
	pkt := gopacket.NewPacket(b, layers.LayerTypeEthernet, gopacket.Default)

	// Check IPv4
	tmplayer := pkt.Layers()[1]
	ipv4Layer, ok := tmplayer.(*layers.IPv4)
	if !ok {
		return nil, fmt.Errorf("Not ipv4 (%s)", tmplayer.LayerType().String())
	}

	// Check TCP
	tmplayer = pkt.Layers()[2]
	tcpLayer, ok := tmplayer.(*layers.TCP)
	if !ok {
		return nil, fmt.Errorf("Not tcp (%s)", tmplayer.LayerType().String())
	}
	tcpLayer.SrcPort = layers.TCPPort(uint16(tcpLayer.SrcPort) & 0xff00)
	if err := tcpLayer.SetNetworkLayerForChecksum(ipv4Layer); err != nil {
		return nil, err
	}
	pkt.Layers()[2] = tcpLayer

	// Re-crafting
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializePacket(buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		pkt); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (tc EndMfnNormalTcpOpenValidTestCase) PreTestMapContext() *ProgRunMapContext {
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
							Vip:                []string{"142.0.0.1"},
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
	}
	return &c
}

func (tc EndMfnNormalTcpOpenValidTestCase) PostTestMapContextPreprocess(mc *ProgRunMapContext) {
	mc.CounterRender = CounterRender{}
	mc.Fib4Render = Fib4Render{}
	mc.Fib6Render = Fib6Render{}
	mc.NeighRender = NeighRender{}
	mc.LbBackendRender = LbBackendRender{}
	mc.EncapSourceRender = EncapSourceRender{}
	mc.OverlayFib4Render = OverlayFib4Render{}
	for i := 0; i < len(mc.NatOutRender.Items); i++ {
		mc.NatOutRender.Items[i].Val.CreatedAt = 0
		mc.NatOutRender.Items[i].Val.UpdatedAt = 0
		mc.NatOutRender.Items[i].Val.Port = mc.NatOutRender.Items[i].Val.Port & 0x00ff // mf-nat
	}
	for i := 0; i < len(mc.NatRetRender.Items); i++ {
		mc.NatRetRender.Items[i].Val.CreatedAt = 0
		mc.NatRetRender.Items[i].Val.UpdatedAt = 0
		mc.NatRetRender.Items[i].Key.Port = mc.NatRetRender.Items[i].Key.Port & 0x00ff // mf-nat
	}
}

func (tc EndMfnNormalTcpOpenValidTestCase) PostTestMapContextExpect() *ProgRunMapContext {
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
							TcpStateEstablish: false,
						},
					},
				},
			},
		},
	}
	return &c
}

func (tc EndMfnNormalTcpOpenValidTestCase) PostTestEventPreprocess(events []GenericEvent) []GenericEvent {
	for idx := range events {
		events[idx].Timestamp = time.Time{}
		if events[idx].EventNatSessionCreate != nil {
			events[idx].EventNatSessionCreate.NatPort &= 0xff00
		}
	}
	return ExcludeEventFunctionCall(events)
}

func (tc EndMfnNormalTcpOpenValidTestCase) PostTestEventsExpect() []GenericEvent {
	return []GenericEvent{
		{EventNatSessionCreate: &EventBodyNatSessionRender{
			OrgSrc:  "10.0.1.10",
			OrgPort: 10000,
			NatSrc:  "142.0.0.1",
			NatPort: 26548 & 0xff00,
			Proto:   "tcp",
			Flags:   0,
		}},
	}
}

func TestEndMfnNormalTcpOpenValidTestCase(t *testing.T) {
	ExecuteTestCase(EndMfnNormalTcpOpenValidTestCase{}, t)
}
