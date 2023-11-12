package ebpf

import (
	"fmt"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/slankdev/mfplane/pkg/util"
)

type EndMfnNormalTestCase struct{}

func (tc EndMfnNormalTestCase) GenerateInput() ([]byte, error) {
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

func (tc EndMfnNormalTestCase) GenerateOutput() (int, []byte, error) {
	// Ethernet
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       util.MustParseMAC("52:54:00:00:00:02"),
		DstMAC:       util.MustParseMAC("52:54:00:00:00:01"),
		EthernetType: layers.EthernetTypeIPv4,
	}

	// IPv4
	ipv4Layer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.ParseIP("142.0.0.1"),
		DstIP:    net.ParseIP("20.0.0.1"),
		Protocol: layers.IPProtocolUDP,
	}

	// UDP
	udpLayer := &layers.UDP{
		SrcPort: 0x7c00,
		DstPort: 443,
	}
	if err := udpLayer.SetNetworkLayerForChecksum(ipv4Layer); err != nil {
		return 0, nil, err
	}

	// Craft
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ethernetLayer,
		ipv4Layer,
		udpLayer,
		gopacket.Payload([]byte("Hello, MF-Plane!")),
	); err != nil {
		return 0, nil, err
	}

	return XDP_TX, buf.Bytes(), nil
}

func (tc EndMfnNormalTestCase) OutputPostProcess(b []byte) ([]byte, error) {
	pkt := gopacket.NewPacket(b, layers.LayerTypeEthernet, gopacket.Default)

	// Check IPv4
	tmplayer := pkt.Layers()[1]
	ipv4Layer, ok := tmplayer.(*layers.IPv4)
	if !ok {
		return nil, fmt.Errorf("Not ipv4 (%s)", tmplayer.LayerType().String())
	}

	// Check UDP
	tmplayer = pkt.Layers()[2]
	udpLayer, ok := tmplayer.(*layers.UDP)
	if !ok {
		return nil, fmt.Errorf("Not udp (%s)", tmplayer.LayerType().String())
	}
	udpLayer.SrcPort = layers.UDPPort(uint16(udpLayer.SrcPort) & 0xff00)
	if err := udpLayer.SetNetworkLayerForChecksum(ipv4Layer); err != nil {
		return nil, err
	}
	pkt.Layers()[2] = udpLayer

	// Re-crafting
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializePacket(buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		pkt); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (tc EndMfnNormalTestCase) PreTestMapContext() *MapContext {
	c := MapContext{
		Fib6: Fib6Render{
			Items: []Fib6RenderItem{
				{
					Key: StructTrie6KeyRender{
						Prefix: "fc00:3100::/32",
					},
					Val: StructTrie6ValRender{
						Action:             456,
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
		},
	}
	return &c
}

func (tc EndMfnNormalTestCase) PostTestMapContextPreprocess(mc *MapContext) {
	mc.Fib6 = Fib6Render{}
	mc.LbBackend = LbBackendRender{}
	for i := 0; i < len(mc.NatOut.Items); i++ {
		mc.NatOut.Items[i].Val.CreatedAt = 0
		mc.NatOut.Items[i].Val.UpdatedAt = 0
		mc.NatOut.Items[i].Val.Port = mc.NatOut.Items[i].Val.Port & 0x00ff // mf-nat
	}
	for i := 0; i < len(mc.NatRet.Items); i++ {
		mc.NatRet.Items[i].Val.CreatedAt = 0
		mc.NatRet.Items[i].Val.UpdatedAt = 0
		mc.NatRet.Items[i].Key.Port = mc.NatRet.Items[i].Key.Port & 0x00ff // mf-nat
	}

	return
}

func (tc EndMfnNormalTestCase) PostTestMapContextExpect() *MapContext {
	c := MapContext{
		Fib6:        Fib6Render{},
		OverlayFib4: OverlayFib4Render{Items: []OverlayFib4RenderItem{}},
		NatOut: NatOutRender{
			Items: []NatOutRenderItem{
				{
					Key: StructAddrPortRender{
						Addr:  "10.0.1.10",
						Port:  4135,
						Proto: 17,
					},
					Val: StructAddrPortStatsRender{
						Addr:      "142.0.0.1",
						Port:      0x007c,
						Proto:     17,
						Pkts:      1,
						Bytes:     122,
						CreatedAt: 0,
						UpdatedAt: 0,
					},
				},
			},
		},
		NatRet: NatRetRender{
			Items: []NatRetRenderItem{
				{
					Key: StructAddrPortRender{
						Addr:  "142.0.0.1",
						Port:  0x007c,
						Proto: 17,
					},
					Val: StructAddrPortStatsRender{
						Addr:      "10.0.1.10",
						Port:      4135,
						Proto:     17,
						Pkts:      1,
						Bytes:     122,
						CreatedAt: 0,
						UpdatedAt: 0,
					},
				},
			},
		},
	}
	return &c
}

func TestEndMfnNormalTestCase(t *testing.T) {
	ExecuteTestCase(EndMfnNormalTestCase{}, t)
}
