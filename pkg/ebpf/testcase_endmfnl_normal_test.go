package ebpf

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/slankdev/mfplane/pkg/util"
)

type EndMflNormalTestCase struct{}

func (tc EndMflNormalTestCase) GenerateInput() ([]byte, error) {
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
		DstIP:      net.ParseIP("fc00:ff01::"),
	}

	// SRH
	segmentList := []net.IP{
		net.ParseIP("fc00:ff01::"),
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

func (tc EndMflNormalTestCase) GenerateOutput() (int, []byte, error) {
	// Ethernet
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       util.MustParseMAC("52:54:00:00:00:02"),
		DstMAC:       util.MustParseMAC("52:54:00:00:00:01"),
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
		net.ParseIP("fc00:3100::"), // I don't care this pkt update...
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
		udpLayer,
		gopacket.Payload([]byte("Hello, MF-Plane!")),
	); err != nil {
		return 0, nil, err
	}

	return XDP_TX, buf.Bytes(), nil
}

func (tc EndMflNormalTestCase) OutputPostProcess(b []byte) ([]byte, error) {
	return b, nil
}

func (tc EndMflNormalTestCase) PreTestMapContext() *MapContext {
	c := MapContext{
		Fib6: Fib6Render{
			Items: []Fib6RenderItem{
				{
					Key: StructTrie6KeyRender{
						Prefix: "fc00:ff01::/32",
					},
					Val: StructTrie6ValRender{
						Action:             123,
						BackendBlockIndex:  0,
						Vip:                "142.0.0.1",
						NatPortHashBit:     0x00ff,
						UsidBlockLength:    16,
						UsidFunctionLength: 16,
						NatMapping:         0,
						NatFiltering:       0,
						Sources: []StructTrie6ValRenderSnatSource{
							{Prefix: "10.0.1.0/24"},
						},
						StatsTotalPkts:  0,
						StatsTotalBytes: 0,
					},
				},
			},
		},
		NatOut: NatOutRender{},
		NatRet: NatRetRender{},
		LbBackend: LbBackendRender{
			Items: []LbBackendRenderItem{
				{Key: StructArrayKey32Render{Index: 0}, Val: StructFlowProcessorRender{Addr: "fc00:3100::"}},
				{Key: StructArrayKey32Render{Index: 1}, Val: StructFlowProcessorRender{Addr: "fc00:3100::"}},
				{Key: StructArrayKey32Render{Index: 2}, Val: StructFlowProcessorRender{Addr: "fc00:3100::"}},
				{Key: StructArrayKey32Render{Index: 3}, Val: StructFlowProcessorRender{Addr: "fc00:3100::"}},
				{Key: StructArrayKey32Render{Index: 4}, Val: StructFlowProcessorRender{Addr: "fc00:3100::"}},
				{Key: StructArrayKey32Render{Index: 5}, Val: StructFlowProcessorRender{Addr: "fc00:3100::"}},
				{Key: StructArrayKey32Render{Index: 6}, Val: StructFlowProcessorRender{Addr: "fc00:3100::"}},
				{Key: StructArrayKey32Render{Index: 7}, Val: StructFlowProcessorRender{Addr: "::"}},
				{Key: StructArrayKey32Render{Index: 8}, Val: StructFlowProcessorRender{Addr: "::"}},
				{Key: StructArrayKey32Render{Index: 9}, Val: StructFlowProcessorRender{Addr: "::"}},
				{Key: StructArrayKey32Render{Index: 10}, Val: StructFlowProcessorRender{Addr: "::"}},
				{Key: StructArrayKey32Render{Index: 11}, Val: StructFlowProcessorRender{Addr: "::"}},
				{Key: StructArrayKey32Render{Index: 12}, Val: StructFlowProcessorRender{Addr: "::"}},
				{Key: StructArrayKey32Render{Index: 13}, Val: StructFlowProcessorRender{Addr: "::"}},
			},
		},
	}
	return &c
}

func (tc EndMflNormalTestCase) PostTestMapContextPreprocess(mc *MapContext) {}

func (tc EndMflNormalTestCase) PostTestMapContextExpect() *MapContext {
	c := MapContext{
		Fib6: Fib6Render{
			Items: []Fib6RenderItem{
				{
					Key: StructTrie6KeyRender{
						Prefix: "fc00:ff01::/32",
					},
					Val: StructTrie6ValRender{
						Action:             123,
						BackendBlockIndex:  0,
						Vip:                "142.0.0.1",
						NatPortHashBit:     0x00ff,
						UsidBlockLength:    16,
						UsidFunctionLength: 16,
						NatMapping:         0,
						NatFiltering:       0,
						Sources: []StructTrie6ValRenderSnatSource{
							{Prefix: "10.0.1.0/24"},
						},
						StatsTotalPkts:  1,
						StatsTotalBytes: 122,
					},
				},
			},
		},
		NatOut:      NatOutRender{Items: []NatOutRenderItem{}},
		NatRet:      NatRetRender{Items: []NatRetRenderItem{}},
		OverlayFib4: OverlayFib4Render{Items: []OverlayFib4RenderItem{}},
		LbBackend: LbBackendRender{
			Items: []LbBackendRenderItem{
				{Key: StructArrayKey32Render{Index: 0}, Val: StructFlowProcessorRender{Addr: "fc00:3100::"}},
				{Key: StructArrayKey32Render{Index: 1}, Val: StructFlowProcessorRender{Addr: "fc00:3100::"}},
				{Key: StructArrayKey32Render{Index: 2}, Val: StructFlowProcessorRender{Addr: "fc00:3100::"}},
				{Key: StructArrayKey32Render{Index: 3}, Val: StructFlowProcessorRender{Addr: "fc00:3100::"}},
				{Key: StructArrayKey32Render{Index: 4}, Val: StructFlowProcessorRender{Addr: "fc00:3100::"}},
				{Key: StructArrayKey32Render{Index: 5}, Val: StructFlowProcessorRender{Addr: "fc00:3100::"}},
				{Key: StructArrayKey32Render{Index: 6}, Val: StructFlowProcessorRender{Addr: "fc00:3100::"}},
				{Key: StructArrayKey32Render{Index: 7}, Val: StructFlowProcessorRender{Addr: "::"}},
				{Key: StructArrayKey32Render{Index: 8}, Val: StructFlowProcessorRender{Addr: "::"}},
				{Key: StructArrayKey32Render{Index: 9}, Val: StructFlowProcessorRender{Addr: "::"}},
				{Key: StructArrayKey32Render{Index: 10}, Val: StructFlowProcessorRender{Addr: "::"}},
				{Key: StructArrayKey32Render{Index: 11}, Val: StructFlowProcessorRender{Addr: "::"}},
				{Key: StructArrayKey32Render{Index: 12}, Val: StructFlowProcessorRender{Addr: "::"}},
				{Key: StructArrayKey32Render{Index: 13}, Val: StructFlowProcessorRender{Addr: "::"}},
			},
		},
	}
	return &c
}

func TestEndMflNormalTestCase(t *testing.T) {
	ExecuteTestCase(EndMflNormalTestCase{}, t)
}
