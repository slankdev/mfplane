package ebpf

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/slankdev/mfplane/pkg/util"
)

type EndMfnNormalTcpOpenInvalidTestCase struct{}

func (tc EndMfnNormalTcpOpenInvalidTestCase) ProgInfo() (string, []string) {
	return "common_main.c", []string{
		"DEBUG_FUNCTION_CALL",
		"DEBUG_MF_REDIRECT",
		"DEBUG_PARSE_METADATA",
	}
}

func (tc EndMfnNormalTcpOpenInvalidTestCase) GenerateInput() ([]byte, error) {
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
		ACK:     true,
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

func (tc EndMfnNormalTcpOpenInvalidTestCase) GenerateOutput() (int, []byte, error) {
	return XDP_DROP, nil, nil
}

func (tc EndMfnNormalTcpOpenInvalidTestCase) OutputPostProcess(b []byte) ([]byte, error) {
	return nil, nil
}

func (tc EndMfnNormalTcpOpenInvalidTestCase) PreTestMapContext() *ProgRunMapContext {
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
	}
	return &c
}

func (tc EndMfnNormalTcpOpenInvalidTestCase) PostTestMapContextPreprocess(mc *ProgRunMapContext) {
	mc.CounterRender = CounterRender{}
	mc.Fib4Render = Fib4Render{}
	mc.Fib6Render = Fib6Render{}
	mc.NeighRender = NeighRender{}
	mc.NatOutRender = NatOutRender{}
	mc.NatRetRender = NatRetRender{}
	mc.LbBackendRender = LbBackendRender{}
	mc.EncapSourceRender = EncapSourceRender{}
	mc.OverlayFib4Render = OverlayFib4Render{}
}

func (tc EndMfnNormalTcpOpenInvalidTestCase) PostTestMapContextExpect() *ProgRunMapContext {
	c := ProgRunMapContext{}
	return &c
}

func TestEndMfnNormalTcpOpenInvalidTestCase(t *testing.T) {
	ExecuteTestCase(EndMfnNormalTcpOpenInvalidTestCase{}, t)
}
