/*
Copyright 2024 Hiroki Shirokura.
Copyright 2024 Kyoto University.

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

package ebpf

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"

	"github.com/slankdev/mfplane/pkg/util"
)

type EventHeader struct {
	Type   uint16
	Length uint16
}

type EventBodyFunctionCall struct {
	FuncNameIdx  uint16
	FuncCallLine uint16
}

type EventBodyFunctionCallRender struct {
	FuncNameIdx  string
	FuncCallLine uint16
}

func (raw *EventBodyFunctionCall) ToRender() (*EventBodyFunctionCallRender, error) {
	render := EventBodyFunctionCallRender{}
	render.FuncNameIdx = funcidxString[raw.FuncNameIdx]
	render.FuncCallLine = raw.FuncCallLine
	return &render, nil
}

type EventBodyNatSession struct {
	OrgSrc  uint32
	OrgPort uint16
	NatSrc  uint32
	NatPort uint16
	Proto   uint8
	Flags   uint8
}

const (
	FUNCTION_NAME_unspec = iota
	FUNCTION_NAME_ignore_packet
	FUNCTION_NAME_error_packet
	FUNCTION_NAME_tx_packet
	FUNCTION_NAME_tx_packet_neigh
	FUNCTION_NAME_parse_metadata
	FUNCTION_NAME_process_nat_return
	FUNCTION_NAME_process_ipv4
	FUNCTION_NAME_process_mf_redirect
	FUNCTION_NAME_process_nat_ret
	FUNCTION_NAME_process_nat_out
	FUNCTION_NAME_process_srv6_end_mfn_nat
	FUNCTION_NAME_process_srv6_end_mfl_nat
	FUNCTION_NAME_process_ipv6
	FUNCTION_NAME_process_ethernet
)

var funcidxString = map[uint16]string{
	FUNCTION_NAME_ignore_packet:            "ignore_packet",
	FUNCTION_NAME_error_packet:             "error_packet",
	FUNCTION_NAME_tx_packet:                "tx_packet",
	FUNCTION_NAME_tx_packet_neigh:          "tx_packet_neigh",
	FUNCTION_NAME_parse_metadata:           "parse_metadata",
	FUNCTION_NAME_process_nat_return:       "process_nat_return",
	FUNCTION_NAME_process_ipv4:             "process_ipv4",
	FUNCTION_NAME_process_mf_redirect:      "process_mf_redirect",
	FUNCTION_NAME_process_nat_ret:          "process_nat_ret",
	FUNCTION_NAME_process_nat_out:          "process_nat_out",
	FUNCTION_NAME_process_srv6_end_mfn_nat: "process_srv6_end_mfn_nat",
	FUNCTION_NAME_process_srv6_end_mfl_nat: "process_srv6_end_mfl_nat",
	FUNCTION_NAME_process_ipv6:             "process_ipv6",
	FUNCTION_NAME_process_ethernet:         "process_ethernet",
}

var ipprotoString = map[uint8]string{
	0x01: "icmp",
	0x06: "tcp",
	0x11: "udp",
}

type EventBodyNatSessionRender struct {
	OrgSrc  string
	OrgPort uint16
	NatSrc  string
	NatPort uint16
	Proto   string
	Flags   uint8
}

type EventBodyRender interface {
}

var (
	_ EventBodyRender = &EventBodyFunctionCallRender{}
	_ EventBodyRender = &EventBodyNatSessionRender{}
)

func (raw *EventBodyNatSession) ToRender() (*EventBodyNatSessionRender, error) {
	render := EventBodyNatSessionRender{}
	render.OrgPort = raw.OrgPort
	render.NatPort = raw.NatPort
	render.Proto = fmt.Sprintf("unknown(%d)", raw.Proto)
	if s, ok := ipprotoString[raw.Proto]; ok {
		render.Proto = s
	}
	render.OrgSrc = util.ConvertUint32ToIPBe(raw.OrgSrc).String()
	render.NatSrc = util.ConvertUint32ToIPBe(raw.NatSrc).String()
	return &render, nil
}

type PrintPerfEventOptions struct {
	PrintCPU         bool
	PrintLostSamples bool
	PrintHeader      bool
	FilterIn         []string
	FilterOut        []string
}

const (
	EVENT_TYPE_UNSPEC = iota
	EVENT_TYPE_DEBUG
	EVENT_TYPE_NAT_SESSION_CREATE
	EVENT_TYPE_NAT_SESSION_DELETE_BY_RST
	EVENT_TYPE_FUNCTION_CALL
	EVENT_TYPE_NAT_CONFLICT
	EVENT_TYPE_IPV6_LOOKUP
	EVENT_TYPE_PARSE_METADATA
	EVENT_TYPE_JHASH_RESULT
	EVENT_TYPE_MF_REDIRECT
	EVENT_TYPE_PACKET_RECORD
)

var stringType = map[uint16]string{
	EVENT_TYPE_UNSPEC:                    "EVENT_TYPE_UNSPE",
	EVENT_TYPE_DEBUG:                     "EVENT_TYPE_DEBUG",
	EVENT_TYPE_NAT_SESSION_CREATE:        "EVENT_TYPE_NAT_SESSION_CREATE",
	EVENT_TYPE_NAT_SESSION_DELETE_BY_RST: "EVENT_TYPE_NAT_SESSION_DELETE_BY_RST",
	EVENT_TYPE_FUNCTION_CALL:             "EVENT_TYPE_FUNCTION_CALL",
	EVENT_TYPE_NAT_CONFLICT:              "EVENT_TYPE_NAT_CONFLICT",
	EVENT_TYPE_IPV6_LOOKUP:               "EVENT_TYPE_IPV6_LOOKUP",
	EVENT_TYPE_PARSE_METADATA:            "EVENT_TYPE_PARSE_METADATA",
	EVENT_TYPE_JHASH_RESULT:              "EVENT_TYPE_JHASH_RESULT",
	EVENT_TYPE_MF_REDIRECT:               "EVENT_TYPE_MF_REDIRECT",
	EVENT_TYPE_PACKET_RECORD:             "EVENT_TYPE_PACKET_RECORD",
}

type EventBodyNatConflict struct {
	OrgSrc  uint32
	OrgPort uint16
	Proto   uint8
}

type EventBodyNatConflictRender struct {
	OrgSrc  string
	OrgPort uint16
	Proto   string
}

func (raw *EventBodyNatConflict) ToRender() (*EventBodyNatConflictRender, error) {
	render := EventBodyNatConflictRender{}
	render.OrgSrc = util.ConvertUint32ToIPBe(raw.OrgSrc).String()
	render.OrgPort = raw.OrgPort
	render.Proto = fmt.Sprintf("unknown(%d)", raw.Proto)
	if s, ok := ipprotoString[raw.Proto]; ok {
		render.Proto = s
	}
	return &render, nil
}

type EventBodyIPv6Lookup struct {
	Addr [16]uint8
}

type EventBodyIPv6LookupRender struct {
	Addr string
}

func (raw *EventBodyIPv6Lookup) ToRender() (*EventBodyIPv6LookupRender, error) {
	render := EventBodyIPv6LookupRender{}
	render.Addr = net.IP(raw.Addr[:]).String()
	return &render, nil
}

type EventBodyParseMetadata struct {
	Result int32
}

type EventBodyParseMetadataResult struct {
	Result int32
}

func (raw *EventBodyParseMetadata) ToRender() (*EventBodyParseMetadataResult, error) {
	render := EventBodyParseMetadataResult{}
	render.Result = raw.Result
	return &render, nil
}

type EventBodyJhashResult struct {
	Hash uint32
}

type EventBodyJhashResultResult struct {
	Hash uint32
}

func (raw *EventBodyJhashResult) ToRender() (*EventBodyJhashResultResult, error) {
	render := EventBodyJhashResultResult{}
	render.Hash = raw.Hash
	return &render, nil
}

type EventBodyMfRedirectResult struct {
	UpdatedAddr [16]uint8
}

type EventBodyMfRedirectResultRender struct {
	UpdatedAddr string
}

func (raw *EventBodyMfRedirectResult) ToRender() (*EventBodyMfRedirectResultRender, error) {
	render := EventBodyMfRedirectResultRender{}
	render.UpdatedAddr = net.IP(raw.UpdatedAddr[:]).String()
	return &render, nil
}

type EventBodyPacketRecord struct {
	SrcAddr   uint32
	DstAddr   uint32
	SrcPort   uint16
	DstPort   uint16
	Proto     uint8
	Metatada1 uint8
	Metatada2 uint8
	Metatada3 uint8
}

type EventBodyPacketRecordRender struct {
	SrcAddr   string
	DstAddr   string
	SrcPort   uint16
	DstPort   uint16
	Proto     string
	Metatada1 uint8
	Metatada2 uint8
	Metatada3 uint8
}

func (raw *EventBodyPacketRecord) ToRender() (*EventBodyPacketRecordRender, error) {
	render := EventBodyPacketRecordRender{}
	render.SrcAddr = util.ConvertUint32ToIPBe(raw.SrcAddr).String()
	render.DstAddr = util.ConvertUint32ToIPBe(raw.DstAddr).String()
	render.SrcPort = raw.SrcPort
	render.DstPort = raw.DstPort
	render.DstPort = raw.DstPort
	render.Proto = fmt.Sprintf("unknown(%d)", raw.Proto)
	if s, ok := ipprotoString[raw.Proto]; ok {
		render.Proto = s
	}
	render.Metatada1 = raw.Metatada1
	render.Metatada2 = raw.Metatada2
	render.Metatada3 = raw.Metatada3
	return &render, nil
}

func check(str string, choices []string) bool {
	for _, choice := range choices {
		if str == choice {
			return true
		}
	}
	return false
}

func writeRawPerfEvent(record perf.Record, f *os.File) error {
	var buf bytes.Buffer
	var length uint16 = uint16(len(record.RawSample))
	var lostSamples uint64 = record.LostSamples
	if err := binary.Write(&buf, binary.BigEndian, length); err != nil {
		return err
	}
	if err := binary.Write(&buf, binary.BigEndian, lostSamples); err != nil {
		return err
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		return err
	}
	if _, err := f.Write(record.RawSample); err != nil {
		return err
	}
	return nil
}

type EventBodyUnknownRender struct {
	Type uint16
	Raw  []byte
}

type GenericEvent struct {
	Timestamp                  time.Time
	EventBodyUnknown           *EventBodyUnknownRender
	EventBodyFunctionCall      *EventBodyFunctionCallRender
	EventNatSessionCreate      *EventBodyNatSessionRender
	EventNatSessionDeleteByRst *EventBodyNatSessionRender
	EventBodyNatConflict       *EventBodyNatConflictRender
	EventBodyIPv6Lookup        *EventBodyIPv6LookupRender
	EventBodyParseMetadata     *EventBodyParseMetadataResult
	EventBodyJhashResult       *EventBodyJhashResultResult
	EventBodyMfRedirectResult  *EventBodyMfRedirectResultRender
	EventBodyPacketRecord      *EventBodyPacketRecordRender
}

func ParseEvent(record perf.Record) (*GenericEvent, error) {
	buf := bytes.NewBuffer(record.RawSample)
	h := EventHeader{}
	binary.Read(buf, binary.LittleEndian, &h)

	ts, err := util.KtimeNanoSecToTime(record.Timestamp)
	if err != nil {
		return nil, err
	}

	ev := GenericEvent{}
	ev.Timestamp = ts
	switch h.Type {
	case EVENT_TYPE_NAT_SESSION_CREATE:
		b := EventBodyNatSession{}
		binary.Read(buf, binary.BigEndian, &b)
		br, err := b.ToRender()
		if err != nil {
			return nil, err
		}
		ev.EventNatSessionCreate = br
	case EVENT_TYPE_NAT_SESSION_DELETE_BY_RST:
		b := EventBodyNatSession{}
		binary.Read(buf, binary.BigEndian, &b)
		br, err := b.ToRender()
		if err != nil {
			return nil, err
		}
		ev.EventNatSessionDeleteByRst = br
	case EVENT_TYPE_FUNCTION_CALL:
		b := EventBodyFunctionCall{}
		binary.Read(buf, binary.LittleEndian, &b)
		br, err := b.ToRender()
		if err != nil {
			return nil, err
		}
		ev.EventBodyFunctionCall = br
	case EVENT_TYPE_NAT_CONFLICT:
		b := EventBodyNatConflict{}
		binary.Read(buf, binary.BigEndian, &b)
		br, err := b.ToRender()
		if err != nil {
			return nil, err
		}
		ev.EventBodyNatConflict = br
	case EVENT_TYPE_IPV6_LOOKUP:
		b := EventBodyIPv6Lookup{}
		binary.Read(buf, binary.BigEndian, &b)
		br, err := b.ToRender()
		if err != nil {
			return nil, err
		}
		ev.EventBodyIPv6Lookup = br
	case EVENT_TYPE_PARSE_METADATA:
		b := EventBodyParseMetadata{}
		binary.Read(buf, binary.BigEndian, &b)
		br, err := b.ToRender()
		if err != nil {
			return nil, err
		}
		ev.EventBodyParseMetadata = br
	case EVENT_TYPE_JHASH_RESULT:
		b := EventBodyJhashResult{}
		binary.Read(buf, binary.BigEndian, &b)
		br, err := b.ToRender()
		if err != nil {
			return nil, err
		}
		ev.EventBodyJhashResult = br
	case EVENT_TYPE_MF_REDIRECT:
		b := EventBodyMfRedirectResult{}
		binary.Read(buf, binary.BigEndian, &b)
		br, err := b.ToRender()
		if err != nil {
			return nil, err
		}
		ev.EventBodyMfRedirectResult = br
	case EVENT_TYPE_PACKET_RECORD:
		b := EventBodyPacketRecord{}
		binary.Read(buf, binary.BigEndian, &b)
		br, err := b.ToRender()
		if err != nil {
			return nil, err
		}
		ev.EventBodyPacketRecord = br
	default:
		ev.EventBodyUnknown = &EventBodyUnknownRender{
			Type: h.Type,
			Raw:  record.RawSample,
		}
	}
	return &ev, nil
}

func NewEventReader(mapName string, bufSize int) (*perf.Reader, error) {
	m, err := ebpf.LoadPinnedMap(mapName, nil)
	if err != nil {
		return nil, err
	}
	reader, err := perf.NewReader(m, bufSize)
	if err != nil {
		return nil, err
	}
	return reader, nil
}

type JsonOutputMetadata struct {
	Type        uint16
	TypeString  string
	Length      uint16
	LostSamples uint64
	Cpu         int
}

type JsonOutput struct {
	Metadata JsonOutputMetadata
	Body     GenericEvent
}

func printPerfEvent(record perf.Record, opts *PrintPerfEventOptions, out *os.File) error {
	// Craft Buffer
	buf := bytes.NewBuffer(record.RawSample)
	h := EventHeader{}
	binary.Read(buf, binary.LittleEndian, &h)

	// Filter IN/OUT
	proceed := true
	if opts != nil {
		if len(opts.FilterIn) > 0 {
			proceed = false
			for _, f := range opts.FilterIn {
				if f == stringType[h.Type] {
					proceed = true
					break
				}
			}
		}
		if len(opts.FilterOut) > 0 {
			for _, f := range opts.FilterOut {
				if f == stringType[h.Type] {
					proceed = false
					break
				}
			}
		}
	}
	if !proceed {
		return nil
	}

	// Parse Events
	ev, err := ParseEvent(record)
	if err != nil {
		return err
	}

	// TODO(slankdev): abstraction for each RenderTypes
	// if bodyHasImplementedInterface {
	// 	fields = append(fields, zap.String("message", b.Message())
	// }

	// Output Json data
	b, err := json.Marshal(JsonOutput{
		Metadata: JsonOutputMetadata{
			Type:        h.Type,
			TypeString:  stringType[h.Type],
			Length:      h.Length,
			Cpu:         record.CPU,
			LostSamples: record.LostSamples,
		},
		Body: *ev,
	})
	if err != nil {
		return err
	}
	fmt.Fprintln(out, string(b))
	return nil
}
