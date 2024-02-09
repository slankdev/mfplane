package ebpf

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/google/go-cmp/cmp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/k0kubun/pp"
	"github.com/pkg/errors"
	"github.com/slankdev/mfplane/pkg/util"
	"go.uber.org/zap"
)

const (
	XDP_ABORTED  = 0
	XDP_DROP     = 1
	XDP_PASS     = 2
	XDP_TX       = 3
	XDP_REDIRECT = 4
)

type TestCase interface {
	ProgInfo() (string, []string)
	GenerateInput() ([]byte, error)
	GenerateOutput() (int, []byte, error)
	OutputPostProcess(b []byte) ([]byte, error)
	PreTestMapContext() *ProgRunMapContext
	PostTestMapContextPreprocess(mc *ProgRunMapContext)
	PostTestMapContextExpect() *ProgRunMapContext
}

type TestCaseWithEvent interface {
	PostTestEventsExpect() []GenericEvent
	PostTestEventPreprocess(events []GenericEvent) []GenericEvent
}

func unlinkAll(rootdir string) error {
	files, err := os.ReadDir(rootdir)
	if err != nil {
		return err
	}

	// Filter map files
	toBeDeleted := []string{}
	for _, file := range files {
		if !file.IsDir() {
			// NOTE(slankdev):
			// When the event map is re-created, all processes that watch the
			// existing perf event become zombies, even if they are on the same path.
			// It is not a neat solution, but we exclude this map from cleanup so
			// that we can continue to watch perf events while running go test.
			if strings.HasSuffix(file.Name(), "_events") {
				continue
			}
			toBeDeleted = append(toBeDeleted, file.Name())
		}
	}

	// Delete files
	for _, name := range toBeDeleted {
		fullpath := filepath.Join(rootdir, name)
		if err := os.Remove(fullpath); err != nil {
			return err
		}
	}

	return nil
}

var (
	ebpfProgramName string
	ebpfObjFile     string
)

func xdpBuildForTest(file string, defines []string, t *testing.T) error {
	// Map clear
	if err := unlinkAll("/sys/fs/bpf/xdp/globals/"); err != nil {
		return err
	}

	// Logger
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	log := logger.Sugar()
	util.SetLocalExecuteSilence(false)

	// Common vars and Build ebpf program
	ebpfProgramName = "test001"
	tmppath, err := Build(log, file, true, ebpfProgramName, defines)
	if err != nil {
		return err
	}

	ebpfObjFile = fmt.Sprintf("%s/bin/out.o", tmppath)
	return nil
}

func DiffPackets(b1, b2 []byte) (bool, string, error) {
	p1 := gopacket.NewPacket(b1, layers.LayerTypeEthernet, gopacket.Default)
	p2 := gopacket.NewPacket(b2, layers.LayerTypeEthernet, gopacket.Default)

	if len(p1.Layers()) != len(p2.Layers()) {
		return true, fmt.Sprintf("#layer is diff %d, %d",
			len(p1.Layers()), len(p2.Layers())), nil
	}

	for i := 0; i < len(p1.Layers()); i++ {
		l1 := p1.Layers()[i]
		l2 := p2.Layers()[i]
		if !reflect.DeepEqual(l1.LayerContents(), l2.LayerContents()) {
			pp.Println("p1-debug-output", l1)
			pp.Println("p2-debug-output", l2)
			msg := fmt.Sprintf("idx%d %s %s %s", i,
				l1.LayerType().String(),
				l2.LayerType().String(),
				cmp.Diff(l1.LayerContents(), l2.LayerContents()))
			return true, msg, nil
		}
	}

	return false, "", nil
}

func ExecuteTestCase(tc TestCase, t *testing.T) {
	progFile, defines := tc.ProgInfo()
	if err := xdpBuildForTest(progFile, defines, t); err != nil {
		t.Error(err)
	}

	// Load ebpf program
	prog, err := XdpLoad(ebpfObjFile, "xdp_ingress")
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			s := fmt.Sprint("\n\n\n")
			for _, log := range ve.Log {
				s += fmt.Sprintln(log)
			}
			s += fmt.Sprint("\n\n\n")
			s += fmt.Sprintf("%d logs\n", len(ve.Log))
			_ = os.WriteFile("/tmp/verifier.log", []byte(s), os.ModePerm)
		}
		t.Error(err)
	}
	if err := FlushProgRunMapContext(ebpfProgramName); err != nil {
		t.Error(err)
	}

	// Set ebpf map fib6
	if err := SetProgRunMapContext(tc.PreTestMapContext(), ebpfProgramName); err != nil {
		t.Error(err)
	}

	// Start PerfEvent subscribe
	reader, err := NewEventReader(fmt.Sprintf(
		"/sys/fs/bpf/xdp/globals/%s_events", ebpfProgramName), 4096)
	if err != nil {
		t.Error(err)
	}
	defer reader.Close()

	// Test ebpf program
	input, err := tc.GenerateInput()
	if err != nil {
		t.Error(err)
	}
	ret, output, err := prog.Test(input)
	if err != nil {
		t.Error(err)
	}

	// Save return pkt to pcap
	// Check output packet and retCode
	if err := util.LogPacket("/tmp/output.pcapng", output); err != nil {
		t.Error(err)
	}
	retCheck, outputCheck, err := tc.GenerateOutput()
	if err != nil {
		t.Error(err)
	}
	if ret != uint32(retCheck) {
		t.Errorf("got %d want %d", ret, 2)
	}
	outputProcessed, err := tc.OutputPostProcess(output)
	if err != nil {
		t.Error(err)
	}
	pktDiffExist, pktDiffMsg, err := DiffPackets(outputProcessed, outputCheck)
	if err != nil {
		t.Error(err)
	}
	if pktDiffExist {
		t.Errorf("out-pkt invalid DIFF:\n%s", pktDiffMsg)
	}

	// Dump result map data
	// Proprocess
	dump, err := DumpProgRunMapContext(ebpfProgramName)
	if err != nil {
		t.Error(err)
	}
	tc.PostTestMapContextPreprocess(dump)
	check := tc.PostTestMapContextExpect()
	if !reflect.DeepEqual(check, dump) {
		t.Errorf("map invalid DIFF:\n%s", cmp.Diff(check, dump))
	}

	// Dump result event data
	if tc, ok := tc.(TestCaseWithEvent); ok {
		events := tc.PostTestEventsExpect()
		eventsResults := []GenericEvent{}
		loop := true
		for loop {
			reader.SetDeadline(time.Now().Add(time.Second))
			record, err := reader.Read()
			switch {
			case errors.Is(err, os.ErrDeadlineExceeded):
				loop = false
			case err == nil:
				e, err := ParseEvent(record)
				if err != nil {
					t.Error(err)
				}
				eventsResults = append(eventsResults, *e)
			case errors.Is(err, os.ErrDeadlineExceeded):
				continue
			default:
				t.Error(err)
			}
		}
		eventsResults = tc.PostTestEventPreprocess(eventsResults)
		if !reflect.DeepEqual(eventsResults, events) {
			t.Errorf("events invalid DIFF:\n%s", cmp.Diff(eventsResults, events))
		}
	}
}

func TestXDPLoad(t *testing.T) {
	xdpBuildForTest("common_main.c", []string{
		"DEBUG_FUNCTION_CALL",
	}, t)

	if _, err := XdpLoad(ebpfObjFile, "xdp_ingress"); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			s := fmt.Sprintf("Bpf Verifier failed at %s\n", time.Now().String())
			for _, log := range ve.Log {
				s += fmt.Sprintln(log)
			}
			s += fmt.Sprintf("%d logs\n", len(ve.Log))
			_ = os.WriteFile("/tmp/verifier.log", []byte(s), os.ModePerm)
		}
		t.Error(errors.Wrap(err, "log:/tmp/verifier.log"))
	}
}

func ExcludeEventFunctionCall(events []GenericEvent) []GenericEvent {
	deleteIdx := []int{}
	for idx := range events {
		if events[idx].EventBodyFunctionCall != nil {
			deleteIdx = append(deleteIdx, idx)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(deleteIdx)))
	for _, idx := range deleteIdx {
		events = append(events[:idx], events[idx+1:]...)
	}
	return events
}
