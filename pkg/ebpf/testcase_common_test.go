package ebpf

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
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
	GenerateInput() ([]byte, error)
	GenerateOutput() (int, []byte, error)
	OutputPostProcess(b []byte) ([]byte, error)
	PreTestMapContext() *ProgRunMapContext
	PostTestMapContextPreprocess(mc *ProgRunMapContext)
	PostTestMapContextExpect() *ProgRunMapContext
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

func TestMain(m *testing.M) {
	// Map clear
	if err := unlinkAll("/sys/fs/bpf/xdp/globals/"); err != nil {
		pp.Println(err)
		os.Exit(1)
	}

	// Logger
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	log := logger.Sugar()
	util.SetLocalExecuteSilence(false)

	// Common vars
	ebpfProgramName = "test001"

	// Build ebpf program
	file := "common_main.c"
	tmppath, err := Build(log, file,
		true,
		false,
		ebpfProgramName,
		true,
		true,
		[]string{
			"DEBUG_FUNCTION_CALL",
			"DEBUG_MF_REDIRECT",
			"DEBUG_PARSE_METADATA",
		},
	)
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	ebpfObjFile = fmt.Sprintf("%s/bin/out.o", tmppath)
	m.Run()
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
}

func TestXDPLoad(t *testing.T) {
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
