package mfpctl

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sys/unix"

	"github.com/slankdev/mfplane/pkg/ebpf"
	"github.com/slankdev/mfplane/pkg/util"
)

func NewCommandDaemon() *cobra.Command {
	cmd := &cobra.Command{
		Use: "daemon",
	}
	cmd.AddCommand(NewCommandDaemonNat())
	cmd.AddCommand(NewCommandDaemonMetrics())
	return cmd
}

func NewCommandDaemonNat() *cobra.Command {
	var clioptLoglevel int
	cmd := &cobra.Command{
		Use: "nat",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Logger
			cfg := zap.NewProductionConfig()
			cfg.Level = zap.NewAtomicLevelAt(zapcore.Level(clioptLoglevel))
			logger, err := cfg.Build()
			if err != nil {
				return err
			}
			log = logger

			// Main
			mainDeamonNat()
			return nil
		},
	}
	cmd.Flags().IntVarP(&clioptLoglevel, "log", "l", int(zapcore.InfoLevel),
		"-1:Debug, 0:Info, 1:Warn: 2:Error")
	cmd.Flags().Uint32Var(&conntrack_tcp_timeout_opening, "conntrack_tcp_timeout_opening", 10, "")
	cmd.Flags().Uint32Var(&conntrack_tcp_timeout_closing, "conntrack_tcp_timeout_closing", 1, "")
	cmd.Flags().Uint32Var(&conntrack_tcp_timeout_established, "conntrack_tcp_timeout_established", 1200, "")
	cmd.Flags().Uint32Var(&conntrack_udp_timeout, "conntrack_udp_timeout", 10, "")
	cmd.Flags().Uint32Var(&conntrack_icmp_timeout, "conntrack_icmp_timeout", 10, "")
	return cmd
}

var (
	log *zap.Logger

	// bpffs root directory
	mapfileDir = "/sys/fs/bpf/xdp/globals"

	// Timers
	conntrack_tcp_timeout_opening     uint32
	conntrack_tcp_timeout_closing     uint32
	conntrack_tcp_timeout_established uint32
	conntrack_udp_timeout             uint32
	conntrack_icmp_timeout            uint32
)

func IsExpired(addrPortStats ebpf.StructAddrPortStatsRender) (bool, error) {
	lastUpdated, err := util.KtimeSecToTime(addrPortStats.UpdatedAt)
	if err != nil {
		return false, err
	}

	switch addrPortStats.Proto {
	case unix.IPPROTO_UDP:
		return time.Now().After(lastUpdated.Add(
			time.Second * time.Duration(conntrack_udp_timeout))), nil
	case unix.IPPROTO_ICMP:
		return time.Now().After(lastUpdated.Add(
			time.Second * time.Duration(conntrack_icmp_timeout))), nil
	case unix.IPPROTO_TCP:
		switch {
		case addrPortStats.Flags.TcpStateClosing == false &&
			addrPortStats.Flags.TcpStateEstablish == false:
			return time.Now().After(lastUpdated.Add(
				time.Second * time.Duration(conntrack_tcp_timeout_opening))), nil
		case addrPortStats.Flags.TcpStateClosing == false &&
			addrPortStats.Flags.TcpStateEstablish == true:
			return time.Now().After(lastUpdated.Add(
				time.Second * time.Duration(conntrack_tcp_timeout_established))), nil
		case addrPortStats.Flags.TcpStateClosing == true:
			return time.Now().After(lastUpdated.Add(
				time.Second * time.Duration(conntrack_tcp_timeout_closing))), nil
		default:
			return false, fmt.Errorf("unknown tcp state %d",
				addrPortStats.Flags.Uint64())
		}
	default:
		return false, fmt.Errorf("unknown proto %d", addrPortStats.Proto)
	}
}

func batchNatOut(mapfile string, natOut *ebpf.NatOutRender) error {
	cntExpiredOpening := 0
	cntExpiredClosing := 0
	cntExpiredEstablished := 0
	keys := []ebpf.StructAddrPort{}
	for _, ent := range natOut.Items {
		expired, err := IsExpired(ent.Val)
		if err != nil {
			return err
		}
		if expired {
			switch ent.Val.Proto {
			case unix.IPPROTO_TCP:
				switch {
				case !ent.Val.Flags.TcpStateClosing &&
					!ent.Val.Flags.TcpStateEstablish:
					cntExpiredOpening++
				case !ent.Val.Flags.TcpStateClosing &&
					ent.Val.Flags.TcpStateEstablish:
					cntExpiredEstablished++
				case ent.Val.Flags.TcpStateClosing:
					cntExpiredClosing++
				}
			}

			log.Debug("clear nat_out",
				zap.String("map", mapfile),
				zap.Uint8("proto", ent.Key.Proto),
				zap.String("orgAddr", ent.Key.Addr),
				zap.Uint16("orgPort", ent.Key.Port),
				zap.String("natAddr", ent.Val.Addr),
				zap.Uint16("natPort", ent.Val.Port),
			)
			raw, err := ent.Key.ToRaw()
			if err != nil {
				return err
			}
			raw0, ok := raw.(*ebpf.StructAddrPort)
			if !ok {
				return fmt.Errorf("cast error")
			}
			keys = append(keys, *raw0)
		}
	}

	if len(keys) == 0 {
		return nil
	}

	// BatchDelete
	m, err := ciliumebpf.LoadPinnedMap(mapfile, nil)
	if err != nil {
		return errors.Wrap(err, "natOut ebpf.LoadPinnedMap")
	}
	log.Info("nat_out batchDelete start",
		zap.Int("count", len(keys)),
		zap.Int("countOpening", cntExpiredOpening),
		zap.Int("countClosing", cntExpiredClosing),
		zap.Int("countEstablished", cntExpiredEstablished),
	)
	before := time.Now()
	if _, err := m.BatchDelete(keys, nil); err != nil {
		return errors.Wrap(err, "natOut m.BatchDelete")
	}
	diff := time.Since(before)
	log.Info("nat_out batchDelete finished",
		zap.Int("count", len(keys)),
		zap.Int("countOpening", cntExpiredOpening),
		zap.Int("countClosing", cntExpiredClosing),
		zap.Int("countEstablished", cntExpiredEstablished),
		zap.Duration("latency", diff),
	)
	return nil
}

func batchNatRet(mapfile string, natRet *ebpf.NatRetRender) error {
	cntExpiredOpening := 0
	cntExpiredClosing := 0
	cntExpiredEstablished := 0
	keys := []ebpf.StructAddrPort{}
	for _, ent := range natRet.Items {
		expired, err := IsExpired(ent.Val)
		if err != nil {
			return err
		}
		if expired {
			switch ent.Val.Proto {
			case unix.IPPROTO_TCP:
				switch {
				case !ent.Val.Flags.TcpStateClosing &&
					!ent.Val.Flags.TcpStateEstablish:
					cntExpiredOpening++
				case !ent.Val.Flags.TcpStateClosing &&
					ent.Val.Flags.TcpStateEstablish:
					cntExpiredEstablished++
				case ent.Val.Flags.TcpStateClosing:
					cntExpiredClosing++
				}
			}

			log.Debug("clear nat_ret",
				zap.String("map", mapfile),
				zap.Uint8("proto", ent.Key.Proto),
				zap.String("orgAddr", ent.Key.Addr),
				zap.Uint16("orgPort", ent.Key.Port),
				zap.String("natAddr", ent.Val.Addr),
				zap.Uint16("natPort", ent.Val.Port),
			)
			raw, err := ent.Key.ToRaw()
			if err != nil {
				return err
			}
			raw0, ok := raw.(*ebpf.StructAddrPort)
			if !ok {
				return fmt.Errorf("cast error")
			}
			keys = append(keys, *raw0)
		}
	}

	if len(keys) == 0 {
		return nil
	}

	// BatchDelete
	m, err := ciliumebpf.LoadPinnedMap(mapfile, nil)
	if err != nil {
		return errors.Wrap(err, "natRet ebpf.LoadPinnedMap")
	}
	log.Info("nat_ret batchDelete start",
		zap.Int("count", len(keys)),
		zap.Int("countOpening", cntExpiredOpening),
		zap.Int("countClosing", cntExpiredClosing),
		zap.Int("countEstablished", cntExpiredEstablished),
	)
	before := time.Now()
	if _, err := m.BatchDelete(keys, nil); err != nil {
		return errors.Wrap(err, "natRet m.BatchDelete")
	}
	diff := time.Since(before)
	log.Info("nat_ret batchDelete finished",
		zap.Int("count", len(keys)),
		zap.Int("countOpening", cntExpiredOpening),
		zap.Int("countClosing", cntExpiredClosing),
		zap.Int("countEstablished", cntExpiredEstablished),
		zap.Duration("latency", diff),
	)
	return nil
}

func getMatchingFiles(dirPath, pattern string) ([]string, error) {
	matchedFiles := []string{}
	files, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		if !file.IsDir() && re.MatchString(file.Name()) {
			matchedFiles = append(matchedFiles,
				filepath.Join(dirPath, file.Name()))
		}
	}
	return matchedFiles, nil
}

func mainDeamonNat() {
	log.Info("starting daemon")

	// Fetch mapfiles
	mapfilesNatOut, err := getMatchingFiles(mapfileDir, ".*_nat_out$")
	if err != nil {
		log.Error("ERROR", zap.Error(err))
		return
	}
	mapfilesNatRet, err := getMatchingFiles(mapfileDir, ".*_nat_ret$")
	if err != nil {
		log.Error("ERROR", zap.Error(err))
		return
	}

	// Loop stopper
	loop := true
	quit := make(chan os.Signal, 10)
	signal.Notify(quit, os.Interrupt)
	go func() {
		<-quit
		loop = false
	}()

	// nat_out
	go func() {
		ticker1s := time.NewTicker(time.Second)
		for loop {
			select {
			case <-ticker1s.C:
				log.Debug("tick")
				for _, mapfile := range mapfilesNatOut {
					before := time.Now()
					natOut := ebpf.NatOutRender{}
					if err := ebpf.Read(mapfile, &natOut); err == nil {
						diff := time.Since(before)
						log.Info("nat_out read latency",
							zap.Duration("latency", diff))
						if err := batchNatOut(mapfile, &natOut); err != nil {
							log.Error("ERROR", zap.Error(err))
						}
					} else {
						log.Error("ERROR", zap.Error(err))
					}
				}
			}
		}
	}()

	// nat_ret
	go func() {
		ticker1s := time.NewTicker(time.Second)
		for loop {
			select {
			case <-ticker1s.C:
				log.Debug("tick")
				for _, mapfile := range mapfilesNatRet {
					before := time.Now()
					natRet := ebpf.NatRetRender{}
					if err := ebpf.Read(mapfile, &natRet); err == nil {
						diff := time.Since(before)
						log.Info("nat_ret read latency",
							zap.Duration("latency", diff))
						if err := batchNatRet(mapfile, &natRet); err != nil {
							log.Error("ERROR", zap.Error(err))
						}
					} else {
						log.Error("ERROR", zap.Error(err))
					}
				}
			}
		}
	}()

	// Main loop
	for loop {
		time.Sleep(time.Second)
	}
}

func writeFile(path string, names []string, counters []ebpf.CounterRender) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for idx := range counters {
		n := names[idx]
		v := counters[idx].Items[0].Val
		rv := reflect.ValueOf(v)
		rt := rv.Type()
		for i := 0; i < rt.NumField(); i++ {
			field := rt.Field(i)
			fmt.Fprintf(f, "counter{name=\"%s\",counter=\"%s\"} %v\n", n,
				field.Name, rv.FieldByName(field.Name))
		}
	}
	return nil
}

func NewCommandDaemonMetrics() *cobra.Command {
	var clioptNames []string
	var clioptDir string
	var clioptLoglevel int
	cmd := &cobra.Command{
		Use: "metrics",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := zap.NewProductionConfig()
			cfg.Level = zap.NewAtomicLevelAt(zapcore.Level(clioptLoglevel))
			logger, err := cfg.Build()
			if err != nil {
				return err
			}

			if err := os.MkdirAll(clioptDir, os.ModePerm); err != nil {
				return err
			}

			// Loop stopper
			loop := true
			quit := make(chan os.Signal, 10)
			signal.Notify(quit, os.Interrupt)
			go func() {
				<-quit
				loop = false
			}()

			ticker1s := time.NewTicker(time.Second)
			for loop {
				//XXX
				loop = false
				//XXX

				select {
				case <-ticker1s.C:
					counters := []ebpf.CounterRender{}
					for _, name := range clioptNames {
						mapfile := fmt.Sprintf("/sys/fs/bpf/xdp/globals/%s_counter", name)
						counter := ebpf.CounterRender{}
						if err := ebpf.Read(mapfile, &counter); err != nil {
							logger.Error("ebpf.Read", zap.Error(err),
								zap.String("mapfile", mapfile))
						}
						counters = append(counters, counter)
					}
					d := fmt.Sprintf("%s/counter.prom.$$", clioptDir)
					if err := writeFile(d, clioptNames, counters); err != nil {
						return err
					}
					if err := os.Rename(d, fmt.Sprintf("%s/counter.prom",
						clioptDir)); err != nil {
						return err
					}
				}
			}

			return nil
		},
	}
	cmd.Flags().StringVarP(&clioptDir, "dir", "d", "/var/run/mfplane/stats", "")
	cmd.Flags().StringArrayVarP(&clioptNames, "name", "n", []string{}, "")
	cmd.Flags().IntVarP(&clioptLoglevel, "log", "l", int(zapcore.InfoLevel),
		"-1:Debug, 0:Info, 1:Warn: 2:Error")
	return cmd
}
