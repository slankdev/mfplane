package mfpctl

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

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

	return cmd
}

var (
	log *zap.Logger

	// bpffs root directory
	mapfileDir = "/sys/fs/bpf/xdp/globals"

	// Timers
	conntrack_tcp_timeout_opening     = 10
	conntrack_tcp_timeout_closing     = 1
	conntrack_tcp_timeout_established = 1200
	conntrack_udp_timeout             = 10
	conntrack_icmp_timeout            = 10
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
	for _, ent := range natOut.Items {
		expired, err := IsExpired(ent.Val)
		if err != nil {
			return err
		}
		if expired {
			log.Info("clear nat_out",
				zap.String("map", mapfile),
				zap.Uint8("proto", ent.Key.Proto),
				zap.String("orgAddr", ent.Key.Addr),
				zap.Uint16("orgPort", ent.Key.Port),
				zap.String("natAddr", ent.Val.Addr),
				zap.Uint16("natPort", ent.Val.Port),
			)
			if err := ebpf.Delete(mapfile, &ent.Key); err != nil {
				return err
			}
		}
	}
	return nil
}

func batchNatRet(mapfile string, natRet *ebpf.NatRetRender) error {
	for _, ent := range natRet.Items {
		expired, err := IsExpired(ent.Val)
		if err != nil {
			return err
		}
		if expired {
			log.Info("clear nat_ret",
				zap.String("map", mapfile),
				zap.Uint8("proto", ent.Key.Proto),
				zap.String("orgAddr", ent.Key.Addr),
				zap.Uint16("orgPort", ent.Key.Port),
				zap.String("natAddr", ent.Val.Addr),
				zap.Uint16("natPort", ent.Val.Port),
			)
			if err := ebpf.Delete(mapfile, &ent.Key); err != nil {
				return err
			}
		}
	}
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

	// Const
	ticker1s := time.NewTicker(time.Second)

	// Main loop
	for {
		select {
		case <-ticker1s.C:
			log.Debug("tick")

			// nat_out
			for _, mapfile := range mapfilesNatOut {
				natOut := ebpf.NatOutRender{}
				if err := ebpf.Read(mapfile, &natOut); err != nil {
					log.Error("ERROR", zap.Error(err))
					continue
				}
				if err := batchNatOut(mapfile, &natOut); err != nil {
					log.Error("ERROR", zap.Error(err))
					continue
				}
			}

			// nat_ret
			for _, mapfile := range mapfilesNatRet {
				natRet := ebpf.NatRetRender{}
				if err := ebpf.Read(mapfile, &natRet); err != nil {
					log.Error("ERROR", zap.Error(err))
					continue
				}
				if err := batchNatRet(mapfile, &natRet); err != nil {
					log.Error("ERROR", zap.Error(err))
					continue
				}
			}
		}
	}
}
