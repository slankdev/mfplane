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

package main

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/pile"
	"github.com/gcla/gowid/widgets/text"

	"github.com/slankdev/mfplane/pkg/util"
)

type Config struct {
	Targets []struct {
		Name    string `json:"name"`
		Command string `json:"command,omitempty"`

		// TODO(slankdev): to be implemented correctly
		// IntervalMsec uint   `json:"interval_msec"`
		// WindowMsec   uint   `json:"window_msec"`
		//
		// TODO(slankdev): example configuration
		// targets:
		// - name: n1_xdp_tx
		//   interval_msec: 500
		//   window_msec: 2000
		//   command: |
		// 	   mfpctl bpf map inspect counter -n n1 \
		//       | jq .items[0].val.XdpActionTxPkts
	} `json:"targets"`
}

type CommandStatus struct {
	Name    string
	Command string
	Script  string
	Rate    int
	Window  int
	Buffer  []int
	Text    *text.Widget
}

var (
	clioptLoglevel int
	clioptFile     string
	clioptCmd      string
	logger         *zap.Logger
	// commandStatuses stores each command's execution result and it's
	// tsdb contents
	commandStatuses []CommandStatus

	app *gowid.App
)

func initCommandStatusesFromArgs(cmd string) error {
	// Init command status
	cs := CommandStatus{
		Name:    "no-name",
		Window:  2,
		Command: cmd,
		Rate:    -1,
		Text:    text.New("out"),
	}
	dirname, err := os.MkdirTemp("", "rate-")
	if err != nil {
		return err
	}
	filename := fmt.Sprintf("%s/rate.sh", dirname)
	if err := os.WriteFile(filename, []byte(cs.Command), 0755); err != nil {
		return err
	}
	cs.Script = filename
	commandStatuses = append(commandStatuses, cs)
	return nil
}

func initCommandStatusesFromConfig(filename string) error {
	// Parse configfile and construct command statuses
	fileContent, err := os.ReadFile(clioptFile)
	if err != nil {
		return err
	}
	cfg := Config{}
	if err := util.YamlUnmarshalViaJson(fileContent, &cfg); err != nil {
		return err
	}
	dirname, err := os.MkdirTemp("", "rate-")
	if err != nil {
		return err
	}
	for i, target := range cfg.Targets {
		if err := os.WriteFile(fmt.Sprintf("/tmp/rate%d.sh", i), []byte(target.Command), 0755); err != nil {
			return err
		}
		cs := CommandStatus{
			Name:    target.Name,
			Command: target.Command,
			Window:  2,
			Rate:    -1,
			Text:    text.New("out"),
		}
		filename := fmt.Sprintf("%s/rate%d.sh", dirname, i)
		if err := os.WriteFile(filename, []byte(cs.Command), 0755); err != nil {
			return err
		}
		cs.Script = filename
		commandStatuses = append(commandStatuses, cs)
	}
	return nil
}

func initLogger() error {
	var err error
	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(zapcore.Level(clioptLoglevel))
	logger, err = cfg.Build()
	if err != nil {
		return err
	}
	return nil
}

func main() {
	rand.Seed(time.Now().UnixNano())
	if err := NewCommand().Execute(); err != nil {
		os.Exit(1)
	}
}

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "rate",
		RunE: rateCallback,
	}
	cmd.Flags().StringVarP(&clioptFile, "file", "f", "", "config file")
	cmd.Flags().StringVarP(&clioptCmd, "cmd", "c", "", "command")
	cmd.PersistentFlags().IntVarP(&clioptLoglevel, "log", "l",
		int(zapcore.InfoLevel), "-1:Debug, 0:Info, 1:Warn: 2:Error")
	cmd.AddCommand(util.NewCommandVersion())
	cmd.AddCommand(util.NewCmdCompletion(cmd))
	return cmd
}

func rateCallback(cmd *cobra.Command, args []string) error {
	if err := initLogger(); err != nil {
		return err
	}

	// init commandstatus
	if clioptCmd != "" && clioptFile != "" {
		return fmt.Errorf("invalid. both cmd and file cannot be specified")
	}
	if clioptCmd != "" {
		if err := initCommandStatusesFromArgs(clioptCmd); err != nil {
			return err
		}
	}
	if clioptFile != "" {
		if err := initCommandStatusesFromConfig(clioptFile); err != nil {
			return err
		}
	}

	// Start tui loop
	return printLoopFn()
}

func scrapingLoopFn(i int) {
	if len(commandStatuses) <= i {
		panic("invalid index")
	}
	cs := &commandStatuses[i]

	// Loop
	ticker := time.NewTicker(1000 * time.Millisecond)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	loop := true
	for loop {
		select {
		case <-quit:
			fmt.Println("bye...")
			loop = false
		case <-ticker.C:
			// Command execute
			stdoutbuf := bytes.Buffer{}
			stderrbuf := bytes.Buffer{}
			ctx, _ := context.WithTimeout(context.Background(),
				10000*time.Millisecond)
			cmd := exec.CommandContext(ctx, "sh", "-c", cs.Script)
			cmd.Stdout = &stdoutbuf
			cmd.Stderr = &stderrbuf
			if err := cmd.Run(); err != nil {
				logger.Error("ERROR", zap.Error(err))
				return
			}
			val, err := strconv.Atoi(strings.TrimSpace(stdoutbuf.String()))
			if err != nil {
				logger.Error("ERROR", zap.Error(err))
				return
			}

			// TS-DB and print result
			cs.Buffer = append([]int{val}, cs.Buffer...)
			if len(cs.Buffer) > cs.Window {
				cs.Buffer = cs.Buffer[:cs.Window]
				cs.Rate = (cs.Buffer[0] - cs.Buffer[cs.Window-1]) / (cs.Window - 1)
				logger.Debug("buffer", zap.Any("buffer", cs.Buffer))
			}
		}
	}
}

// TODO(slankdev): implement tui
//
//	NAME         RATE  LATENCY
//	n1_nat_out   8000  xx
//	n1_nat_ret   xx    xx
//	n1_xdp_tx    xx    xx
//	n1_xdp_drop  xx    xx
func printLoopFn() error {
	// Constructing TUI App
	var err error
	flow := gowid.RenderFlow{}
	widgets := []gowid.IContainerWidget{}
	for i := range commandStatuses {
		widget := &gowid.ContainerWidget{IWidget: commandStatuses[i].Text, D: flow}
		widgets = append(widgets, widget)
	}
	view := pile.New(widgets)
	app, err = gowid.NewApp(gowid.AppArgs{
		View: view,
		Log:  logrus.New(),
	})
	if err != nil {
		return err
	}

	// Start scraping loops
	for i := range commandStatuses {
		go scrapingLoopFn(i)
	}

	// Refresh callbacks
	go func() {
		ticker := time.NewTicker(1000 * time.Millisecond)
		for range ticker.C {
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				for i := range commandStatuses {
					cs := &commandStatuses[i]
					commandStatuses[i].Text.SetText(
						fmt.Sprintf("%s  %d", cs.Name, cs.Rate), app)
				}
			}))
		}
	}()

	// Start frontend
	app.SimpleMainLoop()
	return nil
}
