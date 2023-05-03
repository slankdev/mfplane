/*
Copyright 2022 Hiroki Shirokura.
Copyright 2022 Keio University.
Copyright 2022 Wide Project.

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

package util

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/fatih/color"
	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	silence = true
	logger  logr.Logger
	logging = false
)

func SetLocalExecuteSilence(v bool) {
	silence = v
}

func SetLogger(l logr.Logger) {
	logger = l
	logging = true
}

func UnsetLogger() {
	logging = false
}

func LocalExecute(cmdstr string) (string, error) {
	stdoutbuf := bytes.Buffer{}
	stderrbuf := bytes.Buffer{}

	cmd := exec.Command("sh", "-c", cmdstr)
	cmd.Stdout = &stdoutbuf
	cmd.Stderr = &stderrbuf

	if err := cmd.Run(); err != nil {
		str := fmt.Sprintf("CommandExecute [%s] ", cmd)
		str += color.RedString("Failed")
		str += color.RedString("%s", err.Error())
		println(str)
		println(stderrbuf.String())
		return "", err
	}

	if !silence {
		str := fmt.Sprintf("CommandExecute [%s] ", cmd)
		str += color.GreenString("Success")
		fmt.Printf("%s\n", str)
	}
	if logging {
		log.Log.Info("CMD", "command", cmdstr, "return", 0)
	}
	return stdoutbuf.String(), nil
}

func LocalExecutef(fs string, a ...interface{}) (string, error) {
	return LocalExecute(fmt.Sprintf(fs, a...))
}

func BackgroundLocalExecutef(fs string, a ...interface{}) (int, error) {
	cmdstr := fmt.Sprintf(fs, a...)
	cmd := exec.Command("sh", "-c", cmdstr)
	if err := cmd.Start(); err != nil {
		str := fmt.Sprintf("CommandExecute [%s] ", cmdstr)
		str += color.RedString("Failed")
		str += color.RedString("%s", err.Error())
		fmt.Printf("%s\n", str)
		return 0, err
	}
	go func() {
		cmd.Wait()
	}()
	return cmd.Process.Pid, nil
}

func CheckProcess(pidfile string) (bool, error) {
	if !FileExist(pidfile) {
		return false, nil
	}
	file, err := os.Open(pidfile)
	if err != nil {
		return false, err
	}
	defer file.Close()

	var pid int
	_, err = fmt.Fscanf(file, "%d", &pid)
	if err != nil {
		return false, err
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return false, err
	}

	err = process.Signal(syscall.Signal(0))
	if err != nil {
		if err.Error() == "os: process already finished" {
			return false, nil
		}
		return false, err
	}

	return true, nil
}
