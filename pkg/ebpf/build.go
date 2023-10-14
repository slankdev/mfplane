package ebpf

import (
	"fmt"
	"os"

	"go.uber.org/zap"

	"github.com/slankdev/mfplane/pkg/util"
)

func Build(log *zap.SugaredLogger,
	file string,
	clioptVerbose bool,
	clioptDebug bool,
	clioptName string,
	clioptDebugIgnorePacket bool,
	clioptDebugErrorPacket bool,
	clioptDefine []string,
) (string, error) {
	// create temp dir
	if err := os.MkdirAll("/var/run/mfplane", 0777); err != nil {
		return "", err
	}
	tmppath, err := os.MkdirTemp("/var/run/mfplane", "")
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(fmt.Sprintf("%s/bin", tmppath), 0777); err != nil {
	}
	if clioptVerbose {
		log.Info("create tmp dir", "path", tmppath)
	}

	// copy bpf c code
	for _, file := range files {
		f, err := codeFS.ReadFile(file)
		if err != nil {
			return "", err
		}
		if err := util.WriteFile(fmt.Sprintf("%s/%s", tmppath, file),
			f); err != nil {
			return "", err
		}
	}
	if clioptVerbose {
		log.Info("write c files", "path", tmppath)
	}

	// build with some special parameter
	// TODO(slankdev): cflags += " -nostdinc" for less dependency
	cflags := "-target bpf -O2 -g -I /usr/include/x86_64-linux-gnu"
	cflags += fmt.Sprintf(" -I %s/code", tmppath)
	cflags += " -D NAME=" + clioptName
	if clioptDebug {
		cflags += " -DDEBUG"
	}
	if clioptDebugIgnorePacket {
		cflags += " -DDEBUG_IGNORE_PACKET"
	}
	if clioptDebugErrorPacket {
		cflags += " -DDEBUG_ERROR_PACKET"
	}
	for _, def := range clioptDefine {
		cflags += " -D " + def
	}
	cmdstr := fmt.Sprintf(
		"clang %s -c %s/code/%s -o %s/bin/out.o",
		cflags, tmppath, file, tmppath)
	if _, err := util.LocalExecutef(
		"clang %s -c %s/code/%s -o %s/bin/out.o",
		cflags, tmppath, file, tmppath); err != nil {
		return "", err
	}
	if clioptVerbose {
		log.Info(cmdstr)
		log.Info("build c files",
			"main", fmt.Sprintf("%s/code/%s", tmppath, file),
			"out", fmt.Sprintf("%s/bin/out.o", tmppath),
			"cflags", cflags)
	}

	return tmppath, err
}
