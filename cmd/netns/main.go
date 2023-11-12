package main

import (
	"github.com/slankdev/mfplane/pkg/ebpf"
)

func main() {
	if err := ebpf.XdpAttach("tmp1", "eth0",
		"/var/run/mfplane/476979965/bin/out.o",
		"xdp_ingress", "xdpgeneric"); err != nil {
		panic(err)
	}

	if err := ebpf.XdpAttach("tmp2", "eth0",
		"/var/run/mfplane/476979965/bin/out.o",
		"xdp_ingress", "xdpgeneric"); err != nil {
		panic(err)
	}

	if err := ebpf.XdpAttach("", "dum1",
		"/var/run/mfplane/476979965/bin/out.o",
		"xdp_ingress", "xdpgeneric"); err != nil {
		panic(err)
	}

	if err := ebpf.XdpDetach("tmp2", "eth0"); err != nil {
		panic(err)
	}

	if err := ebpf.XdpDetach("", "dum1"); err != nil {
		panic(err)
	}
}
