package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func XdpLoad(progFile, section string) (*ebpf.Program, error) {
	spec, err := ebpf.LoadCollectionSpec(progFile)
	if err != nil {
		return nil, err
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: "/sys/fs/bpf/xdp/globals"},
	})
	if err != nil {
		return nil, err
	}
	prog, ok := coll.Programs[section]
	if !ok {
		return nil, fmt.Errorf("no xdp section named %s", section)
	}
	return prog, nil
}

func XdpAttach(netnsName, ifaceName, progFile, section, mode string) error {
	// Save root network namespace context
	rootNs, err := netns.Get()
	if err != nil {
		return err
	}

	// Get network namespace handler
	var handle *netlink.Handle
	var targetNs netns.NsHandle = rootNs
	handle, err = netlink.NewHandleAt(rootNs)
	if err != nil {
		return err
	}

	// If network namespace is specified,
	// get target network namespace context
	if netnsName != "" {
		targetNs, err = netns.GetFromPath(fmt.Sprintf("/var/run/netns/%s", netnsName))
		if err != nil {
			return err
		}
		handle, err = netlink.NewHandleAt(targetNs)
		if err != nil {
			return err
		}
	}

	// Resolve target-link info
	dev, err := handle.LinkByName(ifaceName)
	if err != nil {
		return err
	}

	// Load ebpf program and its maps
	prog, err := XdpLoad(progFile, section)
	if err != nil {
		return err
	}

	// Set network namespace context
	if netnsName != "" {
		if err := netns.Set(targetNs); err != nil {
			return err
		}
	}

	// Attach XDP program
	var flags int
	switch mode {
	case "xdp":
		flags = int(link.XDPDriverMode)
	case "xdpgeneric":
		flags = int(link.XDPGenericMode)
	case "xdpoffload":
		flags = int(link.XDPOffloadMode)
	default:
		return fmt.Errorf("unknown xdp mode %s", mode)
	}
	if err := netlink.LinkSetXdpFdWithFlags(dev, prog.FD(), flags); err != nil {
		return err
	}

	// Reset network namespace context.
	if netnsName != "" {
		if err := netns.Set(rootNs); err != nil {
			return err
		}
	}
	return nil
}

func XdpDetach(netnsName, ifaceName string) error {
	// Save root network namespace context
	rootNs, err := netns.Get()
	if err != nil {
		return err
	}

	// Get network namespace handler
	var handle *netlink.Handle
	var targetNs netns.NsHandle = rootNs
	handle, err = netlink.NewHandleAt(rootNs)
	if err != nil {
		return err
	}

	// If network namespace is specified,
	// get target network namespace context
	if netnsName != "" {
		targetNs, err = netns.GetFromPath(fmt.Sprintf("/var/run/netns/%s",
			netnsName))
		if err != nil {
			return err
		}
		handle, err = netlink.NewHandleAt(targetNs)
		if err != nil {
			return err
		}
	}

	// Resolve target-link info
	dev, err := handle.LinkByName(ifaceName)
	if err != nil {
		return err
	}

	// Set network namespace context
	if netnsName != "" {
		if err := netns.Set(targetNs); err != nil {
			return err
		}
	}

	// Detach XDP program
	// If the file is not attached, no error message will appear,
	// so you can force the file to be executed.
	//
	// NOTE(slankdev): how to detach forcely,
	// respecting the way of cilium
	// https://github.com/cilium/cilium/blob/\
	// a79241a6ad4f5d4184e1698a8490171d036918ce/\
	// cilium-dbg/cmd/cleanup.go#L575
	if err := netlink.LinkSetXdpFdWithFlags(dev, -1,
		int(link.XDPGenericMode)); err != nil {
		return err
	}
	if err := netlink.LinkSetXdpFdWithFlags(dev, -1,
		int(link.XDPDriverMode)); err != nil {
		return err
	}

	// Reset network namespace context.
	if netnsName != "" {
		if err := netns.Set(rootNs); err != nil {
			return err
		}
	}
	return nil
}
