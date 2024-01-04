package ebpf

import (
	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

//go:generate go run ./gen/gen.go

type Driver struct {
	SetCommand     *cobra.Command
	InspectCommand *cobra.Command
	FlushCommand   *cobra.Command
	SizeCommand    *cobra.Command
}

var (
	Drivers []Driver
)

func NewCommandMapSet() *cobra.Command {
	cmd := &cobra.Command{
		Use: "set",
	}
	for _, d := range Drivers {
		if d.SetCommand != nil {
			cmd.AddCommand(d.SetCommand)
		}
	}
	return cmd
}

func NewCommandMapInspect() *cobra.Command {
	cmd := &cobra.Command{
		Use: "inspect",
	}
	for _, d := range Drivers {
		if d.InspectCommand != nil {
			cmd.AddCommand(d.InspectCommand)
		}
	}
	return cmd
}

func NewCommandMapFlush() *cobra.Command {
	cmd := &cobra.Command{
		Use: "flush",
	}
	for _, d := range Drivers {
		if d.FlushCommand != nil {
			cmd.AddCommand(d.FlushCommand)
		}
	}
	return cmd
}

func NewCommandMapSize() *cobra.Command {
	cmd := &cobra.Command{
		Use: "size",
	}
	for _, d := range Drivers {
		if d.SizeCommand != nil {
			cmd.AddCommand(d.SizeCommand)
		}
	}
	return cmd
}

type KVRender interface {
	ToRaw() (KVRaw, error)
}

type KVRaw interface {
	ToRender() (KVRender, error)
}

type MapRender interface {
	ReadImpl(mapfile string) error
	WriteImpl(mapfile string) error
}

func Read(mapfile string, r MapRender) error {
	return r.ReadImpl(mapfile)
}

func Write(mapfile string, r MapRender) error {
	return r.WriteImpl(mapfile)
}

func Delete(mapfile string, k KVRender) error {
	m, err := ebpf.LoadPinnedMap(mapfile, nil)
	if err != nil {
		return err
	}
	key, err := k.ToRaw()
	if err != nil {
		return err
	}
	return m.Delete(key)
}

func Flush(mapfile string) error {
	m, err := ebpf.LoadPinnedMap(mapfile, nil)
	if err != nil {
		return errors.Wrap(err, "ebpf.LoadPinnedMap")
	}

	if m.Type() == ebpf.Array || m.Type() == ebpf.PerCPUArray {
		return nil
	}

	// Parse
	key := []byte{}
	val := []byte{}
	iterate := m.Iterate()
	for iterate.Next(&key, &val) {
		if err := m.Delete(key); err != nil {
			return errors.Wrap(err, "m.Delete")
		}
	}
	return nil
}

func Size(mapfile string) (uint32, error) {
	m, err := ebpf.LoadPinnedMap(mapfile, nil)
	if err != nil {
		return 0, errors.Wrap(err, "ebpf.LoadPinnedMap")
	}
	cnt := uint32(0)
	key := []byte{}
	val := []byte{}
	iterate := m.Iterate()
	for iterate.Next(&key, &val) {
		cnt++
	}
	return cnt, nil
}
