package bwfilter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"
)

func Attach(iface int) (link.Link, error) {
	objs := bwfilterObjects{}
	if err := loadBwfilterObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	// defer objs.Close()

	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open rtnetlink socket: %v\n", err)
		return nil, err
	}
	defer func() {
		if err := tcnl.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "could not close rtnetlink socket: %v\n", err)
		}
	}()

	qdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface),
			Handle:  core.BuildHandle(tc.HandleRoot, 0),
			Parent:  tc.HandleIngress,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}

	if err := tcnl.Qdisc().Delete(&qdisc); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := tcnl.Qdisc().Add(&qdisc); err != nil {
		fmt.Fprintf(os.Stderr, "could not assign clsact to %d: %v\n", iface, err)
		return nil, err
	}

	for _, e := range []uint32{tc.HandleMinIngress, tc.HandleMinEgress} {
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, syscall.ETH_P_ALL)

		fd := uint32(objs.TcProg.FD())
		flags := uint32(tc.BpfActDirect)
		name := "bwfilter"
		filter := tc.Object{
			Msg: tc.Msg{
				Family:  unix.AF_UNSPEC,
				Ifindex: uint32(iface),
				Handle:  0,
				Parent:  core.BuildHandle(tc.HandleRoot, e),
				Info:    uint32(*(*uint16)(unsafe.Pointer(&b[0]))),
			},
			Attribute: tc.Attribute{
				Kind: "bpf",
				BPF: &tc.Bpf{
					FD:    &fd,
					Flags: &flags,
					Name:  &name,
				},
			},
		}
		if err := tcnl.Filter().Add(&filter); err != nil {
			fmt.Fprintf(os.Stderr, "could not attach filter for eBPF program: %v\n", err)
			return nil, err
		}
	}

	return nil, nil
}
