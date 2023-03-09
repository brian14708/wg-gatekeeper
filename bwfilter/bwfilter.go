package bwfilter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"
)

type Handle struct {
	done chan struct{}
	objs bwfilterObjects

	currClientAccount map[uint32]bwfilterClientInfo
}

func Attach(iface int) (*Handle, error) {
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

	h := &Handle{
		objs: objs,
		done: make(chan struct{}),
	}
	return h, nil
}

func (h *Handle) Close() error {
	close(h.done)
	return h.objs.Close()
}

type ClientAccount struct {
	AccountID    uint32
	BandwidthIn  uint64
	BandwidthOut uint64
}

func (h *Handle) UpdateClientAccount(ca map[string]ClientAccount) error {
	if h.currClientAccount == nil {
		h.currClientAccount = make(map[uint32]bwfilterClientInfo)
		it := h.objs.ClientAccountMap.Iterate()
		var key uint32
		var value bwfilterClientInfo
		for it.Next(&key, &value) {
			h.currClientAccount[key] = value
		}
	}

	keys := make(map[uint32]struct{})
	for k, v := range ca {
		i := binary.BigEndian.Uint32(net.ParseIP(k).To4())
		val := bwfilterClientInfo{
			AccountId:          v.AccountID,
			ThrottleInRateBps:  uint32(v.BandwidthIn),
			ThrottleOutRateBps: uint32(v.BandwidthOut),
		}
		keys[i] = struct{}{}
		if ca, ok := h.currClientAccount[i]; ok {
			if ca == val {
				continue
			}
		}
		if err := h.objs.ClientAccountMap.Update(&i, &val, ebpf.UpdateAny); err != nil {
			return err
		}
		h.currClientAccount[i] = val
	}

	for k := range h.currClientAccount {
		if _, ok := keys[k]; !ok {
			err := h.objs.ClientAccountMap.Delete(&k)
			if err == nil || errors.Is(err, ebpf.ErrKeyNotExist) {
				delete(h.currClientAccount, k)
			} else {
				return err
			}
		}
	}

	return nil
}
