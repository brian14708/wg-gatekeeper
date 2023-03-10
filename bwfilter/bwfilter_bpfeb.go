// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64be || armbe || mips || mips64 || mips64p32 || ppc64 || s390 || s390x || sparc || sparc64
// +build arm64be armbe mips mips64 mips64p32 ppc64 s390 s390x sparc sparc64

package bwfilter

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bwfilterAccountMetric struct {
	BytesIn  uint32
	BytesOut uint32
}

type bwfilterClientInfo struct {
	AccountId          uint32
	ThrottleInRateBps  uint32
	ThrottleOutRateBps uint32
}

// loadBwfilter returns the embedded CollectionSpec for bwfilter.
func loadBwfilter() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BwfilterBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bwfilter: %w", err)
	}

	return spec, err
}

// loadBwfilterObjects loads bwfilter and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bwfilterObjects
//	*bwfilterPrograms
//	*bwfilterMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBwfilterObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBwfilter()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bwfilterSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bwfilterSpecs struct {
	bwfilterProgramSpecs
	bwfilterMapSpecs
}

// bwfilterSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bwfilterProgramSpecs struct {
	TcProg *ebpf.ProgramSpec `ebpf:"tc_prog"`
}

// bwfilterMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bwfilterMapSpecs struct {
	AccountMetricMap *ebpf.MapSpec `ebpf:"account_metric_map"`
	ClientAccountMap *ebpf.MapSpec `ebpf:"client_account_map"`
	FlowMap          *ebpf.MapSpec `ebpf:"flow_map"`
}

// bwfilterObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBwfilterObjects or ebpf.CollectionSpec.LoadAndAssign.
type bwfilterObjects struct {
	bwfilterPrograms
	bwfilterMaps
}

func (o *bwfilterObjects) Close() error {
	return _BwfilterClose(
		&o.bwfilterPrograms,
		&o.bwfilterMaps,
	)
}

// bwfilterMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBwfilterObjects or ebpf.CollectionSpec.LoadAndAssign.
type bwfilterMaps struct {
	AccountMetricMap *ebpf.Map `ebpf:"account_metric_map"`
	ClientAccountMap *ebpf.Map `ebpf:"client_account_map"`
	FlowMap          *ebpf.Map `ebpf:"flow_map"`
}

func (m *bwfilterMaps) Close() error {
	return _BwfilterClose(
		m.AccountMetricMap,
		m.ClientAccountMap,
		m.FlowMap,
	)
}

// bwfilterPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBwfilterObjects or ebpf.CollectionSpec.LoadAndAssign.
type bwfilterPrograms struct {
	TcProg *ebpf.Program `ebpf:"tc_prog"`
}

func (p *bwfilterPrograms) Close() error {
	return _BwfilterClose(
		p.TcProg,
	)
}

func _BwfilterClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bwfilter_bpfeb.o
var _BwfilterBytes []byte
