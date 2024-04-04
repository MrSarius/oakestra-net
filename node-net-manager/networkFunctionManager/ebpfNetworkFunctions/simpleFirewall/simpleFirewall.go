package simpleFirewall

import (
	"NetManager/networkFunctionManager/ebpfNetworkFunctions"
	"fmt"
	"github.com/cilium/ebpf"
	"log"
	"os"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go simpleFirewall simpleFirewall.c

// SimpleFirewall represents the control plane of a simple firewall. It also maintains the underlying eBPF function
type SimpleFirewall struct {
	ebpfNetworkFunctions.EBPFNetworkFunction
	allowedPorts *ebpf.Map
	nextProg     *ebpf.Map
}

type Allow uint8

const (
	// AllowTCP allows only TCP traffic.
	Block int = iota
	AllowTCP
	// AllowUDP allows only UDP traffic.
	AllowUDP
	// AllowBoth allows both TCP and UDP traffic.
	AllowBoth
)

func New() SimpleFirewall {
	return SimpleFirewall{
		EBPFNetworkFunction: ebpfNetworkFunctions.EBPFNetworkFunction{},
	}
}

func (e *SimpleFirewall) Chain(fn ebpfNetworkFunctions.EBPFNetworkFunction) {
	// TODO can chained function already be attached? Initial though would be
	if !e.EBPFNetworkFunction.Attached || e.nextProg == nil || fn.Attached {
		return // TODO error
	}
	// TODO handle the case if value is already set! Is this actually allowed? -> For now its fine...
	if err := e.nextProg.Update(0, uint32(e.Program.FD()), ebpf.UpdateAny); err != nil {
		log.Fatalf("Failed to insert program FD into prog_array map: %v", err)
	}
}

func (e *SimpleFirewall) AddFirewallRule(allow Allow, port uint16) {
	err := e.allowedPorts.Update(port, allow, ebpf.UpdateAny)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to update map: %v\n", err)
		os.Exit(1)
	}
}

func (e *SimpleFirewall) LoadAndAttach() error {

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs simpleFirewallObjects
	if err := loadSimpleFirewallObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	e.Program = objs.SimpleFirewall
	e.allowedPorts = objs.AllowedPorts
	e.allowedPorts = objs.AllowedPorts

	e.EBPFNetworkFunction.Attach()

	return nil
}
