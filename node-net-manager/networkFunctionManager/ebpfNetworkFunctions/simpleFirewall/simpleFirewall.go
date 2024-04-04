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
}

type Allow int

const (
	// AllowTCP allows only TCP traffic.
	Block int = iota
	AllowTCP
	// AllowUDP allows only UDP traffic.
	AllowUDP
	// AllowBoth allows both TCP and UDP traffic.
	AllowBoth
)

func (e *SimpleFirewall) AddFirewallRule(allow Allow, port uint16) {
	err := e.allowedPorts.Update(port, &simpleFirewallPortProtocol{Port: port, Protocol: uint8(allow)}, ebpf.UpdateAny)
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

	e.EBPFNetworkFunction.Attach()

	//log.Printf("Counting incoming packets on %s..", "eth0")

	return nil
}
