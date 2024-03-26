package simpleFirewall

import (
	"NetManager/networkFunctionManager/ebpfNetworkFunctions"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go simpleFirewall simpleFirewall.c

// SimpleFirewall represents the control plane of a simple firewall. It also maintains the underlying eBPF function
type SimpleFirewall struct {
	ebpfNetworkFunctions.EBPFNetworkFunction
	AllowedPorts map[int]bool
}
