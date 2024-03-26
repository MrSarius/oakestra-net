package packetCounter

import (
	"NetManager/networkFunctionManager/ebpfNetworkFunctions"
	"github.com/cilium/ebpf"
	"log"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go packetCounter ./packetCounter.c

type PacketCounter struct {
	ebpfNetworkFunctions.EBPFNetworkFunction
	pktCount *ebpf.Map
}

// Attach attaches the eBPF program to the specified network interface.
func (e *PacketCounter) LoadAndAttach() error {

	/*
		// Remove resource limits for kernels <5.11.
		if err := rlimit.RemoveMemlock(); err != nil {
			log.Fatal("Removing memlock:", err)
		}
	*/

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs packetCounterObjects
	if err := loadPacketCounterObjects(&objs, nil); err != nil {
		log.Fatal("Loadinsg eBPF objects:", err)
	}
	defer objs.Close()

	e.Program = objs.CountPackets
	e.pktCount = objs.PktCount

	e.EBPFNetworkFunction.Attach()

	//log.Printf("Counting incoming packets on %s..", "eth0")

	return nil
}

// Idea for the control plane: Configure an FD where the amount of packets is written.
