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

func New() PacketCounter {
	return PacketCounter{
		EBPFNetworkFunction: ebpfNetworkFunctions.EBPFNetworkFunction{},
	}
}

// Attach attaches the eBPF program to the specified network interface.
func (e *PacketCounter) LoadAndAttach() error {

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs packetCounterObjects
	if err := loadPacketCounterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	e.Program = objs.CountPackets
	e.pktCount = objs.PktCount

	e.EBPFNetworkFunction.Attach()

	//log.Printf("Counting incoming packets on %s..", "eth0")

	return nil
}
