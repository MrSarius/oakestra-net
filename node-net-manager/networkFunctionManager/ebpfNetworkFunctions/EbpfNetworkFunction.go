package ebpfNetworkFunctions

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"net"
)

type EBPFNetworkFunction struct {
	ID          string        // Unique identifier
	Description string        // Description of what the function does
	Program     *ebpf.Program // ebpf Program pointer
	Link        link.Link
	Attached    bool // if the Program is currently Attached to the interface
}

// Attach attaches the eBPF program to the specified network interface.
func (e *EBPFNetworkFunction) Attach() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	iface, err := net.InterfaceByName("eth0") // TODO find a sleek way to dynamically find the name of the interface
	if err != nil {
		log.Fatalf("Getting interface %s: %s", iface, err)
	}

	fmt.Printf("%p\n", e.Program)
	e.Link, err = link.AttachXDP(link.XDPOptions{
		Program:   e.Program,
		Interface: iface.Index,
	})

	if err != nil {
		log.Fatal("Attaching XDP:", err)
		return err
	}

	e.Attached = true
	return nil
}

// Detach detaches the eBPF Program from the network interface.
func (e *EBPFNetworkFunction) Detach() error {
	if e.Attached && e.Link != nil {
		err := e.Link.Close()
		if err != nil {
			return err
		}
		e.Attached = false
	}
	return nil
}

// IsActive returns true if the eBPF Program is Attached to a network interface.
func (e *EBPFNetworkFunction) IsActive() bool {
	return e.Attached
}
