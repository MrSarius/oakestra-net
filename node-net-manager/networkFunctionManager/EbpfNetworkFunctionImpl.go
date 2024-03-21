package networkFunctionManager

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"log"
	"net"
)

type eBPFNetworkFunction struct {
	program  *ebpf.Program
	link     link.Link
	attached bool
}

func NewEBPFNetworkFunction(fileName string) (*eBPFNetworkFunction, error) {
	// Load eBPF program from an ELF file
	objs, err := ebpf.LoadCollection(fileName)
	if err != nil {
		return nil, err
	}

	// Assuming the eBPF program is named "my_program" within the ELF file.
	// Adjust the name based on your actual eBPF program's name.
	prog, ok := objs.Programs["my_program"]
	if !ok {
		return nil, err
	}

	return &eBPFNetworkFunction{program: prog}, nil
}

// Attach attaches the eBPF program to the specified network interface.
func (e *eBPFNetworkFunction) Attach(interfaceName string) error {
	var err error

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", interfaceName, err)
	}

	e.link, err = link.AttachXDP(link.XDPOptions{
		Program:   e.program,
		Interface: iface.Index,
	})
	if err != nil {
		return err
	}
	e.attached = true
	return nil
}

// Detach detaches the eBPF program from the network interface.
func (e *eBPFNetworkFunction) Detach() error {
	if e.attached && e.link != nil {
		err := e.link.Close()
		if err != nil {
			return err
		}
		e.attached = false
	}
	return nil
}

// IsActive returns true if the eBPF program is attached to a network interface.
func (e *eBPFNetworkFunction) IsActive() bool {
	return e.attached
}
