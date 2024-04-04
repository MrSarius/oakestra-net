package networkFunctionManager

import (
	"NetManager/networkFunctionManager/ebpfNetworkFunctions"
	"NetManager/networkFunctionManager/ebpfNetworkFunctions/packetCounter"
)

type NetworkFunctionManager struct {
	functions []NetworkFunction
}

func New() *NetworkFunctionManager {
	return &NetworkFunctionManager{}
}

func (e *NetworkFunctionManager) DetachAll() {
	for _, nf := range e.functions {
		nf.Detach()
	}
}

// AttachNewPacketCounter this function is just here for prototyping
func (e *NetworkFunctionManager) NewPacketCounter() error {
	counter := packetCounter.PacketCounter{
		EBPFNetworkFunction: ebpfNetworkFunctions.EBPFNetworkFunction{},
	}
	counter.LoadAndAttach()
	return nil
}
