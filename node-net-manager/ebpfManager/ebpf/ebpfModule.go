package ebpf

import "github.com/gorilla/mux"

type Config struct {
	Name   string      `json:"name"`
	Config interface{} `json:"config"`
}

type Module struct {
	Id     string `json:"id"`
	Config Config `json:"config"`
}

type ModuleInterface interface {
	// Configure Pass its configuration to the module. This is usually the first method to be called.
	Configure(config Config, router *mux.Router) // TODO ben later not a string anymore

	// NewInterfaceCreated notifies the ebpf module that a new interface (+ service) was created
	NewInterfaceCreated(ifname string) error

	// DestroyModule removes deconstructs the module and releases all ressources
	DestroyModule() error
	// TODO ben do we need to tell the module if a service got undeployed?
	// In general and ebpf function get removed when veth is removed. I think a module should be written in a way such that it can handle this

	// TODO ben does it make sense to have a destroy method for each interface?
}