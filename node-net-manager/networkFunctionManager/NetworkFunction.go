package networkFunctionManager

// NetworkFunction defines the interface that has to be implemented by all network function. In the future this should help also supporting technologies other than just eBPF.
type NetworkFunction interface {
	Attach() error
	Detach() error
	IsActive() bool
}
