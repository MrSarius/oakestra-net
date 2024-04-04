package networkFunctionManager

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

func (e *NetworkFunctionManager) AttachNetworkFunction(fn NetworkFunction) {
	fn.Attach()
}
