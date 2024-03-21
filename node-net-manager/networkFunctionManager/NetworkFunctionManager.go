package networkFunctionManager

type NetworkFunctionManager struct {
	functions []NetworkFunction
}

func New() *NetworkFunctionManager {
	return &NetworkFunctionManager{}
}

func (m *NetworkFunctionManager) AddFunction(fn NetworkFunction) {
	m.functions = append(m.functions, fn)
}

func (m *NetworkFunctionManager) AttachFunctions(interfaceName string) error {
	for _, fn := range m.functions {
		if err := fn.Attach(interfaceName); err != nil {
			return err
		}
	}
	return nil
}

func (m *NetworkFunctionManager) DetachFunctions() error {
	for _, fn := range m.functions {
		if err := fn.Detach(); err != nil {
			return err
		}
	}
	return nil
}
