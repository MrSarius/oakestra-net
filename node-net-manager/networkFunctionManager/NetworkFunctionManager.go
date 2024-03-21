package networkFunctionManager

type NetworkFunction interface {
	Attach(interfaceName string) error
	Detach() error
	IsActive() bool
}
