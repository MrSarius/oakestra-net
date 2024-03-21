package networkFunctionManager

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf/simpleFirewall/simpleFirewall ./ebpf/simpleFirewall/simpleFirewall.c
