package main

import (
	"NetManager/ebpfManager"
	"encoding/json"
	"github.com/gorilla/mux"
	"io"
	"net"
	"net/http"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go firewall firewall.c

type FirewallManager struct {
	ebpfManager.ModuleBase
	// maps interface name to firewall
	firewalls map[string]Firewall
	manager   *ebpfManager.EbpfManager
}

func New() ebpfManager.ModuleInterface {
	return &FirewallManager{
		firewalls: make(map[string]Firewall),
	}
}

func (f *FirewallManager) GetModule() *ebpfManager.ModuleBase {
	return &f.ModuleBase
}

func (f *FirewallManager) Configure(config ebpfManager.Config, router *mux.Router, manager *ebpfManager.EbpfManager) {
	f.ModuleBase.Config = config
	f.manager = manager
	router.HandleFunc("/rule", func(writer http.ResponseWriter, request *http.Request) {
		type FirewallRequest struct {
			Proto   string `json:"proto"`
			SrcIp   string `json:"srcIp"`
			DstIp   string `json:"dstIp"`
			SrcPort uint16 `json:"scrPort"`
			DstPort uint16 `json:"dstPort"`
		}

		reqBody, _ := io.ReadAll(request.Body)
		var firewallRequest FirewallRequest
		err := json.Unmarshal(reqBody, &firewallRequest)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
		}

		src := net.ParseIP(firewallRequest.SrcIp).To4()
		dst := net.ParseIP(firewallRequest.DstIp).To4()

		// TODO ben default is always TCP. Does that make sense? + can I add this parsing step to JSON serialiser?
		proto := TCP
		if request.Proto == "UDP" {
			proto = UDP
		} else if request.Proto == "ICMP" {
			proto = ICMP
		}

		f.AddFirewallRule(src, dst, proto, firewallRequest.SrcPort, firewallRequest.DstPort)

		writer.WriteHeader(http.StatusOK)
	})
}

// TODO ben instead of creating one function per Event, pass a Event channel to the module that emits all events
func (f *FirewallManager) NewInterfaceCreated(ifname string) error {
	firewall := Firewall{}
	firewall.Load()
	fdIn := uint32(firewall.FwObjects.HandleIngress.FD())
	fdEg := uint32(firewall.FwObjects.HandleEgress.FD())
	f.manager.AttachEbpf(ifname, fdIn, fdEg)
	f.firewalls[ifname] = firewall
	return nil
}

func (f *FirewallManager) DestroyModule() error {
	for ifname := range f.firewalls {
		f.removeFirewall(ifname)
	}
	return nil
}

func (f *FirewallManager) AddFirewallRule(srcIp net.IP, dstIp net.IP, proto Protocol, srcPort uint16, dstPort uint16) {
	for _, fw := range f.firewalls {
		fw.AddRule(srcIp, dstIp, proto, srcPort, dstPort)
	}
}

func (f *FirewallManager) removeFirewall(ifname string) {
	if _, exists := f.firewalls[ifname]; exists {
		// TODO ben add request unattach to ebpfManager
		delete(f.firewalls, ifname)
	}
}

func main() {}
