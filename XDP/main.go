package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	configPath := flag.String("config", "config/backend-server-pools.yaml", "path to the backend pool config")
	ifname := flag.String("iface", "lo", "interface to attach the XDP program to")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatal("Loading config:", err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	spec, err := loadXdp()
	if err != nil {
		log.Fatal("Loading eBPF spec:", err)
	}

	var objs xdpObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	inners, err := populatePools(spec, &objs, cfg)
	for _, m := range inners {
		defer m.Close()
	}
	if err != nil {
		log.Fatal("Populating pools:", err)
	}
	log.Printf("Loaded %d L7 pool(s)", len(inners))

	iface, err := net.InterfaceByName(*ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", *ifname, err)
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpIngress,
		Interface: iface.Index,
		// XDPGenericMode for development
		Flags: link.XDPGenericMode,
	})
	if err != nil {
		log.Fatal("Attaching XDP ingress:", err)
	}
	defer link.Close()

	log.Printf("XDP ingress program attached to %s. Ctrl-C to exit.", *ifname)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Print("Received signal, exiting..")
}
