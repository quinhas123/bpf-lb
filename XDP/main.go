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
	pool := flag.String("pool", "tcp", "which configured pool to load into the datapath")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatal("Loading config:", err)
	}
	p, ok := cfg.Pools[*pool]
	if !ok {
		log.Fatalf("Pool %q not found in %s", *pool, *configPath)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	var objs xdpObjects
	if err := loadXdpObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	if err := populateBackends(&objs, p.Servers); err != nil {
		log.Fatal("Populating backends:", err)
	}
	log.Printf("Loaded %d backend(s) from pool %q", len(p.Servers), *pool)

	ifname := "lo"
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
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

	log.Printf("XDP ingress program attached to %s. Ctrl-C to exit.", ifname)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Print("Received signal, exiting..")
}
