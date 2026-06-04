package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	ifname := flag.String("iface", "eth0", "interface to attach the TC egress program to")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	var objs tcObjects
	if err := loadTcObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(*ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", *ifname, err)
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.TcEgress,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Fatal("Attaching TC egress:", err)
	}
	defer l.Close()

	log.Printf("TC egress (DSR source rewrite) attached to %s. Ctrl-C to exit.", *ifname)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Print("Received signal, exiting..")
}
