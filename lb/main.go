package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func initMaps(objs *lbObjects) error {
	var idxKey uint32 = 0
	var idxVal uint32 = 0
	if err := objs.lbMaps.IndexMap.Update(&idxKey, &idxVal, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("init index_map: %w", err)
	}

	var firstBackendIp uint32 = 2
	backendSize := uint32(objs.BackendCircArray.MaxEntries())
	for i := uint32(0); i < backendSize; i++ {
    	v := firstBackendIp
		if err := objs.BackendCircArray.Update(&i, &v, ebpf.UpdateAny); err != nil {
			return err
		}
		firstBackendIp++
	}

	return nil
}

// go generate && go build && sudo ./ebpf-test
func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs lbObjects
	if err := loadLbObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	initMaps(&objs)

	ifname := "eth0"
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// Attach count_packets to the network interface.
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.Lb,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer link.Close()

	log.Printf("Counting incoming packets on %s..", ifname)

	// Periodically fetch the packet counter from PktCount,
	// exit the program when interrupted.
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for range stop {
		log.Print("Received signal, exiting..")
		return
	}
}
