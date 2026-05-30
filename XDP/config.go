package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

type server struct {
	IP  string `yaml:"ip"`
	MAC string `yaml:"mac"`
}

type pool struct {
	Servers []server `yaml:"servers"`
}

type config struct {
	Pools map[string]pool `yaml:"pools"`
}

func loadConfig(path string) (*config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	var cfg config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	return &cfg, nil
}

func populateBackends(objs *xdpObjects, servers []server) error {
	if len(servers) == 0 {
		return fmt.Errorf("no backends configured")
	}

	for i, s := range servers {
		ip := net.ParseIP(s.IP)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("backend %d: invalid IPv4 address %q", i, s.IP)
		}
		mac, err := net.ParseMAC(s.MAC)
		if err != nil {
			return fmt.Errorf("backend %d: invalid MAC %q: %w", i, s.MAC, err)
		}
		if len(mac) != 6 {
			return fmt.Errorf("backend %d: MAC %q is not 6 bytes", i, s.MAC)
		}

		b := xdpBackend{
			// The eBPF side stores the IP as __be32 (network byte order) and
			// assigns it straight to iph->daddr. The ebpf library marshals
			// struct fields in host byte order, so encode the network-order
			// bytes as a host-order uint32 to land them in memory unchanged.
			Ip: binary.LittleEndian.Uint32(ip.To4()),
		}
		copy(b.Mac[:], mac)

		if err := objs.Backends.Put(uint32(i), &b); err != nil {
			return fmt.Errorf("backend %d: writing map: %w", i, err)
		}
	}

	count := uint32(len(servers))
	if err := objs.BackendCount.Put(uint32(0), &count); err != nil {
		return fmt.Errorf("writing backend count: %w", err)
	}
	return nil
}