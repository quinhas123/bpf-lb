package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"gopkg.in/yaml.v3"
)

type server struct {
	IP     string `yaml:"ip"`
	MAC    string `yaml:"mac"`
	Weight uint16 `yaml:"weight"`
}

type pool struct {
	Servers []server `yaml:"servers"`
}

type config struct {
	Pools map[string]pool `yaml:"pools"`
}

type backendEntry struct {
	IP     uint32
	MAC    [6]byte
	Weight uint16
}

var l7Index = map[string]xdpL7Proto{
	"http":  xdpL7ProtoL7HTTP,
	"https": xdpL7ProtoL7HTTPS,
	"dns":   xdpL7ProtoL7DNS,
	"ssh":   xdpL7ProtoL7SSH,
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

func populatePools(spec *ebpf.CollectionSpec, objs *xdpObjects, cfg *config) ([]*ebpf.Map, error) {
	poolsSpec, ok := spec.Maps["backend_pools"]
	if !ok || poolsSpec.InnerMap == nil {
		return nil, fmt.Errorf("backend_pools inner map template not found in spec")
	}

	var inners []*ebpf.Map
	for name, p := range cfg.Pools {
		l7, ok := l7Index[name]
		if !ok {
			return inners, fmt.Errorf("unknown L7 pool %q (want http/https/dns/ssh)", name)
		}
		if len(p.Servers) == 0 {
			continue
		}

		inner, err := ebpf.NewMap(poolsSpec.InnerMap)
		if err != nil {
			return inners, fmt.Errorf("pool %q: creating inner map: %w", name, err)
		}
		inners = append(inners, inner)

		var total uint32
		for i, s := range p.Servers {
			b, err := backendValue(s, i)
			if err != nil {
				return inners, fmt.Errorf("pool %q: %w", name, err)
			}
			if err := inner.Put(uint32(i), &b); err != nil {
				return inners, fmt.Errorf("pool %q: writing backend %d: %w", name, i, err)
			}
			total += uint32(b.Weight)
		}

		if err := objs.BackendPools.Put(l7, inner); err != nil {
			return inners, fmt.Errorf("pool %q: inserting into backend_pools: %w", name, err)
		}
		count := uint32(len(p.Servers))
		if err := objs.BackendCount.Put(l7, &count); err != nil {
			return inners, fmt.Errorf("pool %q: writing backend count: %w", name, err)
		}
		if err := objs.TotalWeight.Put(l7, &total); err != nil {
			return inners, fmt.Errorf("pool %q: writing total weight: %w", name, err)
		}
	}
	return inners, nil
}

// backendValue converts a config server entry into the eBPF backend struct.
func backendValue(s server, idx int) (backendEntry, error) {
	ip := net.ParseIP(s.IP)
	if ip == nil || ip.To4() == nil {
		return backendEntry{}, fmt.Errorf("backend %d: invalid IPv4 address %q", idx, s.IP)
	}
	mac, err := net.ParseMAC(s.MAC)
	if err != nil {
		return backendEntry{}, fmt.Errorf("backend %d: invalid MAC %q: %w", idx, s.MAC, err)
	}
	if len(mac) != 6 {
		return backendEntry{}, fmt.Errorf("backend %d: MAC %q is not 6 bytes", idx, s.MAC)
	}

	weight := s.Weight
	if weight == 0 {
		weight = 1
	}

	// eBPF side stores the IP as __be32 (network byte order)
	b := backendEntry{
		IP:     binary.LittleEndian.Uint32(ip.To4()),
		Weight: weight,
	}
	copy(b.MAC[:], mac)
	return b, nil
}
