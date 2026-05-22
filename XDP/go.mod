module bpf-lb

go 1.25.4

require (
	github.com/cilium/ebpf v0.20.0
	gopkg.in/yaml.v3 v3.0.1
)

require golang.org/x/sys v0.37.0 // indirect

tool github.com/cilium/ebpf/cmd/bpf2go
