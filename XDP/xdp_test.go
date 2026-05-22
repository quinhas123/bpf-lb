package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf/rlimit"
)

// XDP action codes (uapi/linux/bpf.h).
const (
	xdpAborted = iota
	xdpDrop
	xdpPass
	xdpTx
	xdpRedirect
)

// Loopback test addresses. Must match xdp.c (IP(x) = 127.0.0.x, VIP = 127.0.0.1)
// and the backend pool below.
var (
	vip      = net.IPv4(127, 0, 0, 1).To4()
	backend0 = net.IPv4(127, 0, 0, 2).To4() // first slot -> first round-robin pick
	clientIP = net.IPv4(127, 0, 0, 50).To4()

	clientMAC = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x50}
	lbMAC     = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}
	zeroMAC   = net.HardwareAddr{0, 0, 0, 0, 0, 0}
)

const (
	clientPort  = 12345
	servicePort = 80
)

// Offsets within the crafted Ethernet+IPv4+TCP packet.
const (
	ethLen = 14
	ipLen  = 20
	tcpLen = 20
)

func TestXDPLoadBalance(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("BPF_PROG_TEST_RUN requires root / CAP_BPF; run with sudo")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock: %v", err)
	}

	var objs xdpObjects
	if err := loadXdpObjects(&objs, nil); err != nil {
		t.Fatalf("load eBPF objects: %v", err)
	}
	defer objs.Close()

	servers := []server{
		{IP: "127.0.0.2", MAC: "00:00:00:00:00:00"},
		{IP: "127.0.0.3", MAC: "00:00:00:00:00:00"},
	}
	if err := populateBackends(&objs, servers); err != nil {
		t.Fatalf("populate backends: %v", err)
	}

	// --- Forward: client -> VIP, expect DNAT to the first backend. ---
	fwd := buildTCPPacket(clientMAC, lbMAC, clientIP, vip, clientPort, servicePort)
	verdict, out, err := objs.XdpIngress.Test(fwd)
	if err != nil {
		t.Fatalf("forward run: %v", err)
	}
	out = out[:len(fwd)]

	if verdict != xdpTx {
		t.Fatalf("forward: verdict = %d, want XDP_TX (%d)", verdict, xdpTx)
	}
	ip, tcp := out[ethLen:ethLen+ipLen], out[ethLen+ipLen:ethLen+ipLen+tcpLen]
	if gotDst := net.IP(ip[16:20]); !gotDst.Equal(backend0) {
		t.Errorf("forward: dst IP = %v, want backend %v", gotDst, backend0)
	}
	if !ipChecksumValid(ip) {
		t.Error("forward: IPv4 checksum invalid after DNAT")
	}
	if !tcpChecksumValid(ip[12:16], ip[16:20], tcp) {
		t.Error("forward: TCP checksum invalid after DNAT")
	}
	if !bytes.Equal(out[0:6], zeroMAC) {
		t.Errorf("forward: dst MAC = %x, want backend MAC %x", out[0:6], zeroMAC)
	}

	// --- Reverse: backend reply -> client, expect source restored to VIP and
	// the frame sent back to the return MAC captured on the forward pass. ---
	rev := buildTCPPacket(zeroMAC, lbMAC, backend0, clientIP, servicePort, clientPort)
	verdict, out, err = objs.XdpIngress.Test(rev)
	if err != nil {
		t.Fatalf("reverse run: %v", err)
	}
	out = out[:len(rev)]

	if verdict != xdpTx {
		t.Fatalf("reverse: verdict = %d, want XDP_TX (%d)", verdict, xdpTx)
	}
	ip, tcp = out[ethLen:ethLen+ipLen], out[ethLen+ipLen:ethLen+ipLen+tcpLen]
	if gotSrc := net.IP(ip[12:16]); !gotSrc.Equal(vip) {
		t.Errorf("reverse: src IP = %v, want VIP %v", gotSrc, vip)
	}
	if !ipChecksumValid(ip) {
		t.Error("reverse: IPv4 checksum invalid after un-NAT")
	}
	if !tcpChecksumValid(ip[12:16], ip[16:20], tcp) {
		t.Error("reverse: TCP checksum invalid after un-NAT")
	}
	if !bytes.Equal(out[0:6], clientMAC) {
		t.Errorf("reverse: dst MAC = %x, want stored client MAC %x", out[0:6], clientMAC)
	}
}

// buildTCPPacket assembles an Ethernet+IPv4+TCP frame with valid IP and TCP
// checksums.
func buildTCPPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, sport, dport uint16) []byte {
	pkt := make([]byte, ethLen+ipLen+tcpLen)

	// Ethernet
	copy(pkt[0:6], dstMAC)
	copy(pkt[6:12], srcMAC)
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800) // ETH_P_IP

	// IPv4
	ip := pkt[ethLen : ethLen+ipLen]
	ip[0] = 0x45 // version 4, IHL 5 (20 bytes)
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLen+tcpLen))
	ip[8] = 64 // TTL
	ip[9] = 6  // IPPROTO_TCP
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(ip[10:12], ipChecksum(ip))

	// TCP
	tcp := pkt[ethLen+ipLen : ethLen+ipLen+tcpLen]
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	tcp[12] = 5 << 4                               // data offset 5 (20 bytes)
	tcp[13] = 0x02                                 // SYN
	binary.BigEndian.PutUint16(tcp[14:16], 0xffff) // window
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(srcIP.To4(), dstIP.To4(), tcp))

	return pkt
}

// onesComplementSum accumulates 16-bit big-endian words into a running sum.
func onesComplementSum(data []byte, sum uint32) uint32 {
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	return sum
}

// fold collapses the 32-bit sum to the final 16-bit ones-complement checksum.
func fold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ipChecksum computes the IPv4 header checksum (its checksum field must be 0).
func ipChecksum(hdr []byte) uint16 {
	return fold(onesComplementSum(hdr, 0))
}

// ipChecksumValid returns true if the header (including its checksum) sums to 0.
func ipChecksumValid(hdr []byte) bool {
	return fold(onesComplementSum(hdr, 0)) == 0
}

// tcpPseudoSum is the IPv4 TCP pseudo-header contribution to the checksum.
func tcpPseudoSum(srcIP, dstIP []byte, tcpSegLen int) uint32 {
	var ph [12]byte
	copy(ph[0:4], srcIP)
	copy(ph[4:8], dstIP)
	ph[9] = 6 // IPPROTO_TCP
	binary.BigEndian.PutUint16(ph[10:12], uint16(tcpSegLen))
	return onesComplementSum(ph[:], 0)
}

// tcpChecksum computes the TCP checksum over pseudo-header + segment (the
// segment's checksum field must be 0).
func tcpChecksum(srcIP, dstIP, tcp []byte) uint16 {
	sum := tcpPseudoSum(srcIP, dstIP, len(tcp))
	return fold(onesComplementSum(tcp, sum))
}

// tcpChecksumValid verifies the TCP checksum of an existing segment.
func tcpChecksumValid(srcIP, dstIP, tcp []byte) bool {
	sum := tcpPseudoSum(srcIP, dstIP, len(tcp))
	return fold(onesComplementSum(tcp, sum)) == 0
}
