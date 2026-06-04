package decode

import (
	"testing"
	"time"
)

func TestEthernetIPv4TCP(t *testing.T) {
	packet := []byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
		0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0,
		10, 0, 0, 1, 172, 16, 0, 2,
		0x30, 0x39, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0, 0, 0, 0, 0, 0,
	}
	meta, ok := Ethernet("test-source", "eth-test", packet, time.Unix(100, 0))
	if !ok {
		t.Fatal("expected packet to decode")
	}
	if meta.SrcIP != "10.0.0.1" || meta.DstIP != "172.16.0.2" {
		t.Fatalf("unexpected IPs: %s -> %s", meta.SrcIP, meta.DstIP)
	}
	if meta.SrcPort != 12345 || meta.DstPort != 443 || meta.Proto != 6 {
		t.Fatalf("unexpected transport fields: proto=%d src=%d dst=%d", meta.Proto, meta.SrcPort, meta.DstPort)
	}
	if meta.Ts != 100 || meta.SourceID != "test-source" || meta.Iface != "eth-test" {
		t.Fatalf("unexpected metadata: %+v", meta)
	}
}

func TestCompileFilter(t *testing.T) {
	packet := []byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
		0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0,
		10, 0, 0, 1, 172, 16, 0, 2,
		0x30, 0x39, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0, 0, 0, 0, 0, 0,
	}
	meta, ok := Ethernet("test-source", "eth-test", packet, time.Unix(100, 0))
	if !ok {
		t.Fatal("expected packet to decode")
	}
	cases := map[string]bool{
		"ip or ip6":         true,
		"tcp and port 443":  true,
		"udp":               false,
		"src host 10.0.0.1": true,
		"dst host 10.0.0.1": false,
		"src port 12345":    true,
		"dst port 12345":    false,
		"host 172.16.0.2":   true,
	}
	for expr, want := range cases {
		if got := CompileFilter(expr)(meta); got != want {
			t.Fatalf("filter %q got %v want %v", expr, got, want)
		}
	}
}

func TestEthernetVLANIPv4DSCP(t *testing.T) {
	packet := []byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x81, 0x00,
		0x00, 0x64, 0x08, 0x00,
		0x45, 0x29, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0,
		10, 0, 0, 1, 172, 16, 0, 2,
		0x30, 0x39, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0, 0, 0, 0, 0, 0,
	}
	meta, ok := Ethernet("test-source", "eth-test", packet, time.Unix(100, 0))
	if !ok {
		t.Fatal("expected packet to decode")
	}
	if meta.VLANID != 100 {
		t.Fatalf("unexpected VLAN ID: %d", meta.VLANID)
	}
	if meta.DSCP != 10 || meta.ECN != 1 {
		t.Fatalf("unexpected QoS fields: dscp=%d ecn=%d", meta.DSCP, meta.ECN)
	}
}
