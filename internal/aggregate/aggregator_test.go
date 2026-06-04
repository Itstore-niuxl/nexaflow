package aggregate

import (
	"strconv"
	"testing"
	"time"

	"nexaflow/internal/model"
)

func TestAggregatorKeepsDefaultSessionTopN(t *testing.T) {
	in := make(chan model.PacketMeta)
	out := make(chan model.WindowResult, 1)
	aggregator := New(5*time.Second, 1000, nil)

	go aggregator.Run(in, out)
	for i := 0; i < 620; i++ {
		in <- model.PacketMeta{
			Ts:       100,
			SourceID: "test-source",
			Iface:    "eth0",
			SrcIP:    "10.0.0." + strconv.Itoa(i+1),
			DstIP:    "172.16.0.10",
			SrcPort:  uint16(30000 + i),
			DstPort:  443,
			Proto:    6,
			Length:   uint32(1500 - i),
		}
	}
	close(in)

	window := <-out
	if len(window.TopFlow) != 500 {
		t.Fatalf("expected 500 flow rows, got %d", len(window.TopFlow))
	}
	if len(window.TopPair) != 500 {
		t.Fatalf("expected 500 pair rows, got %d", len(window.TopPair))
	}
	if window.Link.Packets != 620 {
		t.Fatalf("expected 620 packets, got %d", window.Link.Packets)
	}
}

func TestAggregatorUsesRuntimeSessionTopN(t *testing.T) {
	in := make(chan model.PacketMeta)
	out := make(chan model.WindowResult, 1)
	aggregator := New(5*time.Second, 1000, nil)
	aggregator.SessionLimit = func() int { return 80 }

	go aggregator.Run(in, out)
	for i := 0; i < 120; i++ {
		in <- model.PacketMeta{
			Ts:       100,
			SourceID: "test-source",
			Iface:    "eth0",
			SrcIP:    "10.0.1." + strconv.Itoa(i+1),
			DstIP:    "172.16.0.10",
			SrcPort:  uint16(30000 + i),
			DstPort:  443,
			Proto:    6,
			Length:   uint32(1500 - i),
		}
	}
	close(in)

	window := <-out
	if len(window.TopFlow) != 80 {
		t.Fatalf("expected 80 flow rows, got %d", len(window.TopFlow))
	}
	if len(window.TopPair) != 80 {
		t.Fatalf("expected 80 pair rows, got %d", len(window.TopPair))
	}
}
