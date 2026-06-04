package mock

import (
	"context"
	"math/rand"
	"time"

	"nexaflow/internal/model"
)

type Generator struct {
	SourceID string
	Iface    string
	Rand     *rand.Rand
}

func New(sourceID, iface string) *Generator {
	return &Generator{
		SourceID: sourceID,
		Iface:    iface,
		Rand:     rand.New(rand.NewSource(42)),
	}
}

func (g *Generator) Run(ctx context.Context, out chan<- model.PacketMeta) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			for i := 0; i < 120; i++ {
				out <- g.packet(now)
			}
		}
	}
}

func (g *Generator) packet(now time.Time) model.PacketMeta {
	protos := []uint8{6, 6, 6, 17, 17, 1}
	ports := []uint16{443, 443, 80, 53, 22, 3306, 6379, 8080}
	srcHost := 10 + g.Rand.Intn(180)
	dstHost := 1 + g.Rand.Intn(220)
	length := 64 + g.Rand.Intn(1400)

	if g.Rand.Intn(100) < 12 {
		length += 6000
		srcHost = 42
	}

	return model.PacketMeta{
		Ts:       now.Unix(),
		SourceID: g.SourceID,
		Iface:    g.Iface,
		SrcIP:    "10.10.1." + itoa(srcHost),
		DstIP:    "172.20.2." + itoa(dstHost),
		SrcPort:  uint16(30000 + g.Rand.Intn(20000)),
		DstPort:  ports[g.Rand.Intn(len(ports))],
		Proto:    protos[g.Rand.Intn(len(protos))],
		Length:   uint32(length),
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

