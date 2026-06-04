//go:build !linux

package raw

import (
	"context"
	"fmt"

	"nexaflow/internal/model"
)

type LiveCapture struct {
	SourceID  string
	Iface     string
	BPFFilter string
}

func NewLive(sourceID, iface, bpfFilter string) *LiveCapture {
	return &LiveCapture{SourceID: sourceID, Iface: iface, BPFFilter: bpfFilter}
}

func (c *LiveCapture) Run(_ context.Context, _ chan<- model.PacketMeta) error {
	return fmt.Errorf("live_pcap mode is only supported on Linux")
}
