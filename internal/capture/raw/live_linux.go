//go:build linux

package raw

import (
	"context"
	"fmt"
	"log"
	"net"
	"syscall"
	"time"

	"nexaflow/internal/capture/decode"
	"nexaflow/internal/model"
)

const (
	ethPAll = 0x0003
)

type LiveCapture struct {
	SourceID  string
	Iface     string
	BPFFilter string
}

func NewLive(sourceID, iface, bpfFilter string) *LiveCapture {
	return &LiveCapture{SourceID: sourceID, Iface: iface, BPFFilter: bpfFilter}
}

func (c *LiveCapture) Run(ctx context.Context, out chan<- model.PacketMeta) error {
	matcher := decode.CompileFilter(c.BPFFilter)
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return fmt.Errorf("open raw packet socket: %w", err)
	}
	defer syscall.Close(fd)
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 1}); err != nil {
		return fmt.Errorf("set receive timeout: %w", err)
	}

	if c.Iface != "" && c.Iface != "any" {
		iface, err := net.InterfaceByName(c.Iface)
		if err != nil {
			return fmt.Errorf("find interface %s: %w", c.Iface, err)
		}
		if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{
			Protocol: htons(ethPAll),
			Ifindex:  iface.Index,
		}); err != nil {
			return fmt.Errorf("bind interface %s: %w", c.Iface, err)
		}
	}

	log.Printf("live raw capture started iface=%s filter=%q", c.Iface, c.BPFFilter)
	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EINTR || err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				continue
			}
			return fmt.Errorf("recv packet: %w", err)
		}
		meta, ok := decode.Ethernet(c.SourceID, c.Iface, buf[:n], time.Now())
		if !ok {
			continue
		}
		if !matcher(meta) {
			continue
		}
		select {
		case out <- meta:
		case <-ctx.Done():
			return nil
		}
	}
}

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}
