package pcap

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"nexaflow/internal/capture/decode"
	"nexaflow/internal/model"
)

const (
	magicPcapLE       = 0xa1b2c3d4
	magicPcapBE       = 0xd4c3b2a1
	linkTypeEthernet  = 1
	globalHeaderBytes = 24
	packetHeaderBytes = 16
)

type Replay struct {
	SourceID  string
	Iface     string
	File      string
	Speed     float64
	BPFFilter string
}

func New(sourceID, iface, file string, speed float64, bpfFilter string) *Replay {
	if speed <= 0 {
		speed = 1
	}
	return &Replay{SourceID: sourceID, Iface: iface, File: file, Speed: speed, BPFFilter: bpfFilter}
}

func (r *Replay) Run(ctx context.Context, out chan<- model.PacketMeta) error {
	if r.File == "" {
		return fmt.Errorf("pcap file is required")
	}
	file, err := os.Open(r.File)
	if err != nil {
		return fmt.Errorf("open pcap file %s: %w", r.File, err)
	}
	defer file.Close()

	header := make([]byte, globalHeaderBytes)
	if _, err := io.ReadFull(file, header); err != nil {
		return fmt.Errorf("read pcap global header: %w", err)
	}
	order, err := byteOrder(header)
	if err != nil {
		return err
	}
	if linkType := order.Uint32(header[20:24]); linkType != linkTypeEthernet {
		return fmt.Errorf("unsupported pcap link type %d", linkType)
	}

	matcher := decode.CompileFilter(r.BPFFilter)
	var firstCaptureTS time.Time
	var firstReplayTS time.Time
	log.Printf("pcap replay started file=%s speed=%.2fx filter=%q", r.File, r.Speed, r.BPFFilter)

	for {
		recordHeader := make([]byte, packetHeaderBytes)
		if _, err := io.ReadFull(file, recordHeader); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil
			}
			return fmt.Errorf("read pcap packet header: %w", err)
		}
		sec := int64(order.Uint32(recordHeader[0:4]))
		usec := int64(order.Uint32(recordHeader[4:8]))
		captureTS := time.Unix(sec, usec*1000)
		includedLen := order.Uint32(recordHeader[8:12])
		if includedLen == 0 || includedLen > 10*1024*1024 {
			return fmt.Errorf("invalid pcap packet length %d", includedLen)
		}
		packet := make([]byte, includedLen)
		if _, err := io.ReadFull(file, packet); err != nil {
			return fmt.Errorf("read pcap packet body: %w", err)
		}

		if firstCaptureTS.IsZero() {
			firstCaptureTS = captureTS
			firstReplayTS = time.Now()
		}
		target := firstReplayTS.Add(time.Duration(float64(captureTS.Sub(firstCaptureTS)) / r.Speed))
		if wait := time.Until(target); wait > 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(wait):
			}
		}

		meta, ok := decode.Ethernet(r.SourceID, r.Iface, packet, time.Now())
		if !ok || !matcher(meta) {
			continue
		}
		select {
		case out <- meta:
		case <-ctx.Done():
			return nil
		}
	}
}

func byteOrder(header []byte) (binary.ByteOrder, error) {
	switch binary.LittleEndian.Uint32(header[:4]) {
	case magicPcapLE:
		return binary.LittleEndian, nil
	case magicPcapBE:
		return binary.BigEndian, nil
	default:
		return nil, fmt.Errorf("unsupported pcap magic 0x%x", binary.LittleEndian.Uint32(header[:4]))
	}
}
