package pcap

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nexaflow/internal/model"
)

func TestReplayClassicPcap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.pcap")
	if err := os.WriteFile(path, samplePcap(), 0o644); err != nil {
		t.Fatal(err)
	}

	packets := make(chan model.PacketMeta, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- New("pcap-test", "replay0", path, 100, "tcp and port 443").Run(context.Background(), packets)
	}()

	select {
	case meta := <-packets:
		if meta.SrcIP != "10.0.0.1" || meta.DstIP != "172.16.0.2" || meta.DstPort != 443 {
			t.Fatalf("unexpected replay metadata: %+v", meta)
		}
	case err := <-errCh:
		t.Fatalf("replay returned before packet: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for replay packet")
	}
}

func samplePcap() []byte {
	packet := []byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
		0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0,
		10, 0, 0, 1, 172, 16, 0, 2,
		0x30, 0x39, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0, 0, 0, 0, 0, 0,
	}
	buf := make([]byte, 24+16+len(packet))
	binary.LittleEndian.PutUint32(buf[0:4], magicPcapLE)
	binary.LittleEndian.PutUint16(buf[4:6], 2)
	binary.LittleEndian.PutUint16(buf[6:8], 4)
	binary.LittleEndian.PutUint32(buf[16:20], 65535)
	binary.LittleEndian.PutUint32(buf[20:24], linkTypeEthernet)
	offset := 24
	binary.LittleEndian.PutUint32(buf[offset:offset+4], 100)
	binary.LittleEndian.PutUint32(buf[offset+8:offset+12], uint32(len(packet)))
	binary.LittleEndian.PutUint32(buf[offset+12:offset+16], uint32(len(packet)))
	copy(buf[offset+16:], packet)
	return buf
}
