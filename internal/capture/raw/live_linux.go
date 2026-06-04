//go:build linux

package raw

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"nexaflow/internal/model"
)

const (
	ethPAll  = 0x0003
	ethIPv4  = 0x0800
	ethIPv6  = 0x86dd
	ethVLAN  = 0x8100
	ethQinQ  = 0x88a8
	protoTCP = 6
	protoUDP = 17
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
	matcher := compileFilter(c.BPFFilter)
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
		meta, ok := decodeEthernet(c.SourceID, c.Iface, buf[:n])
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

func decodeEthernet(sourceID, iface string, pkt []byte) (model.PacketMeta, bool) {
	if len(pkt) < 14 {
		return model.PacketMeta{}, false
	}
	etherType := binary.BigEndian.Uint16(pkt[12:14])
	offset := 14
	if etherType == ethVLAN || etherType == ethQinQ {
		if len(pkt) < 18 {
			return model.PacketMeta{}, false
		}
		etherType = binary.BigEndian.Uint16(pkt[16:18])
		offset = 18
	}

	meta := model.PacketMeta{
		Ts:       time.Now().Unix(),
		SourceID: sourceID,
		Iface:    iface,
		Length:   uint32(len(pkt)),
	}

	switch etherType {
	case ethIPv4:
		return decodeIPv4(meta, pkt[offset:])
	case ethIPv6:
		return decodeIPv6(meta, pkt[offset:])
	default:
		return model.PacketMeta{}, false
	}
}

func decodeIPv4(meta model.PacketMeta, pkt []byte) (model.PacketMeta, bool) {
	if len(pkt) < 20 {
		return model.PacketMeta{}, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return model.PacketMeta{}, false
	}
	meta.Proto = pkt[9]
	meta.SrcIP = net.IP(pkt[12:16]).String()
	meta.DstIP = net.IP(pkt[16:20]).String()
	parsePorts(&meta, pkt[ihl:])
	return meta, keep(meta)
}

func decodeIPv6(meta model.PacketMeta, pkt []byte) (model.PacketMeta, bool) {
	if len(pkt) < 40 {
		return model.PacketMeta{}, false
	}
	meta.Proto = pkt[6]
	meta.SrcIP = net.IP(pkt[8:24]).String()
	meta.DstIP = net.IP(pkt[24:40]).String()
	parsePorts(&meta, pkt[40:])
	return meta, keep(meta)
}

func parsePorts(meta *model.PacketMeta, payload []byte) {
	if len(payload) < 4 {
		return
	}
	if meta.Proto == protoTCP || meta.Proto == protoUDP {
		meta.SrcPort = binary.BigEndian.Uint16(payload[0:2])
		meta.DstPort = binary.BigEndian.Uint16(payload[2:4])
	}
}

func keep(meta model.PacketMeta) bool {
	src := net.ParseIP(meta.SrcIP)
	dst := net.ParseIP(meta.DstIP)
	if src == nil || dst == nil {
		return false
	}
	return !src.IsLoopback() && !src.IsUnspecified() && !dst.IsLoopback() && !dst.IsUnspecified()
}

type packetMatcher func(model.PacketMeta) bool

func compileFilter(expr string) packetMatcher {
	expr = strings.TrimSpace(strings.ToLower(expr))
	if expr == "" || expr == "ip" || expr == "ip6" || expr == "ip or ip6" || expr == "ip6 or ip" {
		return func(model.PacketMeta) bool { return true }
	}
	orParts := splitExpr(expr, "or")
	orMatchers := make([]packetMatcher, 0, len(orParts))
	for _, part := range orParts {
		andParts := splitExpr(part, "and")
		andMatchers := make([]packetMatcher, 0, len(andParts))
		for _, clause := range andParts {
			andMatchers = append(andMatchers, compileClause(clause))
		}
		orMatchers = append(orMatchers, func(meta model.PacketMeta) bool {
			for _, matcher := range andMatchers {
				if !matcher(meta) {
					return false
				}
			}
			return true
		})
	}
	return func(meta model.PacketMeta) bool {
		for _, matcher := range orMatchers {
			if matcher(meta) {
				return true
			}
		}
		return false
	}
}

func splitExpr(expr, op string) []string {
	tokens := strings.Fields(expr)
	parts := []string{}
	start := 0
	for i, token := range tokens {
		if token == op {
			if i > start {
				parts = append(parts, strings.Join(tokens[start:i], " "))
			}
			start = i + 1
		}
	}
	if start < len(tokens) {
		parts = append(parts, strings.Join(tokens[start:], " "))
	}
	if len(parts) == 0 {
		return []string{expr}
	}
	return parts
}

func compileClause(clause string) packetMatcher {
	tokens := strings.Fields(clause)
	matchers := []packetMatcher{}
	for i := 0; i < len(tokens); i++ {
		switch tokens[i] {
		case "ip", "ip6":
			continue
		case "tcp":
			matchers = append(matchers, protoMatcher(protoTCP))
		case "udp":
			matchers = append(matchers, protoMatcher(protoUDP))
		case "icmp":
			matchers = append(matchers, protoMatcher(1))
		case "host":
			if i+1 < len(tokens) {
				ip := tokens[i+1]
				matchers = append(matchers, func(meta model.PacketMeta) bool { return meta.SrcIP == ip || meta.DstIP == ip })
				i++
			}
		case "port":
			if i+1 < len(tokens) {
				if port, err := strconv.Atoi(tokens[i+1]); err == nil {
					matchers = append(matchers, func(meta model.PacketMeta) bool { return int(meta.SrcPort) == port || int(meta.DstPort) == port })
				}
				i++
			}
		case "src", "dst":
			if i+2 < len(tokens) {
				dir := tokens[i]
				field := tokens[i+1]
				value := tokens[i+2]
				if field == "host" {
					matchers = append(matchers, hostMatcher(dir, value))
					i += 2
				} else if field == "port" {
					if port, err := strconv.Atoi(value); err == nil {
						matchers = append(matchers, portMatcher(dir, port))
					}
					i += 2
				}
			}
		}
	}
	if len(matchers) == 0 {
		return func(model.PacketMeta) bool { return true }
	}
	return func(meta model.PacketMeta) bool {
		for _, matcher := range matchers {
			if !matcher(meta) {
				return false
			}
		}
		return true
	}
}

func protoMatcher(proto uint8) packetMatcher {
	return func(meta model.PacketMeta) bool { return meta.Proto == proto }
}

func hostMatcher(dir, ip string) packetMatcher {
	return func(meta model.PacketMeta) bool {
		if dir == "src" {
			return meta.SrcIP == ip
		}
		return meta.DstIP == ip
	}
}

func portMatcher(dir string, port int) packetMatcher {
	return func(meta model.PacketMeta) bool {
		if dir == "src" {
			return int(meta.SrcPort) == port
		}
		return int(meta.DstPort) == port
	}
}

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}
