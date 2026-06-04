package decode

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"time"

	"nexaflow/internal/model"
)

const (
	ethIPv4  = 0x0800
	ethIPv6  = 0x86dd
	ethVLAN  = 0x8100
	ethQinQ  = 0x88a8
	protoTCP = 6
	protoUDP = 17
)

type Matcher func(model.PacketMeta) bool

func Ethernet(sourceID, iface string, pkt []byte, ts time.Time) (model.PacketMeta, bool) {
	if len(pkt) < 14 {
		return model.PacketMeta{}, false
	}
	etherType := binary.BigEndian.Uint16(pkt[12:14])
	offset := 14
	vlanID := uint16(0)
	if etherType == ethVLAN || etherType == ethQinQ {
		if len(pkt) < 18 {
			return model.PacketMeta{}, false
		}
		tci := binary.BigEndian.Uint16(pkt[14:16])
		vlanID = tci & 0x0fff
		etherType = binary.BigEndian.Uint16(pkt[16:18])
		offset = 18
		if etherType == ethVLAN || etherType == ethQinQ {
			if len(pkt) < 22 {
				return model.PacketMeta{}, false
			}
			etherType = binary.BigEndian.Uint16(pkt[20:22])
			offset = 22
		}
	}

	meta := model.PacketMeta{
		Ts:       ts.Unix(),
		SourceID: sourceID,
		Iface:    iface,
		VLANID:   vlanID,
		Length:   uint32(len(pkt)),
	}

	switch etherType {
	case ethIPv4:
		return ipv4(meta, pkt[offset:])
	case ethIPv6:
		return ipv6(meta, pkt[offset:])
	default:
		return model.PacketMeta{}, false
	}
}

func CompileFilter(expr string) Matcher {
	expr = strings.TrimSpace(strings.ToLower(expr))
	if expr == "" || expr == "ip" || expr == "ip6" || expr == "ip or ip6" || expr == "ip6 or ip" {
		return func(model.PacketMeta) bool { return true }
	}
	orParts := splitExpr(expr, "or")
	orMatchers := make([]Matcher, 0, len(orParts))
	for _, part := range orParts {
		andParts := splitExpr(part, "and")
		andMatchers := make([]Matcher, 0, len(andParts))
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

func ipv4(meta model.PacketMeta, pkt []byte) (model.PacketMeta, bool) {
	if len(pkt) < 20 {
		return model.PacketMeta{}, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return model.PacketMeta{}, false
	}
	meta.Proto = pkt[9]
	meta.DSCP = pkt[1] >> 2
	meta.ECN = pkt[1] & 0x03
	meta.SrcIP = net.IP(pkt[12:16]).String()
	meta.DstIP = net.IP(pkt[16:20]).String()
	parsePorts(&meta, pkt[ihl:])
	return meta, keep(meta)
}

func ipv6(meta model.PacketMeta, pkt []byte) (model.PacketMeta, bool) {
	if len(pkt) < 40 {
		return model.PacketMeta{}, false
	}
	trafficClass := ((pkt[0] & 0x0f) << 4) | (pkt[1] >> 4)
	meta.DSCP = trafficClass >> 2
	meta.ECN = trafficClass & 0x03
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

func compileClause(clause string) Matcher {
	tokens := strings.Fields(clause)
	matchers := []Matcher{}
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

func protoMatcher(proto uint8) Matcher {
	return func(meta model.PacketMeta) bool { return meta.Proto == proto }
}

func hostMatcher(dir, ip string) Matcher {
	return func(meta model.PacketMeta) bool {
		if dir == "src" {
			return meta.SrcIP == ip
		}
		return meta.DstIP == ip
	}
}

func portMatcher(dir string, port int) Matcher {
	return func(meta model.PacketMeta) bool {
		if dir == "src" {
			return int(meta.SrcPort) == port
		}
		return int(meta.DstPort) == port
	}
}
