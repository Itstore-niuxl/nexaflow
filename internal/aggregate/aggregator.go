package aggregate

import (
	"sort"
	"strconv"
	"time"

	"nexaflow/internal/config"
	"nexaflow/internal/enrich"
	"nexaflow/internal/model"
)

type Aggregator struct {
	Window        time.Duration
	BandwidthMbps uint64
	SessionTopN   int
	SessionLimit  func() int
	Alerts        func() config.Alerts
}

type counter struct {
	bytes   uint64
	packets uint64
}

func New(window time.Duration, bandwidthMbps uint64, alerts func() config.Alerts) *Aggregator {
	return &Aggregator{Window: window, BandwidthMbps: bandwidthMbps, SessionTopN: 500, Alerts: alerts}
}

func (a *Aggregator) Run(in <-chan model.PacketMeta, out chan<- model.WindowResult) {
	var current int64
	var sourceID string
	var iface string
	link := counter{}
	src := map[string]counter{}
	dst := map[string]counter{}
	ports := map[string]counter{}
	protos := map[string]counter{}
	flows := map[string]counter{}
	pairs := map[string]counter{}
	packetLens := map[string]counter{}
	services := map[string]counter{}
	serviceCategories := map[string]counter{}
	serviceRisks := map[string]counter{}
	vlans := map[string]counter{}
	dscps := map[string]counter{}
	ecns := map[string]counter{}

	flush := func() {
		if current == 0 {
			return
		}
		util := 0.0
		if a.BandwidthMbps > 0 {
			bits := float64(link.bytes * 8)
			capacity := float64(a.BandwidthMbps) * 1000 * 1000 * a.Window.Seconds()
			util = bits / capacity
		}
		sessionTopN := a.sessionTopN()
		result := model.WindowResult{
			Ts:       current,
			SourceID: sourceID,
			Iface:    iface,
			Link: model.LinkWindow{
				Ts:       current,
				SourceID: sourceID,
				Iface:    iface,
				Bytes:    link.bytes,
				Packets:  link.packets,
				Util:     util,
			},
			TopSrcIP:     top(src, 20),
			TopDstIP:     top(dst, 20),
			TopDstPort:   top(ports, 20),
			TopProtocol:  top(protos, 20),
			TopFlow:      top(flows, sessionTopN),
			TopPair:      top(pairs, sessionTopN),
			TopPacketLen: top(packetLens, 20),
			TopService:   top(services, 20),
			TopSvcCat:    top(serviceCategories, 20),
			TopSvcRisk:   top(serviceRisks, 20),
			TopVLAN:      top(vlans, 20),
			TopDSCP:      top(dscps, 20),
			TopECN:       top(ecns, 20),
		}
		policy := a.alerts()
		result.Alerts = append(result.Alerts, anomalyAlerts(result, policy)...)
		if util > policy.LinkUtilization {
			if !isSilenced(policy, sourceID) {
				result.Alerts = append(result.Alerts, model.AlertEvent{
					ID:        "link-util-" + strconv.FormatInt(current, 10),
					Severity:  "warning",
					Status:    "open",
					Subject:   sourceID,
					Summary:   "链路利用率超过阈值 " + strconv.FormatFloat(policy.LinkUtilization*100, 'f', 1, 64) + "%",
					FirstSeen: current,
					LastSeen:  current,
				})
			}
		}
		out <- result
	}

	reset := func(ts int64) {
		current = ts - ts%int64(a.Window.Seconds())
		link = counter{}
		src = map[string]counter{}
		dst = map[string]counter{}
		ports = map[string]counter{}
		protos = map[string]counter{}
		flows = map[string]counter{}
		pairs = map[string]counter{}
		packetLens = map[string]counter{}
		services = map[string]counter{}
		serviceCategories = map[string]counter{}
		serviceRisks = map[string]counter{}
		vlans = map[string]counter{}
		dscps = map[string]counter{}
		ecns = map[string]counter{}
	}

	for pkt := range in {
		win := pkt.Ts - pkt.Ts%int64(a.Window.Seconds())
		if current == 0 {
			reset(pkt.Ts)
		}
		if win != current {
			flush()
			reset(pkt.Ts)
		}
		sourceID = pkt.SourceID
		iface = pkt.Iface
		add(src, pkt.SrcIP, pkt.Length)
		add(dst, pkt.DstIP, pkt.Length)
		add(ports, strconv.Itoa(int(pkt.DstPort)), pkt.Length)
		add(protos, protoName(pkt.Proto), pkt.Length)
		add(flows, flowKey(pkt), pkt.Length)
		add(pairs, pairKey(pkt), pkt.Length)
		add(packetLens, packetLenBucket(pkt.Length), pkt.Length)
		service := enrich.IdentifyService(pkt.DstPort, pkt.Proto)
		add(services, service.Name, pkt.Length)
		add(serviceCategories, service.Category, pkt.Length)
		add(serviceRisks, service.Risk, pkt.Length)
		add(vlans, vlanKey(pkt.VLANID), pkt.Length)
		add(dscps, dscpLabel(pkt.DSCP), pkt.Length)
		add(ecns, ecnLabel(pkt.ECN), pkt.Length)
		link.bytes += uint64(pkt.Length)
		link.packets++
	}
	flush()
}

func (a *Aggregator) alerts() config.Alerts {
	if a.Alerts == nil {
		return config.Alerts{
			FlowBytes:       20 * 1024,
			FlowShare:       0.30,
			SourcePackets:   50,
			LinkUtilization: 0.80,
		}
	}
	return a.Alerts()
}

func (a *Aggregator) sessionTopN() int {
	if a.SessionLimit != nil {
		return normalizeTopN(a.SessionLimit())
	}
	return normalizeTopN(a.SessionTopN)
}

func normalizeTopN(limit int) int {
	switch {
	case limit <= 0:
		return 500
	case limit < 20:
		return 20
	case limit > 5000:
		return 5000
	default:
		return limit
	}
}

func add(m map[string]counter, key string, bytes uint32) {
	c := m[key]
	c.bytes += uint64(bytes)
	c.packets++
	m[key] = c
}

func top(m map[string]counter, limit int) []model.TopItem {
	items := make([]model.TopItem, 0, len(m))
	for k, c := range m {
		items = append(items, model.TopItem{Key: k, Bytes: c.bytes, Packets: c.packets})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Bytes > items[j].Bytes
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func protoName(proto uint8) string {
	switch proto {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return strconv.Itoa(int(proto))
	}
}

func flowKey(pkt model.PacketMeta) string {
	return pkt.SrcIP + ":" + strconv.Itoa(int(pkt.SrcPort)) +
		" -> " + pkt.DstIP + ":" + strconv.Itoa(int(pkt.DstPort)) +
		" / " + protoName(pkt.Proto)
}

func pairKey(pkt model.PacketMeta) string {
	return pkt.SrcIP + " -> " + pkt.DstIP
}

func packetLenBucket(length uint32) string {
	switch {
	case length <= 64:
		return "<=64B"
	case length <= 128:
		return "65-128B"
	case length <= 256:
		return "129-256B"
	case length <= 512:
		return "257-512B"
	case length <= 1024:
		return "513B-1KB"
	case length <= 1518:
		return "1KB-MTU"
	default:
		return "Jumbo"
	}
}

func vlanKey(vlanID uint16) string {
	if vlanID == 0 {
		return "untagged"
	}
	return strconv.Itoa(int(vlanID))
}

func dscpLabel(dscp uint8) string {
	labels := map[uint8]string{
		0:  "BE",
		8:  "CS1",
		10: "AF11",
		12: "AF12",
		14: "AF13",
		16: "CS2",
		18: "AF21",
		20: "AF22",
		22: "AF23",
		24: "CS3",
		26: "AF31",
		28: "AF32",
		30: "AF33",
		32: "CS4",
		34: "AF41",
		36: "AF42",
		38: "AF43",
		40: "CS5",
		46: "EF",
		48: "CS6",
		56: "CS7",
	}
	if label, ok := labels[dscp]; ok {
		return label
	}
	return "DSCP-" + strconv.Itoa(int(dscp))
}

func ecnLabel(ecn uint8) string {
	switch ecn {
	case 0:
		return "Not-ECT"
	case 1:
		return "ECT(1)"
	case 2:
		return "ECT(0)"
	case 3:
		return "CE"
	default:
		return "ECN-" + strconv.Itoa(int(ecn))
	}
}

func anomalyAlerts(result model.WindowResult, policy config.Alerts) []model.AlertEvent {
	if result.Link.Bytes == 0 {
		return nil
	}
	alerts := []model.AlertEvent{}
	if len(result.TopFlow) > 0 {
		share := float64(result.TopFlow[0].Bytes) / float64(result.Link.Bytes)
		if result.TopFlow[0].Bytes >= policy.FlowBytes && share >= policy.FlowShare && !isSilenced(policy, result.TopFlow[0].Key) {
			alerts = append(alerts, model.AlertEvent{
				ID:        "top-flow-" + result.TopFlow[0].Key + "-" + strconv.FormatInt(result.Ts, 10),
				Severity:  "warning",
				Status:    "open",
				Subject:   result.TopFlow[0].Key,
				Summary:   "单会话流量占比达到 " + strconv.FormatFloat(share*100, 'f', 1, 64) + "%",
				FirstSeen: result.Ts,
				LastSeen:  result.Ts,
			})
		}
	}
	if len(result.TopSrcIP) > 0 {
		pps := float64(result.TopSrcIP[0].Packets) / 5
		if result.TopSrcIP[0].Packets >= policy.SourcePackets && !isSilenced(policy, result.TopSrcIP[0].Key) {
			alerts = append(alerts, model.AlertEvent{
				ID:        "talker-pps-" + result.TopSrcIP[0].Key + "-" + strconv.FormatInt(result.Ts, 10),
				Severity:  "info",
				Status:    "open",
				Subject:   result.TopSrcIP[0].Key,
				Summary:   "源主机包速率约 " + strconv.FormatFloat(pps, 'f', 1, 64) + " pps",
				FirstSeen: result.Ts,
				LastSeen:  result.Ts,
			})
		}
	}
	return alerts
}

func isSilenced(policy config.Alerts, subject string) bool {
	for _, item := range policy.SilencedSubjects {
		if item == subject {
			return true
		}
	}
	return false
}
