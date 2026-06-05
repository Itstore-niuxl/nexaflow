package model

type PacketMeta struct {
	Ts       int64
	SourceID string
	Iface    string
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Proto    uint8
	VLANID   uint16
	DSCP     uint8
	ECN      uint8
	Length   uint32
}

type LinkWindow struct {
	Ts       int64   `json:"ts"`
	SourceID string  `json:"source_id"`
	Iface    string  `json:"iface"`
	Bytes    uint64  `json:"bytes"`
	Packets  uint64  `json:"packets"`
	Drops    uint64  `json:"drops"`
	Util     float64 `json:"utilization"`
}

type CaptureQualityWindow struct {
	Ts                  int64  `json:"ts"`
	SourceID            string `json:"source_id"`
	Iface               string `json:"iface"`
	RxBytes             uint64 `json:"rx_bytes"`
	RxPackets           uint64 `json:"rx_packets"`
	RxDropped           uint64 `json:"rx_dropped"`
	RxErrors            uint64 `json:"rx_errors"`
	TxBytes             uint64 `json:"tx_bytes"`
	TxPackets           uint64 `json:"tx_packets"`
	TxDropped           uint64 `json:"tx_dropped"`
	TxErrors            uint64 `json:"tx_errors"`
	PacketQueueLen      uint64 `json:"packet_queue_len"`
	PacketQueueCapacity uint64 `json:"packet_queue_capacity"`
	WindowQueueLen      uint64 `json:"window_queue_len"`
	WindowQueueCapacity uint64 `json:"window_queue_capacity"`
}

type TopItem struct {
	Key     string `json:"key"`
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
}

type WindowResult struct {
	Ts           int64                 `json:"ts"`
	SourceID     string                `json:"source_id"`
	Iface        string                `json:"iface"`
	Link         LinkWindow            `json:"link"`
	Capture      *CaptureQualityWindow `json:"capture_quality,omitempty"`
	TopSrcIP     []TopItem             `json:"top_src_ip"`
	TopDstIP     []TopItem             `json:"top_dst_ip"`
	TopDstPort   []TopItem             `json:"top_dst_port"`
	TopProtocol  []TopItem             `json:"top_protocol"`
	TopFlow      []TopItem             `json:"top_flow"`
	TopPair      []TopItem             `json:"top_pair"`
	TopPacketLen []TopItem             `json:"top_packet_len"`
	TopService   []TopItem             `json:"top_service"`
	TopSvcCat    []TopItem             `json:"top_service_category"`
	TopSvcRisk   []TopItem             `json:"top_service_risk"`
	TopVLAN      []TopItem             `json:"top_vlan"`
	TopDSCP      []TopItem             `json:"top_dscp"`
	TopECN       []TopItem             `json:"top_ecn"`
	Alerts       []AlertEvent          `json:"alerts"`
}

type AlertEvent struct {
	ID        string `json:"id"`
	Severity  string `json:"severity"`
	Status    string `json:"status"`
	Subject   string `json:"subject"`
	Summary   string `json:"summary"`
	FirstSeen int64  `json:"first_seen"`
	LastSeen  int64  `json:"last_seen"`
}

type DetectionRule struct {
	ID                string  `json:"id"`
	Name              string  `json:"name"`
	Category          string  `json:"category"`
	Metric            string  `json:"metric"`
	Match             string  `json:"match"`
	Operator          string  `json:"operator"`
	Threshold         float64 `json:"threshold"`
	Severity          string  `json:"severity"`
	Enabled           bool    `json:"enabled"`
	Description       string  `json:"description"`
	RecommendedAction string  `json:"recommended_action"`
	UpdatedAt         int64   `json:"updated_at"`
}
