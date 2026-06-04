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

type TopItem struct {
	Key     string `json:"key"`
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
}

type WindowResult struct {
	Ts           int64        `json:"ts"`
	SourceID     string       `json:"source_id"`
	Iface        string       `json:"iface"`
	Link         LinkWindow   `json:"link"`
	TopSrcIP     []TopItem    `json:"top_src_ip"`
	TopDstIP     []TopItem    `json:"top_dst_ip"`
	TopDstPort   []TopItem    `json:"top_dst_port"`
	TopProtocol  []TopItem    `json:"top_protocol"`
	TopFlow      []TopItem    `json:"top_flow"`
	TopPair      []TopItem    `json:"top_pair"`
	TopPacketLen []TopItem    `json:"top_packet_len"`
	TopService   []TopItem    `json:"top_service"`
	TopSvcCat    []TopItem    `json:"top_service_category"`
	TopSvcRisk   []TopItem    `json:"top_service_risk"`
	TopVLAN      []TopItem    `json:"top_vlan"`
	TopDSCP      []TopItem    `json:"top_dscp"`
	TopECN       []TopItem    `json:"top_ecn"`
	Alerts       []AlertEvent `json:"alerts"`
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
