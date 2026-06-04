export interface Summary {
  bytes: number;
  packets: number;
  utilization: number;
}

export interface TopItem {
  key: string;
  bytes: number;
  packets: number;
}

export interface SeriesPoint {
  ts: number;
  bytes: number;
  packets: number;
}

export interface Collector {
  id: string;
  source_id: string;
  status: string;
  mode: string;
  iface?: string;
  bpf_filter?: string;
  updated_at?: number;
}

export interface AlertEvent {
  id: string;
  severity: string;
  status: string;
  subject: string;
  summary: string;
  first_seen: number;
  last_seen: number;
}

export interface NetworkInterface {
  name: string;
  state: string;
  type: string;
}

export interface CollectorConfig {
  mode: string;
  iface: string;
  source_id: string;
  bpf_filter: string;
  updated_at?: number;
}

export interface SystemStatus {
  database: string;
  latest_window_ts: number;
  windows_24h: number;
  sources_24h: number;
  interfaces_24h: number;
  collector?: CollectorConfig & { id?: string };
}

export interface IPProfile {
  ip: string;
  minutes: number;
  inbound_bytes: number;
  inbound_packets: number;
  outbound_bytes: number;
  outbound_packets: number;
  top_pairs: TopItem[];
  top_flows: TopItem[];
  last_seen: number;
}

export interface PortProfile {
  port: string;
  minutes: number;
  bytes: number;
  packets: number;
  flows: TopItem[];
}

export interface WindowRow {
  window_ts: number;
  source_id: string;
  iface: string;
  bytes: number;
  packets: number;
  utilization: number;
}

export interface AlertConfig {
  flow_bytes: number;
  flow_share: number;
  source_packets: number;
  link_utilization: number;
  silenced_subjects?: string[];
}

export interface MatrixRow {
  src: string;
  dst: string;
  bytes: number;
  packets: number;
}

export interface ServiceNode {
  ip: string;
  bytes: number;
  packets: number;
}

export interface ServiceMap {
  nodes: ServiceNode[];
  links: MatrixRow[];
}

export interface ServiceExposure {
  ip: string;
  port: string;
  protocol: string;
  service: string;
  category: string;
  risk: string;
  direction: string;
  confidence: string;
  bytes: number;
  packets: number;
  client_count: number;
  sample_client: string;
  sample_flow: string;
}

export interface ProtocolPoint {
  ts: number;
  protocol: string;
  bytes: number;
  packets: number;
}

export interface PortPoint {
  ts: number;
  port: string;
  bytes: number;
  packets: number;
}

export interface DirectionPoint {
  ts: number;
  direction: string;
  bytes: number;
  packets: number;
}

export interface SearchResult {
  kind: string;
  key: string;
  bytes: number;
  packets: number;
}

export interface AssetRow {
  ip: string;
  name: string;
  owner: string;
  business: string;
  environment: string;
  criticality: string;
  tags: string[];
  note: string;
  metadata_updated_at: number;
  role: string;
  inbound_bytes: number;
  inbound_packets: number;
  outbound_bytes: number;
  outbound_packets: number;
  total_bytes: number;
  total_packets: number;
  avg_packet_size: number;
  first_seen: number;
  last_seen: number;
}

export interface AssetMetadata {
  ip: string;
  name: string;
  owner: string;
  business: string;
  environment: string;
  criticality: string;
  tags: string[];
  note: string;
  metadata_updated_at?: number;
}

export interface SecurityInsight {
  kind: string;
  severity: string;
  subject: string;
  summary: string;
  bytes: number;
  packets: number;
  score: number;
}

export interface TrafficBaseline {
  windows: number;
  avg_bytes: number;
  peak_bytes: number;
  p95_bytes: number;
  avg_packets: number;
  peak_packets: number;
  avg_utilization: number;
  peak_utilization: number;
  avg_mbps: number;
  peak_mbps: number;
  p95_mbps: number;
  burst_ratio: number;
}

export interface TrafficAnalysis {
  minutes: number;
  baseline: TrafficBaseline;
  protocol_mix: TopItem[];
  port_mix: TopItem[];
  packet_sizes: TopItem[];
  directions: TopItem[];
}

export interface TrafficChange {
  dimension: string;
  key: string;
  current_bytes: number;
  previous_bytes: number;
  delta_bytes: number;
  current_packets: number;
  previous_packets: number;
  delta_packets: number;
  change_ratio: number;
}

const json = async <T>(url: string): Promise<T> => {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<T>;
};

export const api = {
  async summary(minutes = 15) {
    return json<{ data: Summary; degraded: boolean }>(`/api/v1/dashboard/summary?minutes=${minutes}`);
  },
  async timeseries(minutes = 15) {
    return json<{ data: SeriesPoint[]; degraded: boolean }>(`/api/v1/traffic/timeseries?minutes=${minutes}`);
  },
  async topn(dimension: string, direction = 'src', minutes = 15) {
    return json<{ data: TopItem[]; degraded: boolean }>(
      `/api/v1/traffic/topn?dimension=${dimension}&direction=${direction}&limit=10&minutes=${minutes}`
    );
  },
  async collectors() {
    return json<{ data: Collector[] }>('/api/v1/collectors');
  },
  async alerts(minutes = 15) {
    return json<{ data: AlertEvent[]; degraded: boolean }>(`/api/v1/alerts?minutes=${minutes}`);
  },
  async interfaces() {
    return json<{ data: NetworkInterface[] }>('/api/v1/interfaces');
  },
  async status() {
    return json<{ data: SystemStatus; degraded: boolean }>('/api/v1/system/status');
  },
  async ipProfile(ip: string, minutes = 15) {
    return json<{ data: IPProfile; degraded: boolean }>(
      `/api/v1/traffic/ip-profile?ip=${encodeURIComponent(ip)}&minutes=${minutes}`
    );
  },
  async portProfile(port: string, minutes = 15) {
    return json<{ data: PortProfile; degraded: boolean }>(
      `/api/v1/traffic/port-profile?port=${encodeURIComponent(port)}&minutes=${minutes}`
    );
  },
  async windows(minutes = 15, limit = 50) {
    return json<{ data: WindowRow[]; degraded: boolean }>(`/api/v1/traffic/windows?minutes=${minutes}&limit=${limit}`);
  },
  async matrix(minutes = 15, limit = 50) {
    return json<{ data: MatrixRow[]; degraded: boolean }>(`/api/v1/traffic/matrix?minutes=${minutes}&limit=${limit}`);
  },
  async serviceMap(minutes = 15, limit = 50) {
    return json<{ data: ServiceMap; degraded: boolean }>(`/api/v1/traffic/service-map?minutes=${minutes}&limit=${limit}`);
  },
  async serviceExposure(minutes = 15, limit = 50) {
    return json<{ data: ServiceExposure[]; degraded: boolean }>(
      `/api/v1/traffic/service-exposure?minutes=${minutes}&limit=${limit}`
    );
  },
  async protocolTimeseries(minutes = 15) {
    return json<{ data: ProtocolPoint[]; degraded: boolean }>(`/api/v1/traffic/protocol-timeseries?minutes=${minutes}`);
  },
  async portTimeseries(minutes = 15, limit = 8) {
    return json<{ data: PortPoint[]; degraded: boolean }>(`/api/v1/traffic/port-timeseries?minutes=${minutes}&limit=${limit}`);
  },
  async directionTimeseries(minutes = 15) {
    return json<{ data: DirectionPoint[]; degraded: boolean }>(`/api/v1/traffic/direction-timeseries?minutes=${minutes}`);
  },
  async search(q: string, minutes = 15, limit = 50) {
    return json<{ data: SearchResult[]; degraded: boolean }>(
      `/api/v1/traffic/search?q=${encodeURIComponent(q)}&minutes=${minutes}&limit=${limit}`
    );
  },
  async assets(minutes = 15, limit = 50) {
    return json<{ data: AssetRow[]; degraded: boolean }>(`/api/v1/assets?minutes=${minutes}&limit=${limit}`);
  },
  async updateAssetMetadata(metadata: AssetMetadata) {
    const response = await fetch('/api/v1/assets/metadata', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(metadata)
    });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response.json() as Promise<{ data: AssetMetadata }>;
  },
  async securityInsights(minutes = 15, limit = 50) {
    return json<{ data: SecurityInsight[]; degraded: boolean }>(
      `/api/v1/security/insights?minutes=${minutes}&limit=${limit}`
    );
  },
  async trafficAnalysis(minutes = 15) {
    return json<{ data: TrafficAnalysis; degraded: boolean }>(`/api/v1/traffic/analysis?minutes=${minutes}`);
  },
  async trafficChanges(minutes = 15, limit = 30) {
    return json<{ data: TrafficChange[]; degraded: boolean }>(`/api/v1/traffic/changes?minutes=${minutes}&limit=${limit}`);
  },
  async alertConfig() {
    return json<{ data: AlertConfig }>('/api/v1/alerts/config');
  },
  async updateAlertConfig(config: AlertConfig) {
    const response = await fetch('/api/v1/alerts/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config)
    });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response.json() as Promise<{ data: AlertConfig }>;
  },
  async updateAlertStatus(id: string, status: string) {
    const response = await fetch('/api/v1/alerts/status', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id, status })
    });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response.json() as Promise<{ data: { id: string; status: string } }>;
  },
  async addAlertSilence(subject: string) {
    const response = await fetch('/api/v1/alerts/silences', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ subject })
    });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response.json() as Promise<{ data: string[] }>;
  },
  async removeAlertSilence(subject: string) {
    const response = await fetch('/api/v1/alerts/silences', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ subject })
    });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response.json() as Promise<{ data: string[] }>;
  },
  async updateCollectorConfig(config: CollectorConfig) {
    const response = await fetch('/api/v1/collectors/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config)
    });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response.json() as Promise<{ data: CollectorConfig }>;
  }
};
