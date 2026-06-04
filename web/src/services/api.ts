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
  pcap_file?: string;
  replay_speed?: number;
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
  pcap_file?: string;
  replay_speed?: number;
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

export interface DataQualitySummary {
  latest_window_ts: number;
  freshness_seconds: number;
  expected_windows: number;
  observed_windows: number;
  coverage_ratio: number;
  gap_count: number;
  stale_sources: number;
  source_count: number;
  interface_count: number;
  bytes: number;
  packets: number;
  drops: number;
  max_utilization: number;
}

export interface DataQualitySource {
  source_id: string;
  iface: string;
  windows: number;
  bytes: number;
  packets: number;
  drops: number;
  max_utilization: number;
  first_window_ts: number;
  latest_window_ts: number;
  freshness_seconds: number;
  coverage_ratio: number;
  status: string;
}

export interface DataQualityGap {
  source_id: string;
  iface: string;
  start_ts: number;
  end_ts: number;
  duration_seconds: number;
  missing_windows: number;
}

export interface DataQualityRecommendation {
  level: string;
  title: string;
  detail: string;
}

export interface DataQuality {
  generated_at: number;
  minutes: number;
  status: string;
  window_interval: number;
  summary: DataQualitySummary;
  sources: DataQualitySource[];
  gaps: DataQualityGap[];
  recommendations: DataQualityRecommendation[];
  degraded_reasons: string[];
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
  detection_rules?: DetectionRule[];
}

export interface DetectionRule {
  id: string;
  name: string;
  category: string;
  metric: string;
  match: string;
  operator: string;
  threshold: number;
  severity: string;
  enabled: boolean;
  description: string;
  recommended_action: string;
  updated_at: number;
}

export interface RuleFinding {
  id: string;
  rule_id: string;
  rule_name: string;
  category: string;
  kind: string;
  metric: string;
  severity: string;
  subject: string;
  summary: string;
  value: number;
  threshold: number;
  unit: string;
  bytes: number;
  packets: number;
  score: number;
  recommended_action: string;
  matched_at: number;
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

export interface ExternalAccess {
  public_ip: string;
  internal_ip: string;
  direction: string;
  port: string;
  protocol: string;
  service: string;
  category: string;
  risk: string;
  bytes: number;
  packets: number;
  session_count: number;
  sample_flow: string;
  first_seen: number;
  last_seen: number;
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

export interface DimensionPoint {
  ts: number;
  dimension: string;
  key: string;
  bytes: number;
  packets: number;
}

export interface SearchResult {
  kind: string;
  key: string;
  bytes: number;
  packets: number;
}

export interface SessionRow {
  key: string;
  src_ip: string;
  src_port: string;
  dst_ip: string;
  dst_port: string;
  protocol: string;
  service: string;
  category: string;
  risk: string;
  direction: string;
  server_ip: string;
  server_port: string;
  client_ip: string;
  confidence: string;
  bytes: number;
  packets: number;
  avg_packet_size: number;
  first_seen: number;
  last_seen: number;
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

export interface AssetRiskPosture {
  ip: string;
  name: string;
  owner: string;
  business: string;
  environment: string;
  criticality: string;
  role: string;
  risk_score: number;
  risk_level: string;
  total_bytes: number;
  total_packets: number;
  external_bytes: number;
  external_peers: number;
  external_sessions: number;
  exposed_services: number;
  high_risk_services: number;
  open_incidents: number;
  critical_incidents: number;
  anomaly_count: number;
  top_finding: string;
  recommended_action: string;
  last_seen: number;
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

export interface SecurityIncident {
  id: string;
  source: string;
  category: string;
  kind: string;
  severity: string;
  status: string;
  subject: string;
  summary: string;
  bytes: number;
  packets: number;
  score: number;
  first_seen: number;
  last_seen: number;
  recommended_action: string;
}

export interface IncidentSelector {
  dimension: string;
  key: string;
  query: string;
  direction: string;
}

export interface PlaybookAction {
  label: string;
  description: string;
}

export interface SecurityIncidentContext {
  subject: string;
  kind: string;
  minutes: number;
  selector: IncidentSelector;
  relations: ObjectRelations;
  sessions: SessionRow[];
  search_results: SearchResult[];
  insights: SecurityInsight[];
  anomalies: TrafficAnomaly[];
  playbook_actions: PlaybookAction[];
  ip_profile?: IPProfile;
  port_profile?: PortProfile;
}

export interface IncidentTimelineEntry {
  id: string;
  type: string;
  status: string;
  note: string;
  author: string;
  summary: string;
  created_at: number;
}

export interface ReportRecommendation {
  level: string;
  title: string;
  detail: string;
}

export interface ReportSummary {
  minutes: number;
  bytes: number;
  packets: number;
  utilization: number;
  asset_count: number;
  critical_assets: number;
  open_incidents: number;
  critical_incidents: number;
  anomaly_count: number;
  critical_anomalies: number;
  exposed_services: number;
  high_risk_services: number;
  external_access: number;
  external_session_sum: number;
  avg_mbps: number;
  peak_mbps: number;
  p95_mbps: number;
}

export interface ReportOverview {
  generated_at: number;
  minutes: number;
  summary: ReportSummary;
  asset_risks: AssetRiskPosture[];
  incidents: SecurityIncident[];
  anomalies: TrafficAnomaly[];
  exposures: ServiceExposure[];
  external_access: ExternalAccess[];
  top_src: TopItem[];
  top_ports: TopItem[];
  top_services: TopItem[];
  recommendations: ReportRecommendation[];
}

export interface ObjectRelationSummary {
  key: string;
  bytes: number;
  packets: number;
  related_count: number;
}

export interface ObjectRelations {
  dimension: string;
  key: string;
  direction: string;
  minutes: number;
  summary: ObjectRelationSummary;
  related_ips: TopItem[];
  related_ports: TopItem[];
  related_services: TopItem[];
  related_flows: TopItem[];
  insights: SecurityInsight[];
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

export interface CapacitySummary {
  minutes: number;
  bandwidth_mbps: number;
  avg_mbps: number;
  peak_mbps: number;
  p95_mbps: number;
  previous_peak_mbps: number;
  growth_mbps: number;
  growth_ratio: number;
  headroom_mbps: number;
  headroom_ratio: number;
  peak_utilization: number;
  p95_utilization: number;
  saturation_eta_mins: number;
  risk_level: string;
}

export interface CapacityTrendPoint {
  ts: number;
  bytes: number;
  packets: number;
  utilization: number;
  mbps: number;
}

export interface CapacityRecommendation {
  level: string;
  title: string;
  detail: string;
}

export interface CapacityPlanning {
  generated_at: number;
  minutes: number;
  summary: CapacitySummary;
  trend: CapacityTrendPoint[];
  top_src_growth: TrafficChange[];
  top_port_growth: TrafficChange[];
  top_service_growth: TrafficChange[];
  recommendations: CapacityRecommendation[];
}

export interface TrafficAnomaly {
  kind: string;
  dimension: string;
  key: string;
  severity: string;
  summary: string;
  current_bytes: number;
  baseline_bytes: number;
  delta_bytes: number;
  current_packets: number;
  baseline_packets: number;
  delta_packets: number;
  change_ratio: number;
  score: number;
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
  async dataQuality(minutes = 15, limit = 20) {
    return json<{ data: DataQuality; degraded: boolean }>(`/api/v1/system/data-quality?minutes=${minutes}&limit=${limit}`);
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
  async externalAccess(minutes = 15, limit = 80) {
    return json<{ data: ExternalAccess[]; degraded: boolean }>(
      `/api/v1/traffic/external-access?minutes=${minutes}&limit=${limit}`
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
  async dimensionTimeseries(dimension = 'service', key = '', minutes = 15, direction = 'src', limit = 5) {
    return json<{ data: DimensionPoint[]; degraded: boolean }>(
      `/api/v1/traffic/dimension-timeseries?dimension=${encodeURIComponent(dimension)}&key=${encodeURIComponent(key)}&direction=${encodeURIComponent(direction)}&minutes=${minutes}&limit=${limit}`
    );
  },
  async objectRelations(dimension = 'service', key = '', minutes = 15, direction = 'src', limit = 8) {
    return json<{ data: ObjectRelations; degraded: boolean }>(
      `/api/v1/traffic/object-relations?dimension=${encodeURIComponent(dimension)}&key=${encodeURIComponent(key)}&direction=${encodeURIComponent(direction)}&minutes=${minutes}&limit=${limit}`
    );
  },
  async sessions(q = '', minutes = 15, limit = 80) {
    return json<{ data: SessionRow[]; degraded: boolean }>(
      `/api/v1/traffic/sessions?q=${encodeURIComponent(q)}&minutes=${minutes}&limit=${limit}`
    );
  },
  async search(q: string, minutes = 15, limit = 50) {
    return json<{ data: SearchResult[]; degraded: boolean }>(
      `/api/v1/traffic/search?q=${encodeURIComponent(q)}&minutes=${minutes}&limit=${limit}`
    );
  },
  async assets(minutes = 15, limit = 50) {
    return json<{ data: AssetRow[]; degraded: boolean }>(`/api/v1/assets?minutes=${minutes}&limit=${limit}`);
  },
  async assetRiskPosture(minutes = 15, limit = 80) {
    return json<{ data: AssetRiskPosture[]; degraded: boolean }>(`/api/v1/assets/risk-posture?minutes=${minutes}&limit=${limit}`);
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
  async securityIncidents(minutes = 15, limit = 80) {
    return json<{ data: SecurityIncident[]; degraded: boolean }>(
      `/api/v1/security/incidents?minutes=${minutes}&limit=${limit}`
    );
  },
  async securityIncidentContext(subject: string, kind = '', minutes = 15, limit = 12) {
    return json<{ data: SecurityIncidentContext; degraded: boolean }>(
      `/api/v1/security/incident-context?subject=${encodeURIComponent(subject)}&kind=${encodeURIComponent(kind)}&minutes=${minutes}&limit=${limit}`
    );
  },
  async updateIncidentStatus(id: string, status: string, note = '', author = 'operator') {
    const response = await fetch('/api/v1/security/incident-status', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id, status, note, author })
    });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response.json() as Promise<{ data: { id: string; status: string } }>;
  },
  async incidentTimeline(id: string, limit = 50) {
    return json<{ data: IncidentTimelineEntry[]; degraded: boolean }>(
      `/api/v1/security/incident-timeline?id=${encodeURIComponent(id)}&limit=${limit}`
    );
  },
  async addIncidentNote(id: string, note: string, author = 'operator') {
    const response = await fetch('/api/v1/security/incident-notes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id, note, author })
    });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response.json() as Promise<{ data: IncidentTimelineEntry }>;
  },
  async reportOverview(minutes = 15, limit = 10) {
    return json<{ data: ReportOverview; degraded: boolean }>(`/api/v1/reports/overview?minutes=${minutes}&limit=${limit}`);
  },
  async detectionRules() {
    return json<{ data: DetectionRule[] }>('/api/v1/security/rules');
  },
  async saveDetectionRule(rule: DetectionRule) {
    const response = await fetch('/api/v1/security/rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(rule)
    });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response.json() as Promise<{ data: DetectionRule[] }>;
  },
  async deleteDetectionRule(id: string) {
    const response = await fetch(`/api/v1/security/rules?id=${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response.json() as Promise<{ data: DetectionRule[] }>;
  },
  async ruleFindings(minutes = 15, limit = 80) {
    return json<{ data: RuleFinding[]; degraded: boolean }>(`/api/v1/security/rule-findings?minutes=${minutes}&limit=${limit}`);
  },
  async trafficAnalysis(minutes = 15) {
    return json<{ data: TrafficAnalysis; degraded: boolean }>(`/api/v1/traffic/analysis?minutes=${minutes}`);
  },
  async capacityPlanning(minutes = 15, limit = 10) {
    return json<{ data: CapacityPlanning; degraded: boolean }>(`/api/v1/traffic/capacity?minutes=${minutes}&limit=${limit}`);
  },
  async trafficChanges(minutes = 15, limit = 30) {
    return json<{ data: TrafficChange[]; degraded: boolean }>(`/api/v1/traffic/changes?minutes=${minutes}&limit=${limit}`);
  },
  async trafficAnomalies(minutes = 15, limit = 30) {
    return json<{ data: TrafficAnomaly[]; degraded: boolean }>(`/api/v1/traffic/anomalies?minutes=${minutes}&limit=${limit}`);
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
