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
  session_topn?: number;
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

export interface AuditEvent {
  id: string;
  ts: number;
  actor: string;
  action: string;
  target: string;
  summary: string;
  detail: string;
  detail_text?: string;
  client_ip: string;
}

export interface ConfigVersion {
  id: string;
  ts: number;
  actor: string;
  scope: string;
  target: string;
  action: string;
  summary: string;
  config: string;
  config_text?: string;
  client_ip: string;
}

export interface ConfigDiffChange {
  path: string;
  type: string;
  before: string;
  after: string;
}

export interface ConfigDiff {
  version_id: string;
  summary: {
    change_count: number;
    source: string;
    source_ts: number;
    current_ts: number;
  };
  changes: ConfigDiffChange[];
}

export interface AuthStatus {
  enabled: boolean;
  authenticated: boolean;
  actor: string;
  role?: string;
  can_write?: boolean;
}

export interface SystemSettings {
  ai: {
    mode: string;
    provider: string;
    model: string;
    base_url: string;
    api_key?: string;
    api_key_set?: boolean;
    api_key_masked?: string;
    max_context_rows: number;
    timeout_seconds: number;
    temperature: number;
    enabled_summaries: boolean;
  };
  analysis: {
    default_minutes: number;
    baseline_minutes: number;
    baseline_deviation_warning: number;
    baseline_deviation_critical: number;
    baseline_min_bytes: number;
    bandwidth_mbps: number;
    report_default_minutes: number;
  };
  security: {
    auth_enabled: boolean;
    readonly_enabled: boolean;
    admin_password?: string;
    readonly_password?: string;
    admin_password_set?: boolean;
    readonly_password_set?: boolean;
    session_ttl_hours: number;
    require_audit_for_write: boolean;
    allow_frontend_secrets: boolean;
  };
  notification: {
    enabled: boolean;
    provider: string;
    webhook_url: string;
    webhook_token?: string;
    webhook_token_set?: boolean;
    webhook_token_masked?: string;
    min_severity: string;
    notify_on_incident: boolean;
    notify_on_report: boolean;
    channels: string[];
  };
  data: {
    clickhouse_retention_days: number;
    audit_retention_days: number;
    config_version_limit: number;
    session_retention_days: number;
    export_enabled: boolean;
  };
  backend: {
    api_addr: string;
    clickhouse_url: string;
    redis_addr: string;
    database: string;
    requires_restart: boolean;
  };
  updated_at: number;
}

export interface SettingsTestResult {
  ok: boolean;
  mode?: string;
  provider?: string;
  model?: string;
  status?: number;
  message: string;
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
  session_topn?: number;
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

export interface CaptureQualitySummary {
  windows: number;
  rx_bytes: number;
  rx_packets: number;
  rx_dropped: number;
  rx_errors: number;
  tx_bytes: number;
  tx_packets: number;
  tx_dropped: number;
  tx_errors: number;
  packet_queue_len: number;
  window_queue_len: number;
  queue_pressure: number;
  drop_ratio: number;
  error_ratio: number;
  source_count: number;
  interface_count: number;
  latest_window_ts: number;
}

export interface CaptureQualitySource {
  source_id: string;
  iface: string;
  windows: number;
  rx_bytes: number;
  rx_packets: number;
  rx_dropped: number;
  rx_errors: number;
  tx_bytes: number;
  tx_packets: number;
  tx_dropped: number;
  tx_errors: number;
  packet_queue_len: number;
  packet_queue_capacity: number;
  window_queue_len: number;
  window_queue_capacity: number;
  packet_queue_pressure: number;
  window_queue_pressure: number;
  queue_pressure: number;
  first_window_ts: number;
  latest_window_ts: number;
  freshness_seconds: number;
  drop_ratio: number;
  error_ratio: number;
  status: string;
}

export interface CaptureQuality {
  generated_at: number;
  minutes: number;
  status: string;
  summary: CaptureQualitySummary;
  sources: CaptureQualitySource[];
  recommendations: DataQualityRecommendation[];
}

export interface CaptureDiagnosticLayer {
  id: string;
  name: string;
  status: string;
  score: number;
  metric: string;
  detail: string;
  recommendation: string;
}

export interface CaptureDiagnostics {
  generated_at: number;
  minutes: number;
  status: string;
  summary: {
    layer_count: number;
    critical_layers: number;
    warning_layers: number;
  };
  layers: CaptureDiagnosticLayer[];
  recommendations: DataQualityRecommendation[];
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

export interface ServiceAnalyticsSummary {
  service_count: number;
  category_count: number;
  high_risk_services: number;
  total_bytes: number;
  total_packets: number;
  top_service: string;
  top_risk: string;
}

export interface ServiceAnalyticsPort {
  service: string;
  port: string;
  protocol: string;
  category: string;
  risk: string;
  bytes: number;
  packets: number;
  sample_flow: string;
  last_seen: number;
}

export interface ServiceAnalyticsDetail {
  service: string;
  category: string;
  risk: string;
  bytes: number;
  packets: number;
  client_count: number;
  server_count: number;
  session_count: number;
  top_port: string;
  sample_flow: string;
  first_seen: number;
  last_seen: number;
}

export interface ServiceAnalytics {
  generated_at: number;
  minutes: number;
  summary: ServiceAnalyticsSummary;
  services: TopItem[];
  categories: TopItem[];
  risks: TopItem[];
  growth: TrafficChange[];
  ports: ServiceAnalyticsPort[];
  details: ServiceAnalyticsDetail[];
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
  src_ip?: string;
  dst_ip?: string;
  dst_port?: string;
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
  src_ip_profile?: IPProfile;
  dst_ip_profile?: IPProfile;
  port_profile?: PortProfile;
  dst_port_profile?: PortProfile;
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

export interface SimilarIncident {
  id: string;
  subject: string;
  kind: string;
  category: string;
  severity: string;
  status: string;
  summary: string;
  first_seen: number;
  last_seen: number;
  score: number;
  similarity: number;
  reason: string;
}

export interface IncidentRecurrence {
  recurring: boolean;
  similar_count: number;
  same_subject: number;
  unresolved_count: number;
  latest_seen: number;
  latest_subject: string;
  timeline_entries: number;
  conclusion: string;
}

export interface IncidentEvidenceItem {
  id: string;
  kind: string;
  title: string;
  target: string;
  summary: string;
  severity: string;
  source: string;
  detail: Record<string, unknown>;
}

export interface IncidentContextQuality {
  status: string;
  score: number;
  sessions: number;
  insights: number;
  anomalies: number;
  search_results: number;
  relation_flows: number;
  profiles: number;
  timeline_entries: number;
  similar_incidents: number;
  degraded: boolean;
  degraded_reasons: string[];
  generated_at_unix?: number;
  evidence_item_hint?: string;
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

export interface AISummary {
  enabled: boolean;
  mode: string;
  provider: string;
  model: string;
  kind: string;
  subject: string;
  title: string;
  summary: string;
  confidence: number;
  findings: string[];
  evidence: string[];
  actions: string[];
  generated_at: number;
}

export interface AIQueryIntent {
  id: string;
  title: string;
  description: string;
  api: string;
  question: string;
  minutes: number;
  limit: number;
  params: Record<string, unknown>;
}

export interface AIQueryResult {
  enabled: boolean;
  mode: string;
  provider: string;
  model: string;
  question: string;
  intent: AIQueryIntent;
  title: string;
  summary: string;
  confidence: number;
  findings: string[];
  evidence: string[];
  actions: string[];
  rows: Record<string, unknown>[];
  followups: string[];
  generated_at: number;
  degraded?: boolean;
  error?: string;
}

export interface AIIncidentInvestigation {
  enabled: boolean;
  mode: string;
  provider: string;
  model: string;
  subject: string;
  summary: AISummary;
  root_causes: string[];
  evidence_chain: string[];
  evidence_items: IncidentEvidenceItem[];
  context_quality: IncidentContextQuality;
  degraded_reasons: string[];
  next_steps: string[];
  similar_incidents: SimilarIncident[];
  recurrence: IncidentRecurrence;
  context: SecurityIncidentContext;
  timeline: IncidentTimelineEntry[];
  generated_at: number;
}

export interface AIGovernanceSuggestion {
  id: string;
  type: string;
  severity: string;
  title: string;
  target: string;
  summary: string;
  confidence: number;
  evidence: string[];
  actions: string[];
  proposed_rule?: DetectionRule;
  proposed_silence?: {
    subject: string;
    reason: string;
    scope: string;
  };
}

export interface AIGovernanceSuggestions {
  enabled: boolean;
  mode: string;
  provider: string;
  model: string;
  minutes: number;
  summary: string;
  suggestions: AIGovernanceSuggestion[];
  generated_at: number;
}

export interface AIRuleEffectivenessRow {
  id: string;
  name: string;
  category: string;
  metric: string;
  match: string;
  operator: string;
  threshold: number;
  severity: string;
  enabled_rule: boolean;
  minutes: number;
  hit_count: number;
  critical_count: number;
  warning_count: number;
  unique_subjects: number;
  duplicate_ratio: number;
  silenced_hits: number;
  total_bytes: number;
  peak_value: number;
  top_subject: string;
  noise_level: string;
  score: number;
  summary: string;
  recommendations: string[];
  sample_findings: RuleFinding[];
  generated_at: number;
}

export interface AIRuleTuningSuggestion {
  rule_id: string;
  rule_name: string;
  noise_level: string;
  severity: string;
  title: string;
  summary: string;
  actions: string[];
  score: number;
}

export interface AIRuleEffectiveness {
  enabled: boolean;
  mode: string;
  provider: string;
  model: string;
  summary: {
    minutes: number;
    rule_count: number;
    enabled_rules: number;
    disabled_rules: number;
    total_hits: number;
    critical_hits: number;
    noisy_rules: number;
    quiet_rules: number;
    health: string;
  };
  rules: AIRuleEffectivenessRow[];
  tuning_suggestions: AIRuleTuningSuggestion[];
  generated_at: number;
}

export interface AIAssetEnrichmentSuggestion {
  id: string;
  type: string;
  severity: string;
  ip: string;
  title: string;
  summary: string;
  confidence: number;
  missing_fields: string[];
  evidence: string[];
  actions: string[];
  proposed_metadata: AssetMetadata;
  generated_at: number;
  enabled: boolean;
}

export interface AIAssetEnrichmentSuggestions {
  enabled: boolean;
  mode: string;
  provider: string;
  model: string;
  minutes: number;
  summary: string;
  suggestions: AIAssetEnrichmentSuggestion[];
  generated_at: number;
}

export interface AIApprovalRequest {
  id: string;
  type: string;
  status: string;
  severity: string;
  title: string;
  target: string;
  summary: string;
  confidence: number;
  evidence: string[];
  actions: string[];
  payload: Record<string, unknown>;
  created_by: string;
  created_at: number;
  reviewed_by?: string;
  reviewed_at?: number;
  review_note?: string;
  applied_at?: number;
  apply_result?: string;
}

export interface AIApprovalCount {
  key: string;
  label: string;
  count: number;
}

export interface AIApprovalStats {
  generated_at: number;
  total: number;
  pending: number;
  approved: number;
  rejected: number;
  critical_pending: number;
  overdue_pending: number;
  oldest_pending_age_seconds: number;
  average_review_seconds: number;
  reviewed_count: number;
  status_counts: AIApprovalCount[];
  type_counts: AIApprovalCount[];
  severity_counts: AIApprovalCount[];
  pending_type_counts: AIApprovalCount[];
  pending_severity_counts: AIApprovalCount[];
  stale_threshold_seconds: number;
  summary: string;
  recommendations: string[];
  requires_operator_attention: boolean;
  approval_completion_rate: number;
  approval_rejection_rate: number;
  pending_criticality_score: number;
  oldest_pending_age_readable: string;
  average_review_time_readable: string;
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

export interface BaselineDeviation {
  dimension: string;
  dimension_title: string;
  key: string;
  current_bytes: number;
  current_packets: number;
  baseline_bytes: number;
  baseline_packets: number;
  p95_bytes: number;
  peak_bytes: number;
  peak_packets: number;
  delta_bytes: number;
  deviation_ratio: number;
  change_ratio: number;
  samples: number;
  status: string;
  severity: string;
  score: number;
  summary: string;
  dimension_source: string;
}

export interface BaselineRecommendation {
  level: string;
  title: string;
  detail: string;
}

export interface BehaviorBaseline {
  generated_at: number;
  minutes: number;
  baseline_minutes: number;
  window_count: number;
  baseline_strategy: string;
  link: BaselineDeviation;
  summary: {
    total_deviations: number;
    critical_count: number;
    warning_count: number;
    new_count: number;
    learning_count: number;
    stable_count: number;
    top_key: string;
    top_dimension: string;
    top_deviation: number;
    link_status: string;
    link_deviation: number;
    link_current_bytes: number;
  };
  deviations: BaselineDeviation[];
  recommendations: BaselineRecommendation[];
}

const json = async <T>(url: string): Promise<T> => {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<T>;
};

export const api = {
  async authStatus() {
    return json<{ data: AuthStatus }>('/api/v1/auth/status');
  },
  async login(actor: string, password: string) {
    const response = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ actor, password })
    });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response.json() as Promise<{ data: AuthStatus }>;
  },
  async logout() {
    const response = await fetch('/api/v1/auth/logout', { method: 'POST' });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response.json() as Promise<{ data: AuthStatus }>;
  },
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
  async captureQuality(minutes = 15, limit = 20) {
    return json<{ data: CaptureQuality; degraded: boolean }>(`/api/v1/system/capture-quality?minutes=${minutes}&limit=${limit}`);
  },
  async captureDiagnostics(minutes = 15, limit = 20) {
    return json<{ data: CaptureDiagnostics; degraded: boolean }>(`/api/v1/system/capture-diagnostics?minutes=${minutes}&limit=${limit}`);
  },
  async systemSettings() {
    return json<{ data: SystemSettings }>('/api/v1/system/settings');
  },
  async saveSystemSettings(settings: SystemSettings) {
    const response = await fetch('/api/v1/system/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings)
    });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response.json() as Promise<{ data: SystemSettings }>;
  },
  async testAISettings(settings: SystemSettings) {
    const response = await fetch('/api/v1/system/settings/test-ai', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings)
    });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response.json() as Promise<{ data: SettingsTestResult }>;
  },
  async testWebhookSettings(settings: SystemSettings) {
    const response = await fetch('/api/v1/system/settings/test-webhook', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings)
    });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response.json() as Promise<{ data: SettingsTestResult }>;
  },
  async exportSystemSettings() {
    return json<{ data: SystemSettings }>('/api/v1/system/settings/export');
  },
  async importSystemSettings(settings: SystemSettings) {
    const response = await fetch('/api/v1/system/settings/import', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings)
    });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response.json() as Promise<{ data: SystemSettings }>;
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
  async serviceAnalytics(minutes = 15, limit = 12) {
    return json<{ data: ServiceAnalytics; degraded: boolean }>(`/api/v1/traffic/service-analytics?minutes=${minutes}&limit=${limit}`);
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
  async downloadReportOverview(minutes = 15, limit = 50) {
    const response = await fetch(`/api/v1/reports/overview/export?minutes=${minutes}&limit=${limit}&format=csv`);
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response;
  },
  async aiIncidentSummary(subject: string, kind = '', id = '', minutes = 15, limit = 12) {
    return json<{ data: AISummary; degraded: boolean }>(
      `/api/v1/ai/incident-summary?subject=${encodeURIComponent(subject)}&kind=${encodeURIComponent(kind)}&id=${encodeURIComponent(id)}&minutes=${minutes}&limit=${limit}`
    );
  },
  async aiAssetSummary(ip: string, minutes = 15, limit = 20) {
    return json<{ data: AISummary; degraded: boolean }>(
      `/api/v1/ai/asset-summary?ip=${encodeURIComponent(ip)}&minutes=${minutes}&limit=${limit}`
    );
  },
  async aiReportSummary(minutes = 15, limit = 10) {
    return json<{ data: AISummary; degraded: boolean }>(`/api/v1/ai/report-summary?minutes=${minutes}&limit=${limit}`);
  },
  async aiCaptureDiagnosticsSummary(minutes = 15, limit = 20) {
    return json<{ data: AISummary; degraded: boolean }>(
      `/api/v1/ai/capture-diagnostics-summary?minutes=${minutes}&limit=${limit}`
    );
  },
  async aiQuery(question: string, minutes = 15, limit = 8) {
    const response = await fetch('/api/v1/ai/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question, minutes, limit })
    });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response.json() as Promise<{ data: AIQueryResult; degraded: boolean }>;
  },
  async aiIncidentInvestigation(subject: string, kind = '', id = '', minutes = 15, limit = 12) {
    return json<{ data: AIIncidentInvestigation; degraded: boolean }>(
      `/api/v1/ai/incident-investigation?subject=${encodeURIComponent(subject)}&kind=${encodeURIComponent(kind)}&id=${encodeURIComponent(id)}&minutes=${minutes}&limit=${limit}`
    );
  },
  async aiIncidentActions(subject: string, kind = '', id = '', minutes = 15, limit = 8) {
    return json<{ data: AIGovernanceSuggestions; degraded: boolean }>(
      `/api/v1/ai/incident-actions?subject=${encodeURIComponent(subject)}&kind=${encodeURIComponent(kind)}&id=${encodeURIComponent(id)}&minutes=${minutes}&limit=${limit}`
    );
  },
  async aiGovernanceSuggestions(minutes = 15, limit = 8) {
    return json<{ data: AIGovernanceSuggestions; degraded: boolean }>(
      `/api/v1/ai/governance-suggestions?minutes=${minutes}&limit=${limit}`
    );
  },
  async aiRuleEffectiveness(minutes = 15, limit = 100) {
    return json<{ data: AIRuleEffectiveness; degraded: boolean }>(
      `/api/v1/ai/rule-effectiveness?minutes=${minutes}&limit=${limit}`
    );
  },
  async aiAssetEnrichmentSuggestions(minutes = 15, limit = 8) {
    return json<{ data: AIAssetEnrichmentSuggestions; degraded: boolean }>(
      `/api/v1/ai/asset-enrichment-suggestions?minutes=${minutes}&limit=${limit}`
    );
  },
  async aiApprovalRequests(status = '') {
    const query = status ? `?status=${encodeURIComponent(status)}` : '';
    return json<{ data: AIApprovalRequest[]; degraded: boolean }>(`/api/v1/ai/approval-requests${query}`);
  },
  async aiApprovalStats() {
    return json<{ data: AIApprovalStats; degraded: boolean }>('/api/v1/ai/approval-stats');
  },
  async downloadAIApprovalRequests(status = '', limit = 500) {
    const response = await fetch(
      `/api/v1/ai/approval-requests/export?status=${encodeURIComponent(status)}&limit=${limit}&format=csv`
    );
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response;
  },
  async createAIApprovalRequest(request: Partial<AIApprovalRequest>) {
    const response = await fetch('/api/v1/ai/approval-requests', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ request })
    });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response.json() as Promise<{ data: AIApprovalRequest }>;
  },
  async reviewAIApprovalRequest(id: string, action: 'approve' | 'reject', note = '') {
    const response = await fetch('/api/v1/ai/approval-requests', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id, action, note })
    });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response.json() as Promise<{ data: AIApprovalRequest }>;
  },
  async bulkRejectAIApprovalRequests(ids: string[], note = '') {
    const response = await fetch('/api/v1/ai/approval-requests', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids, action: 'reject', note })
    });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response.json() as Promise<{ data: { action: string; reviewed: number; skipped: number; requests: AIApprovalRequest[]; errors: string[] } }>;
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
  async behaviorBaseline(minutes = 15, baselineMinutes = 0, limit = 10) {
    const baselineQuery = baselineMinutes > 0 ? `&baseline_minutes=${baselineMinutes}` : '';
    return json<{ data: BehaviorBaseline; degraded: boolean }>(
      `/api/v1/traffic/baseline-profile?minutes=${minutes}${baselineQuery}&limit=${limit}`
    );
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
  },
  async auditEvents(limit = 80) {
    return json<{ data: AuditEvent[]; degraded: boolean }>(`/api/v1/system/audit-events?limit=${limit}`);
  },
  async downloadAuditEvents(limit = 200) {
    const response = await fetch(`/api/v1/system/audit-events/export?limit=${limit}&format=csv`);
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response;
  },
  async configVersions(scope = '', limit = 80) {
    return json<{ data: ConfigVersion[]; degraded: boolean }>(
      `/api/v1/system/config-versions?scope=${encodeURIComponent(scope)}&limit=${limit}`
    );
  },
  async downloadConfigVersions(scope = '', limit = 500) {
    const response = await fetch(`/api/v1/system/config-versions/export?scope=${encodeURIComponent(scope)}&limit=${limit}&format=csv`);
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response;
  },
  async restoreConfigVersion(id: string) {
    const response = await fetch('/api/v1/system/config-versions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id })
    });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response.json() as Promise<{ data: CollectorConfig; version: ConfigVersion }>;
  },
  async configVersionDiff(id: string) {
    return json<{ data: ConfigDiff }>(`/api/v1/system/config-version-diff?id=${encodeURIComponent(id)}`);
  }
};
