<script setup lang="ts">
import {
  Activity,
  AlertTriangle,
  ChartNoAxesCombined,
  ClipboardList,
  CircleGauge,
  Database,
  FileText,
  Gauge,
  HardDrive,
  History,
  LayoutDashboard,
  ListOrdered,
  MonitorDot,
  Network,
  Radar,
  RadioTower,
  RefreshCw,
  Route,
  Search,
  ServerCog,
  Settings2,
  Shield,
  Sparkles,
  Waypoints
} from '@lucide/vue';
import { computed, onMounted, onUnmounted, ref } from 'vue';
import DashboardChart from './components/DashboardChart.vue';
import DimensionTrendChart from './components/DimensionTrendChart.vue';
import FlowMatrixChart from './components/FlowMatrixChart.vue';
import HealthGaugePanel from './components/HealthGaugePanel.vue';
import HorizontalBarChart from './components/HorizontalBarChart.vue';
import LiveFlowMap from './components/LiveFlowMap.vue';
import TopNTable from './components/TopNTable.vue';
import TrafficCompositionPanel from './components/TrafficCompositionPanel.vue';
import TrafficHeatmap from './components/TrafficHeatmap.vue';
import {
  api,
  type AlertConfig,
  type AlertEvent,
  type AIApprovalRequest,
  type AIAssetEnrichmentSuggestions,
  type AIAssetEnrichmentSuggestion,
  type AIGovernanceSuggestions,
  type AIGovernanceSuggestion,
  type AIIncidentInvestigation,
  type AIQueryResult,
  type AIRuleEffectiveness,
  type AISummary,
  type AuditEvent,
  type AssetMetadata,
  type AssetRiskPosture,
  type AssetRow,
  type AuthStatus,
  type BehaviorBaseline,
  type CapacityPlanning,
  type CaptureDiagnostics,
  type CaptureQuality,
  type Collector,
  type CollectorConfig,
  type ConfigDiff,
  type ConfigVersion,
  type DataQuality,
  type DimensionPoint,
  type DetectionRule,
  type ExternalAccess,
  type IPProfile,
  type MatrixRow,
  type NetworkInterface,
  type ObjectRelations,
  type DirectionPoint,
  type PortProfile,
  type PortPoint,
  type ProtocolPoint,
  type ReportOverview,
  type RuleFinding,
  type SearchResult,
  type SecurityInsight,
  type SecurityIncident,
  type SecurityIncidentContext,
  type IncidentTimelineEntry,
  type ServiceAnalytics,
  type ServiceExposure,
  type ServiceMap,
  type SessionRow,
  type SeriesPoint,
  type Summary,
  type SystemSettings,
  type SystemStatus,
  type SettingsTestResult,
  type TrafficAnalysis,
  type TrafficAnomaly,
  type TrafficChange,
  type TopItem,
  type WindowRow
} from './services/api';

const summary = ref<Summary>({ bytes: 0, packets: 0, utilization: 0 });
const series = ref<SeriesPoint[]>([]);
const topSrc = ref<TopItem[]>([]);
const topDst = ref<TopItem[]>([]);
const topPorts = ref<TopItem[]>([]);
const topProtocols = ref<TopItem[]>([]);
const topFlows = ref<TopItem[]>([]);
const topPairs = ref<TopItem[]>([]);
const topPacketLens = ref<TopItem[]>([]);
const topServices = ref<TopItem[]>([]);
const topServiceCategories = ref<TopItem[]>([]);
const topServiceRisks = ref<TopItem[]>([]);
const topVLANs = ref<TopItem[]>([]);
const topDSCP = ref<TopItem[]>([]);
const topECN = ref<TopItem[]>([]);
const collectors = ref<Collector[]>([]);
const alerts = ref<AlertEvent[]>([]);
const auditEvents = ref<AuditEvent[]>([]);
const configVersions = ref<ConfigVersion[]>([]);
const selectedConfigDiff = ref<ConfigDiff | null>(null);
const emptySystemSettings = (): SystemSettings => ({
  ai: {
    mode: 'local_mock',
    provider: 'local_mock',
    model: 'nexaflow-local-summary',
    base_url: '',
    api_key: '',
    api_key_set: false,
    api_key_masked: '',
    max_context_rows: 12,
    timeout_seconds: 30,
    temperature: 0.2,
    enabled_summaries: true
  },
  analysis: {
    default_minutes: 15,
    baseline_minutes: 120,
    baseline_deviation_warning: 1.8,
    baseline_deviation_critical: 3,
    baseline_min_bytes: 1048576,
    bandwidth_mbps: 1000,
    report_default_minutes: 60
  },
  security: {
    auth_enabled: false,
    readonly_enabled: false,
    admin_password: '',
    readonly_password: '',
    admin_password_set: false,
    readonly_password_set: false,
    session_ttl_hours: 12,
    require_audit_for_write: true,
    allow_frontend_secrets: true
  },
  notification: {
    enabled: false,
    provider: 'webhook',
    webhook_url: '',
    webhook_token: '',
    webhook_token_set: false,
    webhook_token_masked: '',
    min_severity: 'critical',
    notify_on_incident: false,
    notify_on_report: false,
    channels: []
  },
  data: {
    clickhouse_retention_days: 30,
    audit_retention_days: 180,
    config_version_limit: 200,
    session_retention_days: 30,
    export_enabled: true
  },
  backend: {
    api_addr: '0.0.0.0:8080',
    clickhouse_url: '',
    redis_addr: '',
    database: 'nexaflow',
    requires_restart: true
  },
  updated_at: 0
});
const systemSettings = ref<SystemSettings>(emptySystemSettings());
const interfaces = ref<NetworkInterface[]>([]);
const systemStatus = ref<SystemStatus>({ database: 'unknown', latest_window_ts: 0, windows_24h: 0, sources_24h: 0, interfaces_24h: 0 });
const emptyDataQuality = (): DataQuality => ({
  generated_at: 0,
  minutes: 15,
  status: 'unknown',
  window_interval: 5,
  summary: {
    latest_window_ts: 0,
    freshness_seconds: 0,
    expected_windows: 0,
    observed_windows: 0,
    coverage_ratio: 0,
    gap_count: 0,
    stale_sources: 0,
    source_count: 0,
    interface_count: 0,
    bytes: 0,
    packets: 0,
    drops: 0,
    max_utilization: 0
  },
  sources: [],
  gaps: [],
  recommendations: [],
  degraded_reasons: []
});
const dataQuality = ref<DataQuality>(emptyDataQuality());
const emptyCaptureQuality = (): CaptureQuality => ({
  generated_at: 0,
  minutes: 15,
  status: 'unknown',
  summary: {
    windows: 0,
    rx_bytes: 0,
    rx_packets: 0,
    rx_dropped: 0,
    rx_errors: 0,
    tx_bytes: 0,
    tx_packets: 0,
    tx_dropped: 0,
    tx_errors: 0,
    packet_queue_len: 0,
    window_queue_len: 0,
    queue_pressure: 0,
    drop_ratio: 0,
    error_ratio: 0,
    source_count: 0,
    interface_count: 0,
    latest_window_ts: 0
  },
  sources: [],
  recommendations: []
});
const captureQuality = ref<CaptureQuality>(emptyCaptureQuality());
const emptyCaptureDiagnostics = (): CaptureDiagnostics => ({
  generated_at: 0,
  minutes: 15,
  status: 'unknown',
  summary: {
    layer_count: 0,
    critical_layers: 0,
    warning_layers: 0
  },
  layers: [],
  recommendations: []
});
const captureDiagnostics = ref<CaptureDiagnostics>(emptyCaptureDiagnostics());
const alertConfig = ref<AlertConfig>({ flow_bytes: 20480, flow_share: 0.3, source_packets: 50, link_utilization: 0.8 });
const ipProfile = ref<IPProfile>({
  ip: '10.2.0.12',
  minutes: 15,
  inbound_bytes: 0,
  inbound_packets: 0,
  outbound_bytes: 0,
  outbound_packets: 0,
  top_pairs: [],
  top_flows: [],
  last_seen: 0
});
const portProfile = ref<PortProfile>({ port: '8081', minutes: 15, bytes: 0, packets: 0, flows: [] });
const historyWindows = ref<WindowRow[]>([]);
const matrixRows = ref<MatrixRow[]>([]);
const serviceMap = ref<ServiceMap>({ nodes: [], links: [] });
const emptyServiceAnalytics = (): ServiceAnalytics => ({
  generated_at: 0,
  minutes: 15,
  summary: {
    service_count: 0,
    category_count: 0,
    high_risk_services: 0,
    total_bytes: 0,
    total_packets: 0,
    top_service: '-',
    top_risk: '-'
  },
  services: [],
  categories: [],
  risks: [],
  growth: [],
  ports: [],
  details: []
});
const serviceAnalytics = ref<ServiceAnalytics>(emptyServiceAnalytics());
const serviceExposure = ref<ServiceExposure[]>([]);
const externalAccess = ref<ExternalAccess[]>([]);
const protocolSeries = ref<ProtocolPoint[]>([]);
const portSeries = ref<PortPoint[]>([]);
const directionSeries = ref<DirectionPoint[]>([]);
const dimensionTrend = ref<DimensionPoint[]>([]);
const emptyObjectRelations = (): ObjectRelations => ({
  dimension: 'service',
  key: '',
  direction: 'src',
  minutes: 15,
  summary: { key: '全部对象', bytes: 0, packets: 0, related_count: 0 },
  related_ips: [],
  related_ports: [],
  related_services: [],
  related_flows: [],
  insights: []
});
const objectRelations = ref<ObjectRelations>(emptyObjectRelations());
const emptyIncidentContext = (): SecurityIncidentContext => ({
  subject: '',
  kind: '',
  minutes: 15,
  selector: { dimension: 'flow', key: '', query: '', direction: 'src' },
  relations: emptyObjectRelations(),
  sessions: [],
  search_results: [],
  insights: [],
  anomalies: [],
  playbook_actions: []
});
const emptyReportOverview = (): ReportOverview => ({
  generated_at: 0,
  minutes: 15,
  summary: {
    minutes: 15,
    bytes: 0,
    packets: 0,
    utilization: 0,
    asset_count: 0,
    critical_assets: 0,
    open_incidents: 0,
    critical_incidents: 0,
    anomaly_count: 0,
    critical_anomalies: 0,
    exposed_services: 0,
    high_risk_services: 0,
    external_access: 0,
    external_session_sum: 0,
    avg_mbps: 0,
    peak_mbps: 0,
    p95_mbps: 0
  },
  asset_risks: [],
  incidents: [],
  anomalies: [],
  exposures: [],
  external_access: [],
  top_src: [],
  top_ports: [],
  top_services: [],
  recommendations: []
});
const emptyAISummary = (kind = 'report', subject = ''): AISummary => ({
  enabled: false,
  mode: 'local_mock',
  provider: 'local_mock',
  model: 'nexaflow-local-summary',
  kind,
  subject,
  title: 'AI 摘要生成中',
  summary: '等待上下文数据加载完成后生成摘要。',
  confidence: 0,
  findings: [],
  evidence: [],
  actions: [],
  generated_at: 0
});
const emptyAIQueryResult = (): AIQueryResult => ({
  enabled: false,
  mode: 'local_mock',
  provider: 'local_mock',
  model: 'nexaflow-local-summary',
  question: '',
  intent: {
    id: 'top_src',
    title: '源 IP 流量排行',
    description: '按现有白名单查询模板返回排行和解释。',
    api: '/api/v1/traffic/topn',
    question: '',
    minutes: 15,
    limit: 8,
    params: {}
  },
  title: 'AI 查询结果',
  summary: '输入中文问题后，系统会先解析查询意图，再调用白名单 API 返回证据和建议。',
  confidence: 0,
  findings: [],
  evidence: [],
  actions: [],
  rows: [],
  followups: ['最近 30 分钟哪个公网 IP 访问最多？', '有没有新增的高风险端口暴露？'],
  generated_at: 0
});
const emptyAIIncidentInvestigation = (): AIIncidentInvestigation => ({
  enabled: false,
  mode: 'local_mock',
  provider: 'local_mock',
  model: 'nexaflow-local-summary',
  subject: '',
  summary: emptyAISummary('incident'),
  root_causes: [],
  evidence_chain: [],
  next_steps: [],
  context: emptyIncidentContext(),
  timeline: [],
  generated_at: 0
});
const emptyAIGovernanceSuggestions = (): AIGovernanceSuggestions => ({
  enabled: false,
  mode: 'local_mock',
  provider: 'local_mock',
  model: 'nexaflow-local-summary',
  minutes: 15,
  summary: '等待流量、事件和资产上下文加载后生成治理建议。',
  suggestions: [],
  generated_at: 0
});
const emptyAIRuleEffectiveness = (): AIRuleEffectiveness => ({
  enabled: false,
  mode: 'local_mock',
  provider: 'local_mock',
  model: 'nexaflow-local-summary',
  summary: {
    minutes: 15,
    rule_count: 0,
    enabled_rules: 0,
    disabled_rules: 0,
    total_hits: 0,
    critical_hits: 0,
    noisy_rules: 0,
    quiet_rules: 0,
    health: '等待规则数据'
  },
  rules: [],
  tuning_suggestions: [],
  generated_at: 0
});
const emptyAIAssetEnrichmentSuggestions = (): AIAssetEnrichmentSuggestions => ({
  enabled: false,
  mode: 'local_mock',
  provider: 'local_mock',
  model: 'nexaflow-local-summary',
  minutes: 15,
  summary: '等待资产风险和公网访问上下文加载后生成资产画像补全建议。',
  suggestions: [],
  generated_at: 0
});
const searchTerm = ref('10.2.0.12');
const searchResults = ref<SearchResult[]>([]);
const sessions = ref<SessionRow[]>([]);
const assets = ref<AssetRow[]>([]);
const assetRisks = ref<AssetRiskPosture[]>([]);
const assetEditor = ref<AssetMetadata | null>(null);
const assetTagsText = ref('');
const securityInsights = ref<SecurityInsight[]>([]);
const securityIncidents = ref<SecurityIncident[]>([]);
const incidentContext = ref<SecurityIncidentContext>(emptyIncidentContext());
const selectedIncident = ref<SecurityIncident | null>(null);
const incidentTimeline = ref<IncidentTimelineEntry[]>([]);
const incidentAISummary = ref<AISummary>(emptyAISummary('incident'));
const incidentInvestigation = ref<AIIncidentInvestigation>(emptyAIIncidentInvestigation());
const incidentNoteText = ref('');
const savingIncidentNote = ref(false);
const reportOverview = ref<ReportOverview>(emptyReportOverview());
const assetAISummary = ref<AISummary>(emptyAISummary('asset'));
const reportAISummary = ref<AISummary>(emptyAISummary('report'));
const aiQuestion = ref('最近 30 分钟哪个公网 IP 访问最多？');
const aiQueryResult = ref<AIQueryResult>(emptyAIQueryResult());
const aiGovernance = ref<AIGovernanceSuggestions>(emptyAIGovernanceSuggestions());
const aiRuleEffectiveness = ref<AIRuleEffectiveness>(emptyAIRuleEffectiveness());
const aiAssetEnrichment = ref<AIAssetEnrichmentSuggestions>(emptyAIAssetEnrichmentSuggestions());
const aiApprovals = ref<AIApprovalRequest[]>([]);
const aiApprovalBusy = ref('');
const queryingAI = ref(false);
const detectionRules = ref<DetectionRule[]>([]);
const ruleFindings = ref<RuleFinding[]>([]);
const ruleEditor = ref<DetectionRule | null>(null);
const trafficChanges = ref<TrafficChange[]>([]);
const trafficAnomalies = ref<TrafficAnomaly[]>([]);
const emptyBehaviorBaseline = (): BehaviorBaseline => ({
  generated_at: 0,
  minutes: 15,
  baseline_minutes: 60,
  window_count: 0,
  baseline_strategy: 'dynamic_window',
  link: {
    dimension: 'link',
    dimension_title: '链路',
    key: '链路总流量',
    current_bytes: 0,
    current_packets: 0,
    baseline_bytes: 0,
    baseline_packets: 0,
    p95_bytes: 0,
    peak_bytes: 0,
    peak_packets: 0,
    delta_bytes: 0,
    deviation_ratio: 0,
    change_ratio: 0,
    samples: 0,
    status: 'learning',
    severity: 'info',
    score: 0,
    summary: '等待基线样本生成。',
    dimension_source: 'link'
  },
  summary: {
    total_deviations: 0,
    critical_count: 0,
    warning_count: 0,
    new_count: 0,
    learning_count: 0,
    stable_count: 0,
    top_key: '',
    top_dimension: '',
    top_deviation: 0,
    link_status: 'learning',
    link_deviation: 0,
    link_current_bytes: 0
  },
  deviations: [],
  recommendations: []
});
const behaviorBaseline = ref<BehaviorBaseline>(emptyBehaviorBaseline());
const trafficAnalysis = ref<TrafficAnalysis>({
  minutes: 15,
  baseline: {
    windows: 0,
    avg_bytes: 0,
    peak_bytes: 0,
    p95_bytes: 0,
    avg_packets: 0,
    peak_packets: 0,
    avg_utilization: 0,
    peak_utilization: 0,
    avg_mbps: 0,
    peak_mbps: 0,
    p95_mbps: 0,
    burst_ratio: 0
  },
  protocol_mix: [],
  port_mix: [],
  packet_sizes: [],
  directions: []
});
const emptyCapacityPlanning = (): CapacityPlanning => ({
  generated_at: 0,
  minutes: 15,
  summary: {
    minutes: 15,
    bandwidth_mbps: 0,
    avg_mbps: 0,
    peak_mbps: 0,
    p95_mbps: 0,
    previous_peak_mbps: 0,
    growth_mbps: 0,
    growth_ratio: 0,
    headroom_mbps: 0,
    headroom_ratio: 0,
    peak_utilization: 0,
    p95_utilization: 0,
    saturation_eta_mins: 0,
    risk_level: 'healthy'
  },
  trend: [],
  top_src_growth: [],
  top_port_growth: [],
  top_service_growth: [],
  recommendations: []
});
const capacityPlanning = ref<CapacityPlanning>(emptyCapacityPlanning());
const degraded = ref(false);
const loading = ref(false);
const authChecking = ref(true);
const authStatus = ref<AuthStatus>({ enabled: false, authenticated: true, actor: 'operator', role: 'admin', can_write: true });
const loginActor = ref('operator');
const loginPassword = ref('');
const loginError = ref('');
const loggingIn = ref(false);
const switching = ref(false);
const savingAlerts = ref(false);
const savingAsset = ref(false);
const savingRule = ref(false);
const diffingConfigVersion = ref('');
const restoringConfigVersion = ref('');
const handlingAlert = ref(false);
const loadingIncidentContext = ref(false);
const savingSettings = ref(false);
const settingsTestResult = ref<SettingsTestResult | null>(null);
const webhookTestResult = ref<SettingsTestResult | null>(null);
const settingsImportText = ref('');
const settingsExportText = ref('');
const currentView = ref('dashboard');
const activeTopN = ref('src_ip');
const selectedMinutes = ref(15);
const profileIP = ref('10.2.0.12');
const profilePort = ref('8081');
const selectedMode = ref('live_pcap');
const selectedIface = ref('eth0');
const selectedFilter = ref('ip or ip6');
const selectedPcapFile = ref('/var/lib/nexaflow/replay.pcap');
const selectedReplaySpeed = ref(1);
const selectedSessionTopN = ref(500);
const trendDimension = ref('service');
const trendKey = ref('');
const trendDirection = ref('src');
const whitelistSubject = ref('');
const exposureSearch = ref('');
const exposureRiskFilter = ref('all');
const exposureCategoryFilter = ref('all');
const sessionSearch = ref('');
let timer: number | undefined;

const navGroups = [
  {
    title: '监控',
    items: [
      { id: 'dashboard', label: '总览大屏', icon: LayoutDashboard },
      { id: 'realtime', label: '实时监控', icon: MonitorDot },
      { id: 'quality', label: '数据质量', icon: Database },
      { id: 'capacity', label: '容量趋势', icon: Gauge },
      { id: 'traffic', label: '流量剖析', icon: ChartNoAxesCombined }
    ]
  },
  {
    title: '分析',
    items: [
      { id: 'ai', label: 'AI 分析', icon: Sparkles },
      { id: 'baseline', label: '行为基线', icon: Radar },
      { id: 'analysis', label: '流向分析', icon: Route },
      { id: 'anomalies', label: '异常波动', icon: AlertTriangle },
      { id: 'service-analytics', label: '应用分析', icon: ServerCog },
      { id: 'topology', label: '服务拓扑', icon: Network },
      { id: 'topn', label: 'TopN 分析', icon: ListOrdered },
      { id: 'sessions', label: '会话追踪', icon: Waypoints },
      { id: 'profile', label: '对象画像', icon: Radar },
      { id: 'port', label: '端口画像', icon: CircleGauge }
    ]
  },
  {
    title: '治理',
    items: [
      { id: 'exposure', label: '服务暴露', icon: ServerCog },
      { id: 'external', label: '公网访问', icon: RadioTower },
      { id: 'assets', label: '资产发现', icon: HardDrive },
      { id: 'asset-risk', label: '资产风险', icon: Shield },
      { id: 'security', label: '风险线索', icon: Shield },
      { id: 'incidents', label: '事件中心', icon: Shield },
      { id: 'rules', label: '规则中心', icon: Settings2 },
      { id: 'alerts', label: '告警中心', icon: AlertTriangle }
    ]
  },
  {
    title: '工具',
    items: [
      { id: 'reports', label: '报表中心', icon: FileText },
      { id: 'search', label: '检索分析', icon: Search },
      { id: 'history', label: '历史回放', icon: History },
      { id: 'audit', label: '审计日志', icon: ClipboardList },
      { id: 'config-versions', label: '配置版本', icon: History },
      { id: 'settings', label: '系统设置', icon: Settings2 },
      { id: 'collectors', label: '采集器', icon: Settings2 }
    ]
  }
];

const viewMeta: Record<string, { title: string; subtitle: string }> = {
  dashboard: { title: '流量总览', subtitle: '近实时流量、采集健康和关键对象排行' },
  realtime: { title: '实时监控', subtitle: '采集窗口、吞吐、包速率和采集器健康状态' },
  quality: { title: '数据质量', subtitle: '核对采集窗口覆盖率、断档、延迟、采集源和网卡健康状态' },
  capacity: { title: '容量趋势', subtitle: '评估带宽余量、峰值增长、P95 利用率和容量风险对象' },
  traffic: { title: '流量剖析', subtitle: '观察基线、峰值、P95、方向、协议、端口和包长结构' },
  ai: { title: 'AI 分析', subtitle: '集中查看巡检、事件和资产 AI 摘要，快速进入调查闭环' },
  baseline: { title: '行为基线', subtitle: '用历史同长度窗口对比当前对象，识别新增、偏离和样本不足的流量行为' },
  analysis: { title: '流向分析', subtitle: '按主机对、会话、端口和协议拆解实时流量路径' },
  anomalies: { title: '异常波动', subtitle: '对比当前窗口和上一周期，识别链路、对象、端口、协议和服务突变' },
  'service-analytics': { title: '应用分析', subtitle: '按应用服务聚合类别、风险、增长、端口和会话样例' },
  topology: { title: '服务拓扑', subtitle: '基于主机对流量构建节点和链路视图' },
  exposure: { title: '服务暴露', subtitle: '识别目的 IP 上的服务端口、协议、服务类型和风险级别' },
  external: { title: '公网访问', subtitle: '聚合公网对端、内部资产、访问方向、服务端口和风险' },
  assets: { title: '资产发现', subtitle: '按活跃 IP 聚合收发流量、角色和最近出现时间' },
  'asset-risk': { title: '资产风险', subtitle: '按资产聚合暴露面、异常、事件和公网访问，给出处置优先级' },
  security: { title: '风险线索', subtitle: '从重流量会话、敏感端口和主机扇出中提取排查线索' },
  incidents: { title: '事件中心', subtitle: '汇总阈值告警、风险线索和异常波动，形成统一处置事件流' },
  rules: { title: '规则中心', subtitle: '配置自定义检测规则，查看实时命中对象并沉淀处置动作' },
  profile: { title: '对象画像', subtitle: '围绕单个 IP 查看收发流量、关联主机对和活跃会话' },
  port: { title: '端口画像', subtitle: '围绕目的端口查看流量规模和关联会话' },
  topn: { title: 'TopN 分析', subtitle: '按 IP、端口、协议和会话维度定位主要流量对象' },
  sessions: { title: '会话追踪', subtitle: '结构化查看源/目的、端口、协议、服务、方向和风险' },
  alerts: { title: '告警中心', subtitle: '查看阈值、采集健康和异常事件' },
  reports: { title: '报表中心', subtitle: '汇总资产风险、事件、异常、暴露面和 Top 流量对象，支持巡检导出' },
  search: { title: '检索分析', subtitle: '按 IP、端口、主机对或会话关键字检索流量对象' },
  history: { title: '历史回放', subtitle: '回看采集窗口明细，辅助排查短时峰值' },
  audit: { title: '审计日志', subtitle: '追踪配置变更、事件处置、规则调整和白名单操作' },
  'config-versions': { title: '配置版本', subtitle: '回溯采集、告警、规则和白名单的运行时配置快照' },
  settings: { title: '系统设置', subtitle: '统一管理大模型、分析参数、安全权限、通知集成、数据保留和后台连接配置' },
  collectors: { title: '采集器', subtitle: '查看采集源、运行模式和服务状态' }
};

const pageTitle = computed(() => viewMeta[currentView.value]?.title ?? '流量总览');
const pageSubtitle = computed(() => viewMeta[currentView.value]?.subtitle ?? '近实时流量、采集健康和关键对象排行');
const canWrite = computed(() => !authStatus.value.enabled || authStatus.value.can_write !== false);
const authRoleText = computed(() => {
  if (!authStatus.value.enabled) return '免登录';
  return authStatus.value.role === 'viewer' ? '观察员' : '管理员';
});
const rangeSeconds = computed(() => selectedMinutes.value * 60);
const rangeLabel = computed(() => {
  if (selectedMinutes.value >= 1440) return '24 小时';
  if (selectedMinutes.value >= 60) return `${selectedMinutes.value / 60} 小时`;
  return `${selectedMinutes.value} 分钟`;
});
const rangeOptions = [
  { value: 5, label: '5 分钟' },
  { value: 15, label: '15 分钟' },
  { value: 60, label: '1 小时' },
  { value: 360, label: '6 小时' },
  { value: 1440, label: '24 小时' }
];

const refresh = async () => {
  if (authStatus.value.enabled && !authStatus.value.authenticated) {
    loading.value = false;
    return;
  }
  loading.value = true;
  try {
    const minutes = selectedMinutes.value;
    const [
      summaryRes,
      seriesRes,
      srcRes,
      dstRes,
      portRes,
      protoRes,
      packetLenRes,
      serviceRes,
      serviceCategoryRes,
      serviceRiskRes,
      vlanRes,
      dscpRes,
      ecnRes,
      flowRes,
      pairRes,
      collectorRes,
      alertRes,
      interfaceRes,
      statusRes,
      dataQualityRes,
      captureQualityRes,
      captureDiagnosticsRes,
      windowsRes,
      alertConfigRes,
      matrixRes,
      serviceMapRes,
      serviceAnalyticsRes,
      serviceExposureRes,
      externalAccessRes,
      protocolSeriesRes,
      portSeriesRes,
      directionSeriesRes,
      sessionsRes,
      assetsRes,
      assetRiskRes,
      securityRes,
      incidentRes,
      trafficAnalysisRes,
      behaviorBaselineRes,
      capacityRes,
      trafficChangesRes,
      trafficAnomaliesRes,
      reportRes,
      reportAIRes,
      governanceRes,
      ruleEffectivenessRes,
      assetEnrichmentRes,
      approvalRes,
      ruleFindingRes,
      auditRes,
      configVersionRes,
      systemSettingsRes
    ] = await Promise.all([
      api.summary(minutes),
      api.timeseries(minutes),
      api.topn('ip', 'src', minutes),
      api.topn('ip', 'dst', minutes),
      api.topn('dst_port', 'src', minutes),
      api.topn('protocol', 'src', minutes),
      api.topn('packet_len', 'src', minutes),
      api.topn('service', 'src', minutes),
      api.topn('service_category', 'src', minutes),
      api.topn('service_risk', 'src', minutes),
      api.topn('vlan', 'src', minutes),
      api.topn('dscp', 'src', minutes),
      api.topn('ecn', 'src', minutes),
      api.topn('flow', 'src', minutes),
      api.topn('pair', 'src', minutes),
      api.collectors(),
      api.alerts(minutes),
      api.interfaces(),
      api.status(),
      api.dataQuality(minutes, 80),
      api.captureQuality(minutes, 80),
      api.captureDiagnostics(minutes, 80),
      api.windows(minutes, 80),
      api.alertConfig(),
      api.matrix(minutes, 80),
      api.serviceMap(minutes, 80),
      api.serviceAnalytics(minutes, 12),
      api.serviceExposure(minutes, 120),
      api.externalAccess(minutes, 160),
      api.protocolTimeseries(minutes),
      api.portTimeseries(minutes, 8),
      api.directionTimeseries(minutes),
      api.sessions(sessionSearch.value.trim(), minutes, 120),
      api.assets(minutes, 100),
      api.assetRiskPosture(minutes, 120),
      api.securityInsights(minutes, 100),
      api.securityIncidents(minutes, 120),
      api.trafficAnalysis(minutes),
      api.behaviorBaseline(minutes, 0, 12),
      api.capacityPlanning(minutes, 12),
      api.trafficChanges(minutes, 30),
      api.trafficAnomalies(minutes, 40),
      api.reportOverview(minutes, 12),
      api.aiReportSummary(minutes, 12),
      api.aiGovernanceSuggestions(minutes, 8),
      api.aiRuleEffectiveness(minutes, 120),
      api.aiAssetEnrichmentSuggestions(minutes, 8),
      api.aiApprovalRequests(''),
      api.ruleFindings(minutes, 100),
      api.auditEvents(120),
      api.configVersions('', 120),
      api.systemSettings()
    ]);
    summary.value = summaryRes.data;
    series.value = seriesRes.data;
    topSrc.value = srcRes.data;
    topDst.value = dstRes.data;
    topPorts.value = portRes.data;
    topProtocols.value = protoRes.data;
    topPacketLens.value = packetLenRes.data;
    topServices.value = serviceRes.data;
    topServiceCategories.value = serviceCategoryRes.data;
    topServiceRisks.value = serviceRiskRes.data;
    topVLANs.value = vlanRes.data;
    topDSCP.value = dscpRes.data;
    topECN.value = ecnRes.data;
    topFlows.value = flowRes.data;
    topPairs.value = pairRes.data;
    collectors.value = collectorRes.data;
    alerts.value = alertRes.data;
    interfaces.value = interfaceRes.data;
    systemStatus.value = statusRes.data;
    dataQuality.value = dataQualityRes.data;
    captureQuality.value = captureQualityRes.data;
    captureDiagnostics.value = captureDiagnosticsRes.data;
    historyWindows.value = windowsRes.data;
    alertConfig.value = alertConfigRes.data;
    detectionRules.value = alertConfigRes.data.detection_rules ?? [];
    matrixRows.value = matrixRes.data;
    serviceMap.value = serviceMapRes.data;
    serviceAnalytics.value = serviceAnalyticsRes.data;
    serviceExposure.value = serviceExposureRes.data;
    externalAccess.value = externalAccessRes.data;
    protocolSeries.value = protocolSeriesRes.data;
    portSeries.value = portSeriesRes.data;
    directionSeries.value = directionSeriesRes.data;
    sessions.value = sessionsRes.data;
    assets.value = assetsRes.data;
    assetRisks.value = assetRiskRes.data;
    securityInsights.value = securityRes.data;
    securityIncidents.value = incidentRes.data;
    trafficAnalysis.value = trafficAnalysisRes.data;
    behaviorBaseline.value = behaviorBaselineRes.data;
    capacityPlanning.value = capacityRes.data;
    trafficChanges.value = trafficChangesRes.data;
    trafficAnomalies.value = trafficAnomaliesRes.data;
    reportOverview.value = reportRes.data;
    reportAISummary.value = reportAIRes.data;
    aiGovernance.value = governanceRes.data;
    aiRuleEffectiveness.value = ruleEffectivenessRes.data;
    aiAssetEnrichment.value = assetEnrichmentRes.data;
    aiApprovals.value = approvalRes.data;
    ruleFindings.value = ruleFindingRes.data;
    auditEvents.value = auditRes.data;
    configVersions.value = configVersionRes.data;
    systemSettings.value = normalizeSettingsForForm(systemSettingsRes.data);
    let nextDegraded =
      summaryRes.degraded ||
      seriesRes.degraded ||
      srcRes.degraded ||
      packetLenRes.degraded ||
      serviceRes.degraded ||
      serviceCategoryRes.degraded ||
      serviceRiskRes.degraded ||
      vlanRes.degraded ||
      dscpRes.degraded ||
      ecnRes.degraded ||
      alertRes.degraded ||
      statusRes.degraded ||
      dataQualityRes.degraded ||
      captureQualityRes.degraded ||
      captureDiagnosticsRes.degraded ||
      windowsRes.degraded ||
      matrixRes.degraded ||
      serviceMapRes.degraded ||
      serviceAnalyticsRes.degraded ||
      serviceExposureRes.degraded ||
      externalAccessRes.degraded ||
      protocolSeriesRes.degraded ||
      portSeriesRes.degraded ||
      directionSeriesRes.degraded ||
      sessionsRes.degraded ||
      assetsRes.degraded ||
      assetRiskRes.degraded ||
      securityRes.degraded ||
      incidentRes.degraded ||
      trafficAnalysisRes.degraded ||
      behaviorBaselineRes.degraded ||
      capacityRes.degraded ||
      trafficChangesRes.degraded ||
      trafficAnomaliesRes.degraded ||
      reportRes.degraded ||
      reportAIRes.degraded ||
      governanceRes.degraded ||
      ruleEffectivenessRes.degraded ||
      assetEnrichmentRes.degraded ||
      approvalRes.degraded ||
      ruleFindingRes.degraded ||
      auditRes.degraded ||
      configVersionRes.degraded;
    if (assetRisks.value[0]) {
      const assetAIRes = await api.aiAssetSummary(assetRisks.value[0].ip, minutes, 20);
      assetAISummary.value = assetAIRes.data;
      nextDegraded = nextDegraded || assetAIRes.degraded;
    } else {
      assetAISummary.value = emptyAISummary('asset');
    }
    if (securityIncidents.value[0]) {
      const incident = securityIncidents.value[0];
      const [incidentAIRes, investigationRes] = await Promise.all([
        api.aiIncidentSummary(incident.subject, incident.kind, incident.id, minutes, 12),
        api.aiIncidentInvestigation(incident.subject, incident.kind, incident.id, minutes, 12)
      ]);
      incidentAISummary.value = incidentAIRes.data;
      incidentInvestigation.value = investigationRes.data;
      nextDegraded = nextDegraded || incidentAIRes.degraded || investigationRes.degraded;
    } else {
      incidentAISummary.value = emptyAISummary('incident');
      incidentInvestigation.value = emptyAIIncidentInvestigation();
    }
    if (!profileIP.value && srcRes.data[0]) {
      profileIP.value = srcRes.data[0].key;
    }
    if (profileIP.value) {
      const profileRes = await api.ipProfile(profileIP.value, minutes);
      ipProfile.value = profileRes.data;
      nextDegraded = nextDegraded || profileRes.degraded;
    }
    if (profilePort.value) {
      const portProfileRes = await api.portProfile(profilePort.value, minutes);
      portProfile.value = portProfileRes.data;
      nextDegraded = nextDegraded || portProfileRes.degraded;
    }
    if (searchTerm.value) {
      const searchRes = await api.search(searchTerm.value, minutes, 80);
      searchResults.value = searchRes.data;
      nextDegraded = nextDegraded || searchRes.degraded;
    }
    if (!trendKey.value && topServices.value[0]) {
      trendKey.value = topServices.value[0].key;
    }
    const [trendRes, relationRes] = await Promise.all([
      api.dimensionTimeseries(trendDimension.value, trendKey.value.trim(), minutes, trendDirection.value, 5),
      api.objectRelations(trendDimension.value, trendKey.value.trim(), minutes, trendDirection.value, 8)
    ]);
    dimensionTrend.value = trendRes.data;
    objectRelations.value = relationRes.data;
    nextDegraded = nextDegraded || trendRes.degraded || relationRes.degraded;
    if (collectorRes.data[0]) {
      selectedMode.value = collectorRes.data[0].mode;
      selectedIface.value = collectorRes.data[0].iface ?? selectedIface.value;
      selectedFilter.value = collectorRes.data[0].bpf_filter ?? selectedFilter.value;
      selectedPcapFile.value = collectorRes.data[0].pcap_file ?? selectedPcapFile.value;
      selectedReplaySpeed.value = collectorRes.data[0].replay_speed ?? selectedReplaySpeed.value;
      selectedSessionTopN.value = collectorRes.data[0].session_topn ?? selectedSessionTopN.value;
    }
    degraded.value = nextDegraded;
  } catch {
    summary.value = { bytes: 125829120, packets: 94281, utilization: 0.18 };
    const now = Math.floor(Date.now() / 1000);
    series.value = Array.from({ length: 12 }, (_, index) => ({
      ts: now - (11 - index) * 60,
      bytes: 40000000 + index * 3200000,
      packets: 24000 + index * 900
    }));
    topSrc.value = [
      { key: '10.10.1.42', bytes: 68000000, packets: 21000 },
      { key: '10.10.1.77', bytes: 24000000, packets: 9000 },
      { key: '10.10.1.18', bytes: 13000000, packets: 7000 }
    ];
    topDst.value = [
      { key: '172.20.2.10', bytes: 52000000, packets: 18000 },
      { key: '172.20.2.81', bytes: 21000000, packets: 8000 },
      { key: '172.20.2.144', bytes: 11000000, packets: 6000 }
    ];
    topPorts.value = [
      { key: '443', bytes: 88000000, packets: 48000 },
      { key: '80', bytes: 22000000, packets: 15000 },
      { key: '53', bytes: 6000000, packets: 18000 }
    ];
    topProtocols.value = [
      { key: 'tcp', bytes: 109000000, packets: 72000 },
      { key: 'udp', bytes: 15000000, packets: 22000 }
    ];
    topFlows.value = [
      { key: '10.10.1.42:53210 -> 172.20.2.10:443 / tcp', bytes: 42000000, packets: 14000 },
      { key: '10.10.1.77:53192 -> 172.20.2.81:80 / tcp', bytes: 18000000, packets: 7200 },
      { key: '10.10.1.18:49812 -> 172.20.2.144:53 / udp', bytes: 5000000, packets: 12000 }
    ];
    topPacketLens.value = [
      { key: '1KB-MTU', bytes: 82000000, packets: 56000 },
      { key: '65-128B', bytes: 9000000, packets: 80000 }
    ];
    topServices.value = [
      { key: 'HTTPS', bytes: 88000000, packets: 48000 },
      { key: 'HTTP', bytes: 22000000, packets: 15000 },
      { key: 'DNS', bytes: 6000000, packets: 18000 }
    ];
    topServiceCategories.value = [
      { key: 'Web', bytes: 110000000, packets: 63000 },
      { key: '基础网络', bytes: 6000000, packets: 18000 }
    ];
    topServiceRisks.value = [
      { key: 'low', bytes: 116000000, packets: 81000 },
      { key: 'medium', bytes: 18000000, packets: 7200 }
    ];
    topVLANs.value = [
      { key: 'untagged', bytes: 128000000, packets: 90000 },
      { key: '100', bytes: 6400000, packets: 3100 }
    ];
    topDSCP.value = [
      { key: 'BE', bytes: 108000000, packets: 76000 },
      { key: 'AF11', bytes: 18000000, packets: 9000 },
      { key: 'EF', bytes: 6000000, packets: 2200 }
    ];
    topECN.value = [
      { key: 'Not-ECT', bytes: 126000000, packets: 88000 },
      { key: 'ECT(0)', bytes: 4000000, packets: 1200 }
    ];
    topPairs.value = [
      { key: '10.10.1.42 -> 172.20.2.10', bytes: 52000000, packets: 18000 },
      { key: '10.10.1.77 -> 172.20.2.81', bytes: 21000000, packets: 8000 },
      { key: '10.10.1.18 -> 172.20.2.144', bytes: 11000000, packets: 6000 }
    ];
    collectors.value = [{ id: 'dev-collector-01', source_id: 'dev-source-01', status: 'offline', mode: 'mock', bpf_filter: 'ip or ip6', session_topn: 500, updated_at: now }];
    interfaces.value = [{ name: 'eth0', state: 'up', type: 'interface' }];
    systemStatus.value = { database: 'degraded', latest_window_ts: now, windows_24h: 0, sources_24h: 0, interfaces_24h: 0 };
    dataQuality.value = {
      generated_at: now,
      minutes: selectedMinutes.value,
      status: 'warning',
      window_interval: 5,
      summary: {
        latest_window_ts: now - 5,
        freshness_seconds: 5,
        expected_windows: selectedMinutes.value * 12,
        observed_windows: 170,
        coverage_ratio: 0.94,
        gap_count: 1,
        stale_sources: 0,
        source_count: 1,
        interface_count: 1,
        bytes: 158000000,
        packets: 98000,
        drops: 0,
        max_utilization: 0.08
      },
      sources: [
        {
          source_id: 'dev-source-01',
          iface: 'mock0',
          windows: 170,
          bytes: 158000000,
          packets: 98000,
          drops: 0,
          max_utilization: 0.08,
          first_window_ts: now - selectedMinutes.value * 60,
          latest_window_ts: now - 5,
          freshness_seconds: 5,
          coverage_ratio: 0.94,
          status: 'healthy'
        }
      ],
      gaps: [{ source_id: 'dev-source-01', iface: 'mock0', start_ts: now - 480, end_ts: now - 455, duration_seconds: 25, missing_windows: 4 }],
      recommendations: [{ level: 'warning', title: '定位采集断档', detail: '示例采集源存在短时断档，真实数据接入后会自动展示实际断档' }],
      degraded_reasons: ['demo data']
    };
    captureQuality.value = {
      generated_at: now,
      minutes: selectedMinutes.value,
      status: 'healthy',
      summary: {
        windows: 170,
        rx_bytes: 158000000,
        rx_packets: 98000,
        rx_dropped: 0,
        rx_errors: 0,
        tx_bytes: 12000000,
        tx_packets: 9000,
        tx_dropped: 0,
        tx_errors: 0,
        packet_queue_len: 18,
        window_queue_len: 0,
        queue_pressure: 0.0018,
        drop_ratio: 0,
        error_ratio: 0,
        source_count: 1,
        interface_count: 1,
        latest_window_ts: now - 5
      },
      sources: [
        {
          source_id: 'dev-source-01',
          iface: 'mock0',
          windows: 170,
          rx_bytes: 158000000,
          rx_packets: 98000,
          rx_dropped: 0,
          rx_errors: 0,
          tx_bytes: 12000000,
          tx_packets: 9000,
          tx_dropped: 0,
          tx_errors: 0,
          packet_queue_len: 18,
          packet_queue_capacity: 10000,
          window_queue_len: 0,
          window_queue_capacity: 32,
          packet_queue_pressure: 0.0018,
          window_queue_pressure: 0,
          queue_pressure: 0.0018,
          first_window_ts: now - selectedMinutes.value * 60,
          latest_window_ts: now - 5,
          freshness_seconds: 5,
          drop_ratio: 0,
          error_ratio: 0,
          status: 'healthy'
        }
      ],
      recommendations: [{ level: 'info', title: '接口采集稳定', detail: '当前网卡 RX/TX 丢包和错误计数未出现异常增量' }]
    };
    captureDiagnostics.value = {
      generated_at: now,
      minutes: selectedMinutes.value,
      status: 'warning',
      summary: {
        layer_count: 5,
        critical_layers: 0,
        warning_layers: 1
      },
      layers: [
        { id: 'interface_counters', name: '网卡接口计数', status: 'healthy', score: 0, metric: 'Dropped 0 / Errors 0', detail: '网卡 RX/TX 计数未发现异常。', recommendation: '持续观察接口计数变化。' },
        { id: 'packet_queue', name: '用户态包队列', status: 'healthy', score: 1, metric: '队列压力 0.2%', detail: '包队列保持低水位。', recommendation: '维持当前队列容量和过滤范围。' },
        { id: 'window_queue', name: '窗口写入队列', status: 'healthy', score: 0, metric: '队列压力 0.0%', detail: '窗口写入队列无明显堆积。', recommendation: '持续观察 ClickHouse 写入延迟。' },
        { id: 'freshness', name: '数据新鲜度', status: 'healthy', score: 17, metric: '最新延迟 5 秒', detail: '实时窗口延迟处于正常范围。', recommendation: '保持采集器在线和时间同步。' },
        { id: 'storage_windows', name: '窗口覆盖率', status: 'warning', score: 6, metric: '覆盖率 94.0%', detail: '示例数据存在短时窗口断档。', recommendation: '检查采集器重启或 ClickHouse 写入失败时间点。' }
      ],
      recommendations: [{ level: 'warning', title: '窗口覆盖率', detail: '示例数据存在短时窗口断档，真实采集接入后会展示实际诊断建议' }]
    };
    alertConfig.value = { flow_bytes: 20480, flow_share: 0.3, source_packets: 50, link_utilization: 0.8 };
    detectionRules.value = [
      {
        id: 'rule-src-heavy-bytes',
        name: '源 IP 大流量',
        category: '流量阈值',
        metric: 'src_ip_bytes',
        match: '',
        operator: 'gte',
        threshold: 100 * 1024 * 1024,
        severity: 'warning',
        enabled: true,
        description: '识别观察窗口内单个源 IP 的大流量行为',
        recommended_action: '确认源主机业务用途，检查是否存在备份、同步或异常外传行为',
        updated_at: now
      },
      {
        id: 'rule-external-session-burst',
        name: '公网会话突增',
        category: '公网访问',
        metric: 'external_sessions',
        match: '',
        operator: 'gte',
        threshold: 30,
        severity: 'critical',
        enabled: true,
        description: '识别公网对端和内部资产之间的高会话数访问',
        recommended_action: '核对公网来源、服务端口和防火墙策略，必要时收敛来源或加入白名单',
        updated_at: now
      }
    ];
    ipProfile.value = {
      ip: profileIP.value,
      minutes: selectedMinutes.value,
      inbound_bytes: 52000000,
      inbound_packets: 18000,
      outbound_bytes: 68000000,
      outbound_packets: 21000,
      top_pairs: topPairs.value,
      top_flows: topFlows.value,
      last_seen: now
    };
    alerts.value = [
      {
        id: 'demo-api-degraded',
        severity: 'warning',
        status: 'open',
        subject: 'api-server',
        summary: 'API 无法连接后端服务，正在展示本地示例数据',
        first_seen: now,
        last_seen: now
      }
    ];
    auditEvents.value = [
      {
        id: 'audit-demo-collector',
        ts: now - 180,
        actor: 'operator',
        action: 'collector.config.update',
        target: 'dev-collector-01',
        summary: '更新采集器配置：live_pcap / eth0',
        detail: '{"mode":"live_pcap","iface":"eth0","session_topn":500}',
        client_ip: '127.0.0.1'
      },
      {
        id: 'audit-demo-rule',
        ts: now - 420,
        actor: 'operator',
        action: 'detection_rule.upsert',
        target: 'rule-external-session-burst',
        summary: '保存检测规则：公网会话突增',
        detail: '{"metric":"external_sessions","threshold":30}',
        client_ip: '127.0.0.1'
      }
    ];
    configVersions.value = [
      {
        id: 'cfg-demo-collector',
        ts: now - 180,
        actor: 'operator',
        scope: 'collector',
        target: 'dev-collector-01',
        action: 'collector.config.update',
        summary: '更新采集器配置：live_pcap / eth0',
        config: '{"mode":"live_pcap","iface":"eth0","source_id":"live_pcap-eth0","bpf_filter":"ip or ip6","session_topn":500}',
        client_ip: '127.0.0.1'
      },
      {
        id: 'cfg-demo-alerts',
        ts: now - 420,
        actor: 'operator',
        scope: 'alerts',
        target: 'dst_port:22',
        action: 'alert.silence.add',
        summary: '加入白名单/静默名单：dst_port:22',
        config: '{"flow_bytes":20480,"flow_share":0.3,"source_packets":50,"link_utilization":0.8,"silenced_subjects":["dst_port:22"]}',
        client_ip: '127.0.0.1'
      }
    ];
    portProfile.value = { port: profilePort.value, minutes: selectedMinutes.value, bytes: 88000000, packets: 48000, flows: topFlows.value };
    historyWindows.value = series.value
      .slice()
      .reverse()
      .map((point) => ({
        window_ts: point.ts,
        source_id: 'dev-source-01',
        iface: 'mock0',
        bytes: point.bytes,
        packets: point.packets,
        utilization: 0.02
      }));
    matrixRows.value = topPairs.value.map((item) => {
      const [src, dst = ''] = item.key.split(' -> ');
      return { src, dst, bytes: item.bytes, packets: item.packets };
    });
    serviceMap.value = {
      nodes: [
        { ip: '10.10.1.42', bytes: 52000000, packets: 18000 },
        { ip: '172.20.2.10', bytes: 52000000, packets: 18000 }
      ],
      links: matrixRows.value
    };
    serviceAnalytics.value = {
      generated_at: now,
      minutes: selectedMinutes.value,
      summary: {
        service_count: 3,
        category_count: 3,
        high_risk_services: 1,
        total_bytes: 111000000,
        total_packets: 67200,
        top_service: 'HTTPS',
        top_risk: 'low'
      },
      services: [
        { key: 'HTTPS', bytes: 88000000, packets: 48000 },
        { key: 'SSH', bytes: 18000000, packets: 7200 },
        { key: 'DNS', bytes: 5000000, packets: 12000 }
      ],
      categories: [
        { key: 'Web', bytes: 88000000, packets: 48000 },
        { key: '远程管理', bytes: 18000000, packets: 7200 },
        { key: '基础网络', bytes: 5000000, packets: 12000 }
      ],
      risks: [
        { key: 'low', bytes: 93000000, packets: 60000 },
        { key: 'high', bytes: 18000000, packets: 7200 }
      ],
      growth: [
        {
          dimension: 'service',
          key: 'HTTPS',
          current_bytes: 88000000,
          previous_bytes: 52000000,
          delta_bytes: 36000000,
          current_packets: 48000,
          previous_packets: 31000,
          delta_packets: 17000,
          change_ratio: 0.69
        },
        {
          dimension: 'service',
          key: 'SSH',
          current_bytes: 18000000,
          previous_bytes: 0,
          delta_bytes: 18000000,
          current_packets: 7200,
          previous_packets: 0,
          delta_packets: 7200,
          change_ratio: 0
        }
      ],
      ports: [
        {
          service: 'HTTPS',
          port: '443',
          protocol: 'tcp',
          category: 'Web',
          risk: 'low',
          bytes: 88000000,
          packets: 48000,
          sample_flow: '10.10.1.42:53210 -> 172.20.2.10:443 / tcp',
          last_seen: now
        },
        {
          service: 'SSH',
          port: '22',
          protocol: 'tcp',
          category: '远程管理',
          risk: 'high',
          bytes: 18000000,
          packets: 7200,
          sample_flow: '10.10.1.77:53192 -> 172.20.2.81:22 / tcp',
          last_seen: now - 10
        }
      ],
      details: [
        {
          service: 'HTTPS',
          category: 'Web',
          risk: 'low',
          bytes: 88000000,
          packets: 48000,
          client_count: 7,
          server_count: 3,
          session_count: 14,
          top_port: '443/tcp',
          sample_flow: '10.10.1.42:53210 -> 172.20.2.10:443 / tcp',
          first_seen: now - selectedMinutes.value * 60,
          last_seen: now
        },
        {
          service: 'SSH',
          category: '远程管理',
          risk: 'high',
          bytes: 18000000,
          packets: 7200,
          client_count: 2,
          server_count: 1,
          session_count: 3,
          top_port: '22/tcp',
          sample_flow: '10.10.1.77:53192 -> 172.20.2.81:22 / tcp',
          first_seen: now - 600,
          last_seen: now - 10
        }
      ]
    };
    serviceExposure.value = [
      {
        ip: '172.20.2.10',
        port: '443',
        protocol: 'tcp',
        service: 'HTTPS',
        category: 'Web',
        risk: 'low',
        direction: '入站',
        confidence: '高',
        bytes: 42000000,
        packets: 14000,
        client_count: 3,
        sample_client: '10.10.1.42',
        sample_flow: '10.10.1.42:53210 -> 172.20.2.10:443 / tcp'
      },
      {
        ip: '172.20.2.81',
        port: '22',
        protocol: 'tcp',
        service: 'SSH',
        category: '远程管理',
        risk: 'high',
        direction: '入站',
        confidence: '高',
        bytes: 18000000,
        packets: 7200,
        client_count: 2,
        sample_client: '10.10.1.77',
        sample_flow: '10.10.1.77:53192 -> 172.20.2.81:22 / tcp'
      }
    ];
    externalAccess.value = [
      {
        public_ip: '211.93.22.130',
        internal_ip: '10.2.0.12',
        direction: '入站响应',
        port: '8081',
        protocol: 'tcp',
        service: 'HTTP Alternate',
        category: 'Web',
        risk: 'medium',
        bytes: 32000000,
        packets: 24000,
        session_count: 8,
        sample_flow: '10.2.0.12:8081 -> 211.93.22.130:4300 / tcp',
        first_seen: now - 600,
        last_seen: now
      },
      {
        public_ip: '203.0.113.24',
        internal_ip: '10.2.0.12',
        direction: '出站',
        port: '443',
        protocol: 'tcp',
        service: 'HTTPS',
        category: 'Web',
        risk: 'low',
        bytes: 12000000,
        packets: 7800,
        session_count: 4,
        sample_flow: '10.2.0.12:53210 -> 203.0.113.24:443 / tcp',
        first_seen: now - 420,
        last_seen: now - 20
      }
    ];
    protocolSeries.value = [
      { ts: now - 10, protocol: 'tcp', bytes: 109000000, packets: 72000 },
      { ts: now - 10, protocol: 'udp', bytes: 15000000, packets: 22000 }
    ];
    portSeries.value = [
      { ts: now - 10, port: '443', bytes: 42000000, packets: 14000 },
      { ts: now - 10, port: '80', bytes: 18000000, packets: 7200 }
    ];
    directionSeries.value = [
      { ts: now - 10, direction: '出站', bytes: 76000000, packets: 48000 },
      { ts: now - 10, direction: '内网东西向', bytes: 26000000, packets: 22000 }
    ];
    dimensionTrend.value = [
      { ts: now - 120, dimension: 'service', key: 'HTTPS', bytes: 18000000, packets: 7200 },
      { ts: now - 60, dimension: 'service', key: 'HTTPS', bytes: 24000000, packets: 9300 },
      { ts: now, dimension: 'service', key: 'HTTPS', bytes: 42000000, packets: 14000 }
    ];
    objectRelations.value = {
      dimension: 'service',
      key: 'HTTPS',
      direction: 'src',
      minutes: selectedMinutes.value,
      summary: { key: 'HTTPS', bytes: 88000000, packets: 48000, related_count: 3 },
      related_ips: [
        { key: '172.20.2.10', bytes: 52000000, packets: 18000 },
        { key: '10.10.1.42', bytes: 42000000, packets: 14000 }
      ],
      related_ports: [{ key: '443/tcp', bytes: 88000000, packets: 48000 }],
      related_services: [{ key: 'HTTPS', bytes: 88000000, packets: 48000 }],
      related_flows: [
        { key: '10.10.1.42:53210 -> 172.20.2.10:443 / tcp', bytes: 42000000, packets: 14000 },
        { key: '10.10.1.77:53192 -> 172.20.2.81:443 / tcp', bytes: 18000000, packets: 7200 }
      ],
      insights: []
    };
    sessions.value = [
      {
        key: '10.10.1.42:53210 -> 172.20.2.10:443 / tcp',
        src_ip: '10.10.1.42',
        src_port: '53210',
        dst_ip: '172.20.2.10',
        dst_port: '443',
        protocol: 'tcp',
        service: 'HTTPS',
        category: 'Web',
        risk: 'low',
        direction: '内网服务',
        server_ip: '172.20.2.10',
        server_port: '443',
        client_ip: '10.10.1.42',
        confidence: '高',
        bytes: 42000000,
        packets: 14000,
        avg_packet_size: 3000,
        first_seen: now - 180,
        last_seen: now
      },
      {
        key: '10.10.1.77:53192 -> 172.20.2.81:22 / tcp',
        src_ip: '10.10.1.77',
        src_port: '53192',
        dst_ip: '172.20.2.81',
        dst_port: '22',
        protocol: 'tcp',
        service: 'SSH',
        category: '远程管理',
        risk: 'high',
        direction: '内网服务',
        server_ip: '172.20.2.81',
        server_port: '22',
        client_ip: '10.10.1.77',
        confidence: '高',
        bytes: 18000000,
        packets: 7200,
        avg_packet_size: 2500,
        first_seen: now - 120,
        last_seen: now - 10
      }
    ];
    searchResults.value = [
      { kind: 'flow', key: `${searchTerm.value}:53210 -> 172.20.2.10:443 / tcp`, bytes: 42000000, packets: 14000 },
      { kind: 'pair', key: `${searchTerm.value} -> 172.20.2.10`, bytes: 52000000, packets: 18000 }
    ];
    assets.value = [
      {
        ip: '10.10.1.42',
        name: '',
        owner: '',
        business: '',
        environment: '未分类',
        criticality: 'normal',
        tags: [],
        note: '',
        metadata_updated_at: 0,
        role: '外联源',
        inbound_bytes: 12000000,
        inbound_packets: 4000,
        outbound_bytes: 68000000,
        outbound_packets: 21000,
        total_bytes: 80000000,
        total_packets: 25000,
        avg_packet_size: 3200,
        first_seen: now - 900,
        last_seen: now
      },
      {
        ip: '172.20.2.10',
        name: '示例 Web 服务',
        owner: '平台团队',
        business: 'NexaFlow',
        environment: '测试',
        criticality: 'high',
        tags: ['web'],
        note: '',
        metadata_updated_at: now,
        role: '服务端',
        inbound_bytes: 52000000,
        inbound_packets: 18000,
        outbound_bytes: 9000000,
        outbound_packets: 2600,
        total_bytes: 61000000,
        total_packets: 20600,
        avg_packet_size: 2961,
        first_seen: now - 900,
        last_seen: now
      }
    ];
    assetRisks.value = [
      {
        ip: '10.2.0.12',
        name: '示例 Web 服务',
        owner: '平台团队',
        business: 'NexaFlow',
        environment: '测试',
        criticality: 'high',
        role: '服务端',
        risk_score: 86,
        risk_level: 'critical',
        total_bytes: 96000000,
        total_packets: 42000,
        external_bytes: 36000000,
        external_peers: 2,
        external_sessions: 44,
        exposed_services: 3,
        high_risk_services: 1,
        open_incidents: 2,
        critical_incidents: 1,
        anomaly_count: 1,
        top_finding: '事件：公网对端在 15 分钟内对内部资产单端口建立 40 条会话',
        recommended_action: '优先核对公网暴露和高危服务，确认访问来源、负责人和白名单策略',
        last_seen: now
      },
      {
        ip: '10.10.1.42',
        name: '',
        owner: '',
        business: '',
        environment: '未分类',
        criticality: 'normal',
        role: '外联源',
        risk_score: 58,
        risk_level: 'high',
        total_bytes: 80000000,
        total_packets: 25000,
        external_bytes: 12000000,
        external_peers: 4,
        external_sessions: 12,
        exposed_services: 0,
        high_risk_services: 0,
        open_incidents: 1,
        critical_incidents: 0,
        anomaly_count: 0,
        top_finding: '事件：单会话占近 15 分钟总流量 32.0%',
        recommended_action: '检查资产归属和流量用途，补齐负责人、业务标签和白名单判断',
        last_seen: now
      }
    ];
    securityInsights.value = [
      {
        kind: 'heavy_flow',
        severity: 'warning',
        subject: '10.10.1.42:53210 -> 172.20.2.10:443 / tcp',
        summary: '单会话占近 15 分钟总流量 32.0%',
        bytes: 42000000,
        packets: 14000,
        score: 32
      },
      {
        kind: 'fanout',
        severity: 'warning',
        subject: '10.10.1.77',
        summary: '源主机在 15 分钟内访问 6 个目的主机',
        bytes: 24000000,
        packets: 9000,
        score: 6
      },
      {
        kind: 'qos_mark',
        severity: 'info',
        subject: 'dscp:AF31',
        summary: '发现非默认 DSCP/QoS 标记流量',
        bytes: 12000000,
        packets: 4200,
        score: 45
      },
      {
        kind: 'external_session_burst',
        severity: 'warning',
        subject: '211.93.22.130 -> 10.2.0.12',
        summary: '公网对端在 15 分钟内对内部资产单端口建立 40 条会话',
        bytes: 7000000,
        packets: 6800,
        score: 80
      }
    ];
    ruleFindings.value = [
      {
        id: 'rule:rule-external-session-burst:211.93.22.130 -> 10.2.0.12:8081',
        rule_id: 'rule-external-session-burst',
        rule_name: '公网会话突增',
        category: '公网访问',
        kind: 'custom_rule',
        metric: 'external_sessions',
        severity: 'critical',
        subject: '211.93.22.130 -> 10.2.0.12:8081',
        summary: '211.93.22.130 -> 10.2.0.12:8081 命中规则：公网会话突增，当前值 40 sessions，阈值 30 sessions',
        value: 40,
        threshold: 30,
        unit: 'sessions',
        bytes: 7000000,
        packets: 6800,
        score: 100,
        recommended_action: '核对公网来源、服务端口和防火墙策略，必要时收敛来源或加入白名单',
        matched_at: now
      }
    ];
    securityIncidents.value = [
      {
        id: 'insight:external_session_burst:211.93.22.130 -> 10.2.0.12',
        source: '风险线索',
        category: '公网暴露',
        kind: 'external_session_burst',
        severity: 'warning',
        status: 'open',
        subject: '211.93.22.130 -> 10.2.0.12',
        summary: '公网对端在 15 分钟内对内部资产单端口建立 40 条会话',
        bytes: 7000000,
        packets: 6800,
        score: 80,
        first_seen: now - 900,
        last_seen: now,
        recommended_action: '核对公网来源、服务用途和防火墙访问策略，必要时加入白名单或限制来源'
      },
      {
        id: 'anomaly:service:SSH',
        source: '异常波动',
        category: '新增对象',
        kind: 'new_dimension',
        severity: 'critical',
        status: 'open',
        subject: 'service:SSH',
        summary: '应用服务 SSH 近 15 分钟新出现流量 18.00 MB',
        bytes: 18000000,
        packets: 7200,
        score: 88,
        first_seen: now - 900,
        last_seen: now,
        recommended_action: '确认新增服务是否符合变更计划，检查关联资产、端口画像和会话明细'
      }
    ];
    selectedIncident.value = securityIncidents.value[0];
    incidentTimeline.value = [
      {
        id: securityIncidents.value[0].id,
        type: 'status',
        status: 'open',
        note: '',
        author: 'system',
        summary: '事件创建',
        created_at: now - 900
      },
      {
        id: securityIncidents.value[0].id,
        type: 'note',
        status: '',
        note: '样例处置备注：已安排核对公网来源和端口用途',
        author: 'operator',
        summary: '样例处置备注：已安排核对公网来源和端口用途',
        created_at: now - 300
      }
    ];
    incidentContext.value = {
      subject: '211.93.22.130 -> 10.2.0.12',
      kind: 'external_session_burst',
      minutes: selectedMinutes.value,
      selector: { dimension: 'pair', key: '211.93.22.130 -> 10.2.0.12', query: '211.93.22.130 -> 10.2.0.12', direction: 'src', src_ip: '211.93.22.130', dst_ip: '10.2.0.12', dst_port: '8081' },
      relations: {
        dimension: 'pair',
        key: '211.93.22.130 -> 10.2.0.12',
        direction: 'src',
        minutes: selectedMinutes.value,
        summary: { key: '211.93.22.130 -> 10.2.0.12', bytes: 7000000, packets: 6800, related_count: 2 },
        related_ips: [{ key: '10.2.0.12', bytes: 7000000, packets: 6800 }],
        related_ports: [{ key: '8081/tcp', bytes: 7000000, packets: 6800 }],
        related_services: [{ key: 'HTTP Alternate', bytes: 7000000, packets: 6800 }],
        related_flows: [{ key: '10.2.0.12:8081 -> 211.93.22.130:4300 / tcp', bytes: 7000000, packets: 6800 }],
        insights: []
      },
      sessions: sessions.value.slice(0, 2),
      search_results: [{ kind: 'flow', key: '10.2.0.12:8081 -> 211.93.22.130:4300 / tcp', bytes: 7000000, packets: 6800 }],
      insights: securityInsights.value.slice(0, 2),
      anomalies: trafficAnomalies.value.slice(0, 1),
      playbook_actions: [
        { label: '核对公网来源', description: '确认来源 IP 是否属于可信业务或已登记访问方' },
        { label: '检查端口暴露', description: '核对 8081 服务用途、防火墙策略和访问来源限制' },
        { label: '关联会话复盘', description: '查看同一来源的会话数量、目的端口扩散和最近出现时间' }
      ]
    };
    incidentAISummary.value = {
      enabled: true,
      mode: 'local_mock',
      provider: 'local_mock',
      model: 'nexaflow-local-summary',
      kind: 'incident',
      subject: '211.93.22.130 -> 10.2.0.12',
      title: 'AI 事件摘要',
      summary: '公网对端对内部 Web 服务产生会话突增，建议优先核对访问来源、服务用途和防火墙策略。',
      confidence: 0.74,
      findings: ['事件对象关联公网会话突增，存在 40 条会话样本。', '关联资产 10.2.0.12 存在公网暴露和高风险服务。', '首要会话流量约 6.68 MB。'],
      evidence: ['事件类型：公网会话突增', '关联会话数：1', '关联风险线索：1'],
      actions: ['核对公网来源是否为业务白名单。', '检查 10.2.0.12 的端口暴露策略。', '必要时生成规则或临时收敛访问来源。'],
      generated_at: now
    };
    assetAISummary.value = {
      enabled: true,
      mode: 'local_mock',
      provider: 'local_mock',
      model: 'nexaflow-local-summary',
      kind: 'asset',
      subject: '10.2.0.12',
      title: 'AI 资产摘要',
      summary: '示例 Web 服务的风险主要来自公网暴露、开放事件和高风险服务，应先确认负责人和暴露策略。',
      confidence: 0.74,
      findings: ['资产风险等级为严重，风险评分 86。', '公网对端 2 个，暴露服务 3 个，开放事件 2 个。', '主要风险原因来自公网会话突增事件。'],
      evidence: ['总流量：91.55 MB', '公网流量：34.33 MB', '关联事件：2'],
      actions: ['补齐资产负责人和业务标签。', '复核公网访问来源和白名单策略。', '先处理该资产关联的开放事件。'],
      generated_at: now
    };
    trafficAnalysis.value = {
      minutes: selectedMinutes.value,
      baseline: {
        windows: 180,
        avg_bytes: 4800000,
        peak_bytes: 16000000,
        p95_bytes: 12000000,
        avg_packets: 6400,
        peak_packets: 18000,
        avg_utilization: 0.02,
        peak_utilization: 0.08,
        avg_mbps: 7.68,
        peak_mbps: 25.6,
        p95_mbps: 19.2,
        burst_ratio: 3.33
      },
      protocol_mix: topProtocols.value,
      port_mix: topPorts.value,
      packet_sizes: [
        { key: '1KB-MTU', bytes: 82000000, packets: 56000 },
        { key: '65-128B', bytes: 9000000, packets: 80000 }
      ],
      directions: [
        { key: '出站', bytes: 76000000, packets: 48000 },
        { key: '内网东西向', bytes: 26000000, packets: 22000 }
      ]
    };
    behaviorBaseline.value = {
      generated_at: now,
      minutes: selectedMinutes.value,
      baseline_minutes: 120,
      window_count: 8,
      baseline_strategy: 'dynamic_window',
      link: {
        dimension: 'link',
        dimension_title: '链路',
        key: '链路总流量',
        current_bytes: 158000000,
        current_packets: 98000,
        baseline_bytes: 85000000,
        baseline_packets: 54000,
        p95_bytes: 120000000,
        peak_bytes: 140000000,
        peak_packets: 76000,
        delta_bytes: 73000000,
        deviation_ratio: 1.32,
        change_ratio: 0.86,
        samples: 8,
        status: 'elevated',
        severity: 'warning',
        score: 66,
        summary: '链路总流量高于历史常态，当前 150.68 MB，历史均值 81.06 MB',
        dimension_source: 'link'
      },
      summary: {
        total_deviations: 3,
        critical_count: 1,
        warning_count: 2,
        new_count: 1,
        learning_count: 0,
        stable_count: 0,
        top_key: 'SSH',
        top_dimension: '应用服务',
        top_deviation: 999,
        link_status: 'elevated',
        link_deviation: 1.32,
        link_current_bytes: 158000000
      },
      deviations: [
        {
          dimension: 'service',
          dimension_title: '应用服务',
          key: 'SSH',
          current_bytes: 18000000,
          current_packets: 7200,
          baseline_bytes: 0,
          baseline_packets: 0,
          p95_bytes: 0,
          peak_bytes: 0,
          peak_packets: 0,
          delta_bytes: 18000000,
          deviation_ratio: 999,
          change_ratio: 999,
          samples: 0,
          status: 'new',
          severity: 'critical',
          score: 72,
          summary: '应用服务 SSH 在近 15 分钟首次进入当前 Top 对象，当前流量 17.17 MB',
          dimension_source: 'service'
        },
        {
          dimension: 'src_ip',
          dimension_title: '源 IP',
          key: '10.10.1.42',
          current_bytes: 68000000,
          current_packets: 21000,
          baseline_bytes: 22000000,
          baseline_packets: 9000,
          p95_bytes: 32000000,
          peak_bytes: 41000000,
          peak_packets: 13000,
          delta_bytes: 46000000,
          deviation_ratio: 2.13,
          change_ratio: 2.09,
          samples: 8,
          status: 'elevated',
          severity: 'warning',
          score: 78,
          summary: '源 IP 10.10.1.42 高于历史常态，当前 64.85 MB，历史均值 20.98 MB',
          dimension_source: 'ip'
        },
        {
          dimension: 'dst_port',
          dimension_title: '目的端口',
          key: '443',
          current_bytes: 88000000,
          current_packets: 48000,
          baseline_bytes: 52000000,
          baseline_packets: 31000,
          p95_bytes: 70000000,
          peak_bytes: 79000000,
          peak_packets: 38000,
          delta_bytes: 36000000,
          deviation_ratio: 1.26,
          change_ratio: 0.69,
          samples: 8,
          status: 'stable',
          severity: 'info',
          score: 60,
          summary: '目的端口 443 与历史基线接近，当前 83.92 MB',
          dimension_source: 'dst_port'
        }
      ],
      recommendations: [
        { level: 'warning', title: '复核链路级偏离', detail: '链路总流量高于历史常态，先确认是否存在计划内业务峰值。' },
        { level: 'critical', title: '优先调查新增服务', detail: 'SSH 在基线外新增，建议下钻端口画像和会话来源。' }
      ]
    };
    capacityPlanning.value = {
      generated_at: now,
      minutes: selectedMinutes.value,
      summary: {
        minutes: selectedMinutes.value,
        bandwidth_mbps: 1000,
        avg_mbps: 7.68,
        peak_mbps: 25.6,
        p95_mbps: 19.2,
        previous_peak_mbps: 18.4,
        growth_mbps: 7.2,
        growth_ratio: 0.39,
        headroom_mbps: 974.4,
        headroom_ratio: 0.974,
        peak_utilization: 0.0256,
        p95_utilization: 0.0192,
        saturation_eta_mins: 9999,
        risk_level: 'healthy'
      },
      trend: [
        { ts: now - 180, bytes: 24000000, packets: 9300, utilization: 0.02, mbps: 3.2 },
        { ts: now - 120, bytes: 36000000, packets: 12000, utilization: 0.03, mbps: 4.8 },
        { ts: now - 60, bytes: 52000000, packets: 18000, utilization: 0.04, mbps: 6.93 }
      ],
      top_src_growth: [
        {
          dimension: 'src_ip',
          key: '10.10.1.42',
          current_bytes: 68000000,
          previous_bytes: 22000000,
          delta_bytes: 46000000,
          current_packets: 21000,
          previous_packets: 9000,
          delta_packets: 12000,
          change_ratio: 2.09
        }
      ],
      top_port_growth: [
        {
          dimension: 'dst_port',
          key: '443',
          current_bytes: 88000000,
          previous_bytes: 52000000,
          delta_bytes: 36000000,
          current_packets: 48000,
          previous_packets: 31000,
          delta_packets: 17000,
          change_ratio: 0.69
        }
      ],
      top_service_growth: [
        {
          dimension: 'service',
          key: 'HTTPS',
          current_bytes: 88000000,
          previous_bytes: 52000000,
          delta_bytes: 36000000,
          current_packets: 48000,
          previous_packets: 31000,
          delta_packets: 17000,
          change_ratio: 0.69
        }
      ],
      recommendations: [{ level: 'info', title: '容量余量充足', detail: '当前峰值和 P95 吞吐低于带宽阈值，可继续观察增长趋势' }]
    };
    trafficChanges.value = [
      {
        dimension: 'src_ip',
        key: '10.10.1.42',
        current_bytes: 68000000,
        previous_bytes: 22000000,
        delta_bytes: 46000000,
        current_packets: 21000,
        previous_packets: 9000,
        delta_packets: 12000,
        change_ratio: 2.09
      },
      {
        dimension: 'dst_port',
        key: '443',
        current_bytes: 88000000,
        previous_bytes: 52000000,
        delta_bytes: 36000000,
        current_packets: 48000,
        previous_packets: 31000,
        delta_packets: 17000,
        change_ratio: 0.69
      }
    ];
    trafficAnomalies.value = [
      {
        kind: 'link_burst',
        dimension: 'link',
        key: '链路总流量',
        severity: 'warning',
        summary: '近 15 分钟链路总流量较上一周期增长 +85.0%',
        current_bytes: 158000000,
        baseline_bytes: 85000000,
        delta_bytes: 73000000,
        current_packets: 98000,
        baseline_packets: 54000,
        delta_packets: 44000,
        change_ratio: 0.85,
        score: 72
      },
      {
        kind: 'new_dimension',
        dimension: 'service',
        key: 'SSH',
        severity: 'critical',
        summary: '应用服务 SSH 近 15 分钟新出现流量 18.00 MB',
        current_bytes: 18000000,
        baseline_bytes: 0,
        delta_bytes: 18000000,
        current_packets: 7200,
        baseline_packets: 0,
        delta_packets: 7200,
        change_ratio: 999,
        score: 88
      }
    ];
    reportOverview.value = {
      generated_at: now,
      minutes: selectedMinutes.value,
      summary: {
        minutes: selectedMinutes.value,
        bytes: summary.value.bytes,
        packets: summary.value.packets,
        utilization: summary.value.utilization,
        asset_count: assetRisks.value.length,
        critical_assets: assetRisks.value.filter((row) => row.risk_level === 'critical').length,
        open_incidents: securityIncidents.value.filter((row) => row.status === 'open').length,
        critical_incidents: securityIncidents.value.filter((row) => row.severity === 'critical').length,
        anomaly_count: trafficAnomalies.value.length,
        critical_anomalies: trafficAnomalies.value.filter((row) => row.severity === 'critical').length,
        exposed_services: serviceExposure.value.length,
        high_risk_services: serviceExposure.value.filter((row) => row.risk === 'critical' || row.risk === 'high').length,
        external_access: externalAccess.value.length,
        external_session_sum: externalAccess.value.reduce((sum, row) => sum + row.session_count, 0),
        avg_mbps: trafficAnalysis.value.baseline.avg_mbps,
        peak_mbps: trafficAnalysis.value.baseline.peak_mbps,
        p95_mbps: trafficAnalysis.value.baseline.p95_mbps
      },
      asset_risks: assetRisks.value,
      incidents: securityIncidents.value,
      anomalies: trafficAnomalies.value,
      exposures: serviceExposure.value,
      external_access: externalAccess.value,
      top_src: topSrc.value,
      top_ports: topPorts.value,
      top_services: topServices.value,
      recommendations: [
        { level: 'critical', title: '优先处置严重资产', detail: '10.2.0.12 存在公网访问、事件和高风险服务，需要确认暴露策略' },
        { level: 'warning', title: '补齐资产归属', detail: '未归属资产需要补充负责人和业务标签，便于后续事件流转' }
      ]
    };
    reportAISummary.value = {
      enabled: true,
      mode: 'local_mock',
      provider: 'local_mock',
      model: 'nexaflow-local-summary',
      kind: 'report',
      subject: 'overview',
      title: 'AI 巡检摘要',
      summary: '当前窗口存在严重资产和开放事件，建议优先围绕公网暴露资产完成事件确认和归属补齐。',
      confidence: 0.86,
      findings: ['观察范围内存在严重资产 1 个。', '开放事件 2 个，其中严重事件 1 个。', '高风险服务与公网访问同时存在。'],
      evidence: ['资产风险样本：2', '事件样本：2', '暴露服务样本：2'],
      actions: ['先处理严重资产和开放事件。', '对高风险服务补充资产归属和访问策略。', '把本摘要作为巡检报告草案。'],
      generated_at: now
    };
    aiGovernance.value = {
      enabled: true,
      mode: 'local_mock',
      provider: 'local_mock',
      model: 'nexaflow-local-summary',
      minutes: selectedMinutes.value,
      summary: '基于样例公网访问、暴露服务和高风险资产生成治理建议，所有动作都需要管理员确认后执行。',
      suggestions: [
        {
          id: 'demo-rule-external',
          type: 'rule',
          severity: 'critical',
          title: '沉淀公网会话检测规则',
          target: '211.93.22.130 -> 10.2.0.12:8081',
          summary: '公网访问会话突增，建议生成规则草案并人工确认阈值。',
          confidence: 0.74,
          evidence: ['公网来源：211.93.22.130', '内部资产：10.2.0.12', '服务端口：8081 / HTTP Alternate'],
          actions: ['确认访问来源是否可信。', '保存前复核阈值和匹配对象。'],
          proposed_rule: {
            id: '',
            name: 'AI 推荐：公网会话突增',
            category: '公网访问',
            metric: 'external_sessions',
            match: '211.93.22.130 -> 10.2.0.12:8081',
            operator: 'gte',
            threshold: 40,
            severity: 'critical',
            enabled: true,
            description: '由 AI 治理建议生成的规则草案，保存前请人工确认。',
            recommended_action: '核对公网来源、服务端口和防火墙策略。',
            updated_at: now
          }
        }
      ],
      generated_at: now
    };
    aiRuleEffectiveness.value = {
      enabled: true,
      mode: 'local_mock',
      provider: 'local_mock',
      model: 'nexaflow-local-summary',
      summary: {
        minutes: selectedMinutes.value,
        rule_count: 3,
        enabled_rules: 3,
        disabled_rules: 0,
        total_hits: 18,
        critical_hits: 2,
        noisy_rules: 1,
        quiet_rules: 1,
        health: '存在噪声规则'
      },
      rules: [
        {
          id: 'rule-external-session-burst',
          name: '公网会话突增',
          category: '公网访问',
          metric: 'external_sessions',
          match: '10.2.0.12',
          operator: 'gte',
          threshold: 40,
          severity: 'warning',
          enabled_rule: true,
          minutes: selectedMinutes.value,
          hit_count: 12,
          critical_count: 0,
          warning_count: 12,
          unique_subjects: 1,
          duplicate_ratio: 0.92,
          silenced_hits: 0,
          total_bytes: 7000000,
          peak_value: 46,
          top_subject: '211.93.22.130 -> 10.2.0.12:8081',
          noise_level: 'noisy',
          score: 62,
          summary: '规则命中 12 次，唯一对象 1 个，重复率 92%，存在告警噪声风险。',
          recommendations: ['提高阈值或收窄匹配对象。', '对重复命中的稳定业务流量先做白名单复核。'],
          sample_findings: [],
          generated_at: now
        }
      ],
      tuning_suggestions: [
        {
          rule_id: 'rule-external-session-burst',
          rule_name: '公网会话突增',
          noise_level: 'noisy',
          severity: 'warning',
          title: '复核规则：公网会话突增',
          summary: '重复命中偏高，建议调高阈值或按对象聚合事件。',
          actions: ['提高阈值或收窄匹配对象。', '对重复命中的稳定业务流量先做白名单复核。'],
          score: 62
        }
      ],
      generated_at: now
    };
    aiAssetEnrichment.value = {
      enabled: true,
      mode: 'local_mock',
      provider: 'local_mock',
      model: 'nexaflow-local-summary',
      minutes: selectedMinutes.value,
      summary: '基于样例资产风险生成 1 条画像补全建议。',
      suggestions: [
        {
          id: 'ai:asset-enrichment:10.2.0.12',
          type: 'asset_enrichment',
          severity: 'critical',
          ip: '10.2.0.12',
          title: '补全资产画像：10.2.0.12',
          summary: '10.2.0.12 缺少负责人、业务系统，且当前风险等级为严重，建议优先补齐画像。',
          confidence: 0.86,
          missing_fields: ['负责人', '业务系统'],
          evidence: ['风险评分：86', '公网对端：2', '暴露服务：3', '开放事件：2', '主要原因：公网暴露'],
          actions: ['确认资产负责人和业务系统。', '复核推荐标签是否符合实际用途。', '填入资产台账后再保存。'],
          proposed_metadata: {
            ip: '10.2.0.12',
            name: '公网服务资产 10.2.0.12',
            owner: '待分配',
            business: '公网服务',
            environment: '生产',
            criticality: 'critical',
            tags: ['AI建议', '公网访问', '服务暴露', '高风险'],
            note: 'AI 建议补全：风险评分 86，公网暴露。'
          },
          generated_at: now,
          enabled: true
        }
      ],
      generated_at: now
    };
    systemSettings.value = normalizeSettingsForForm(emptySystemSettings());
    degraded.value = true;
  } finally {
    loading.value = false;
  }
};

const startRefreshTimer = () => {
  if (timer) {
    window.clearInterval(timer);
  }
  timer = window.setInterval(refresh, 5000);
};

const normalizeSettingsForForm = (settings: SystemSettings): SystemSettings => ({
  ...emptySystemSettings(),
  ...settings,
  ai: { ...emptySystemSettings().ai, ...settings.ai, api_key: '' },
  analysis: { ...emptySystemSettings().analysis, ...settings.analysis },
  security: { ...emptySystemSettings().security, ...settings.security, admin_password: '', readonly_password: '' },
  notification: { ...emptySystemSettings().notification, ...settings.notification, webhook_token: '', channels: settings.notification?.channels ?? [] },
  data: { ...emptySystemSettings().data, ...settings.data },
  backend: { ...emptySystemSettings().backend, ...settings.backend }
});

const saveSettings = async () => {
  if (!canWrite.value) return;
  savingSettings.value = true;
  settingsTestResult.value = null;
  webhookTestResult.value = null;
  try {
    const result = await api.saveSystemSettings(systemSettings.value);
    systemSettings.value = normalizeSettingsForForm(result.data);
    await refresh();
  } finally {
    savingSettings.value = false;
  }
};

const testAISettings = async () => {
  settingsTestResult.value = null;
  const result = await api.testAISettings(systemSettings.value);
  settingsTestResult.value = result.data;
};

const testWebhookSettings = async () => {
  webhookTestResult.value = null;
  const result = await api.testWebhookSettings(systemSettings.value);
  webhookTestResult.value = result.data;
};

const exportSettings = async () => {
  const result = await api.exportSystemSettings();
  settingsExportText.value = JSON.stringify(result.data, null, 2);
};

const importSettings = async () => {
  if (!canWrite.value || !settingsImportText.value.trim()) return;
  const parsed = JSON.parse(settingsImportText.value) as SystemSettings;
  const result = await api.importSystemSettings(parsed);
  systemSettings.value = normalizeSettingsForForm(result.data);
  settingsImportText.value = '';
  await refresh();
};

const checkAuth = async () => {
  authChecking.value = true;
  try {
    const result = await api.authStatus();
    authStatus.value = result.data;
    loginActor.value = result.data.actor || 'operator';
    authChecking.value = false;
    if (!result.data.enabled || result.data.authenticated) {
      void refresh();
      startRefreshTimer();
    }
  } finally {
    authChecking.value = false;
  }
};

const login = async () => {
  loggingIn.value = true;
  loginError.value = '';
  try {
    const result = await api.login(loginActor.value.trim() || 'operator', loginPassword.value);
    authStatus.value = result.data;
    loginActor.value = result.data.actor || loginActor.value || 'operator';
    loginPassword.value = '';
    await refresh();
    startRefreshTimer();
  } catch {
    loginError.value = '登录失败，请检查密码';
  } finally {
    loggingIn.value = false;
  }
};

const logout = async () => {
  if (timer) {
    window.clearInterval(timer);
    timer = undefined;
  }
  const result = await api.logout();
  authStatus.value = result.data;
  loginPassword.value = '';
};

onMounted(() => {
  void checkAuth();
});

onUnmounted(() => {
  if (timer) {
    window.clearInterval(timer);
  }
});

const formatBytes = (value: number) => {
  if (value >= 1024 ** 3) return `${(value / 1024 ** 3).toFixed(2)} GB`;
  if (value >= 1024 ** 2) return `${(value / 1024 ** 2).toFixed(2)} MB`;
  if (value >= 1024) return `${(value / 1024).toFixed(2)} KB`;
  return `${value.toFixed(0)} B`;
};

const recordString = (row: Record<string, unknown>, keys: string[]) => {
  for (const key of keys) {
    const value = row[key];
    if (value !== undefined && value !== null && String(value).trim()) return String(value);
  }
  return '-';
};

const recordNumber = (row: Record<string, unknown>, keys: string[]) => {
  for (const key of keys) {
    const value = row[key];
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    if (typeof value === 'string' && value.trim() && Number.isFinite(Number(value))) return Number(value);
  }
  return 0;
};

const aiRowObject = (row: Record<string, unknown>) =>
  recordString(row, ['key', 'ip', 'subject', 'public_ip', 'internal_ip', 'service', 'src_ip', 'dst_ip']);
const aiRowDetail = (row: Record<string, unknown>) =>
  recordString(row, ['summary', 'top_finding', 'sample_flow', 'direction', 'risk', 'risk_level', 'category']);
const aiRowBytes = (row: Record<string, unknown>) => formatBytes(recordNumber(row, ['bytes', 'total_bytes', 'external_bytes', 'current_bytes']));
const aiRowPackets = (row: Record<string, unknown>) => recordNumber(row, ['packets', 'current_packets', 'session_count', 'open_incidents']).toLocaleString();

const formatRate = (bytes: number, seconds = rangeSeconds.value) => `${((bytes * 8) / seconds / 1000 / 1000).toFixed(2)} Mbps`;

const pps = computed(() => Math.round(summary.value.packets / rangeSeconds.value));
const onlineCollectorCount = computed(() => collectors.value.filter((collector) => collector.status === 'online').length);
const dataQualitySourceItems = computed(() =>
  dataQuality.value.sources.map((row) => ({
    key: `${row.source_id} / ${row.iface}`,
    bytes: Math.round(row.coverage_ratio * 100),
    packets: row.windows
  }))
);
const dataQualityFreshnessItems = computed(() =>
  dataQuality.value.sources.map((row) => ({
    key: `${row.source_id} / ${row.iface}`,
    bytes: row.freshness_seconds,
    packets: row.windows
  }))
);
const dataQualityDropItems = computed(() =>
  dataQuality.value.sources.map((row) => ({
    key: `${row.source_id} / ${row.iface}`,
    bytes: row.drops,
    packets: row.windows
  }))
);
const captureQualityTrafficItems = computed(() =>
  captureQuality.value.sources.map((row) => ({
    key: `${row.source_id} / ${row.iface}`,
    bytes: row.rx_bytes + row.tx_bytes,
    packets: row.rx_packets + row.tx_packets
  }))
);
const captureQualityDropItems = computed(() =>
  captureQuality.value.sources.map((row) => ({
    key: `${row.source_id} / ${row.iface}`,
    bytes: row.rx_dropped + row.tx_dropped,
    packets: row.windows
  }))
);
const captureQualityErrorItems = computed(() =>
  captureQuality.value.sources.map((row) => ({
    key: `${row.source_id} / ${row.iface}`,
    bytes: row.rx_errors + row.tx_errors,
    packets: row.windows
  }))
);
const captureQualityQueueItems = computed(() =>
  captureQuality.value.sources.map((row) => ({
    key: `${row.source_id} / ${row.iface}`,
    bytes: Math.round((row.queue_pressure || 0) * 100),
    packets: row.packet_queue_len + row.window_queue_len
  }))
);
const captureDiagnosticItems = computed(() =>
  captureDiagnostics.value.layers.map((row) => ({
    key: `${dataQualityStatusText(row.status)} / ${row.name}`,
    bytes: row.score,
    packets: row.score
  }))
);
const capacityTrendSeries = computed(() => capacityPlanning.value.trend.map((row) => ({ ts: row.ts, bytes: row.bytes, packets: row.packets })));
const capacitySrcGrowthItems = computed(() =>
  capacityPlanning.value.top_src_growth.map((row) => ({ key: row.key, bytes: Math.max(0, row.delta_bytes), packets: Math.max(0, row.delta_packets) }))
);
const capacityPortGrowthItems = computed(() =>
  capacityPlanning.value.top_port_growth.map((row) => ({ key: row.key, bytes: Math.max(0, row.delta_bytes), packets: Math.max(0, row.delta_packets) }))
);
const capacityServiceGrowthItems = computed(() =>
  capacityPlanning.value.top_service_growth.map((row) => ({ key: row.key, bytes: Math.max(0, row.delta_bytes), packets: Math.max(0, row.delta_packets) }))
);
const baselineDeviationItems = computed(() =>
  behaviorBaseline.value.deviations
    .filter((row) => row.severity !== 'info' || row.status !== 'stable')
    .slice(0, 12)
    .map((row) => ({
      key: `${row.dimension_title} / ${row.key}`,
      bytes: Math.max(0, row.delta_bytes),
      packets: row.score
    }))
);
const baselineSeverityItems = computed(() =>
  aggregateTopItems(
    behaviorBaseline.value.deviations,
    (row) => severityText(row.severity),
    () => 1,
    () => 0
  )
);
const baselineStatusItems = computed(() =>
  aggregateTopItems(
    behaviorBaseline.value.deviations,
    (row) => baselineStatusText(row.status),
    () => 1,
    () => 0
  )
);

const profileTotalBytes = computed(() => ipProfile.value.inbound_bytes + ipProfile.value.outbound_bytes);
const profileTotalPackets = computed(() => ipProfile.value.inbound_packets + ipProfile.value.outbound_packets);
const topologyTotalBytes = computed(() => matrixRows.value.reduce((sum, row) => sum + row.bytes, 0));
const topologyNodeCount = computed(() => serviceMap.value.nodes.length);
const topTopologyLink = computed(() => matrixRows.value[0]);
const serviceAnalyticsGrowthItems = computed(() =>
  serviceAnalytics.value.growth.map((row) => ({ key: row.key, bytes: Math.max(0, row.delta_bytes), packets: Math.max(0, row.delta_packets) }))
);
const serviceAnalyticsPortItems = computed(() =>
  serviceAnalytics.value.ports.map((row) => ({ key: `${row.service} / ${row.port}`, bytes: row.bytes, packets: row.packets }))
);
const serviceAnalyticsHighRiskItems = computed(() =>
  serviceAnalytics.value.details
    .filter((row) => serviceRiskRank[row.risk] >= serviceRiskRank.high)
    .map((row) => ({ key: row.service, bytes: row.bytes, packets: row.packets }))
);
const exposedServiceCount = computed(() => serviceExposure.value.length);
const highRiskServiceCount = computed(() => serviceExposure.value.filter((row) => row.risk === 'critical' || row.risk === 'high').length);
const unknownServiceCount = computed(() => serviceExposure.value.filter((row) => row.risk === 'observe').length);
const exposureTotalBytes = computed(() => serviceExposure.value.reduce((sum, row) => sum + row.bytes, 0));
const externalTotalBytes = computed(() => externalAccess.value.reduce((sum, row) => sum + row.bytes, 0));
const externalPublicCount = computed(() => new Set(externalAccess.value.map((row) => row.public_ip)).size);
const externalInternalCount = computed(() => new Set(externalAccess.value.map((row) => row.internal_ip)).size);
const externalInboundCount = computed(() => externalAccess.value.filter((row) => row.direction.includes('入站')).length);
const serviceRiskRank: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  observe: 1
};
const exposureRiskOptions = [
  { value: 'all', label: '全部风险' },
  { value: 'critical', label: '严重' },
  { value: 'high', label: '高' },
  { value: 'medium', label: '中' },
  { value: 'low', label: '低' },
  { value: 'observe', label: '观察' }
];
const trendDimensionOptions = [
  { value: 'service', label: '应用服务' },
  { value: 'service_category', label: '服务类别' },
  { value: 'service_risk', label: '服务风险' },
  { value: 'dst_port', label: '目的端口' },
  { value: 'protocol', label: '协议' },
  { value: 'vlan', label: 'VLAN' },
  { value: 'dscp', label: 'DSCP' },
  { value: 'ecn', label: 'ECN' },
  { value: 'ip', label: 'IP 地址' }
];
const ruleMetricOptions = [
  { value: 'src_ip_bytes', label: '源 IP 流量' },
  { value: 'dst_ip_bytes', label: '目的 IP 流量' },
  { value: 'dst_port_bytes', label: '目的端口流量' },
  { value: 'service_bytes', label: '应用服务流量' },
  { value: 'flow_bytes', label: '会话流量' },
  { value: 'external_sessions', label: '公网会话数' },
  { value: 'exposed_clients', label: '暴露服务客户端数' },
  { value: 'link_peak_mbps', label: '链路峰值 Mbps' },
  { value: 'link_utilization', label: '链路利用率' }
];
const ruleOperatorOptions = [
  { value: 'gte', label: '大于等于' },
  { value: 'gt', label: '大于' },
  { value: 'lte', label: '小于等于' },
  { value: 'lt', label: '小于' },
  { value: 'eq', label: '等于' }
];
const ruleSeverityOptions = [
  { value: 'critical', label: '严重' },
  { value: 'warning', label: '警告' },
  { value: 'info', label: '提示' }
];
const trendDimensionLabel = computed(() => trendDimensionOptions.find((item) => item.value === trendDimension.value)?.label ?? trendDimension.value);
const trendTitle = computed(() => {
  const suffix = trendKey.value.trim() || 'Top 对象';
  return `${trendDimensionLabel.value}趋势 / ${suffix}`;
});
const exposureCategoryOptions = computed(() => {
  const categories = Array.from(new Set(serviceExposure.value.map((row) => row.category).filter(Boolean))).sort();
  return [{ value: 'all', label: '全部类别' }, ...categories.map((category) => ({ value: category, label: category }))];
});
const filteredServiceExposure = computed(() => {
  const keyword = exposureSearch.value.trim().toLowerCase();
  return serviceExposure.value
    .filter((row) => {
      if (exposureRiskFilter.value !== 'all' && row.risk !== exposureRiskFilter.value) return false;
      if (exposureCategoryFilter.value !== 'all' && row.category !== exposureCategoryFilter.value) return false;
      if (!keyword) return true;
      return [
        row.ip,
        row.port,
        row.protocol,
        row.service,
        row.category,
        row.direction,
        row.confidence,
        row.sample_client,
        row.sample_flow
      ]
        .join(' ')
        .toLowerCase()
        .includes(keyword);
    })
    .sort((a, b) => (serviceRiskRank[b.risk] ?? 0) - (serviceRiskRank[a.risk] ?? 0) || b.bytes - a.bytes);
});
const exposureFilteredCount = computed(() => filteredServiceExposure.value.length);
const exposureFilteredBytes = computed(() => filteredServiceExposure.value.reduce((sum, row) => sum + row.bytes, 0));
const assetTotalBytes = computed(() => assets.value.reduce((sum, row) => sum + row.total_bytes, 0));
const activeAssetCount = computed(() => assets.value.length);
const annotatedAssetCount = computed(() =>
  assets.value.filter((row) => row.name || row.owner || row.business || row.tags.length > 0 || row.note).length
);
const criticalAssetRiskCount = computed(() => assetRisks.value.filter((row) => row.risk_level === 'critical').length);
const unownedAssetRiskCount = computed(() => assetRisks.value.filter((row) => !row.owner).length);
const exposedAssetRiskCount = computed(() => assetRisks.value.filter((row) => row.exposed_services > 0 || row.external_peers > 0).length);
const assetRiskTotalBytes = computed(() => assetRisks.value.reduce((sum, row) => sum + row.total_bytes, 0));
const pendingAIApprovals = computed(() => aiApprovals.value.filter((row) => row.status === 'pending'));
const criticalInsightCount = computed(() => securityInsights.value.filter((row) => row.severity === 'critical').length);
const warningInsightCount = computed(() => securityInsights.value.filter((row) => row.severity === 'warning').length);
const dominantProtocol = computed(() => trafficAnalysis.value.protocol_mix[0]);
const dominantDirection = computed(() => trafficAnalysis.value.directions[0]);
const packetSizeTotal = computed(() => trafficAnalysis.value.packet_sizes.reduce((sum, row) => sum + row.bytes, 0));
const portMixTotal = computed(() => trafficAnalysis.value.port_mix.reduce((sum, row) => sum + row.bytes, 0));
const portTrendSummary = computed(() => {
  const grouped = new Map<string, TopItem>();
  for (const point of portSeries.value) {
    const current = grouped.get(point.port) ?? { key: point.port, bytes: 0, packets: 0 };
    current.bytes += point.bytes;
    current.packets += point.packets;
    grouped.set(point.port, current);
  }
  return Array.from(grouped.values()).sort((a, b) => b.bytes - a.bytes);
});
const directionTrendSummary = computed(() => {
  const grouped = new Map<string, TopItem>();
  for (const point of directionSeries.value) {
    const current = grouped.get(point.direction) ?? { key: point.direction, bytes: 0, packets: 0 };
    current.bytes += point.bytes;
    current.packets += point.packets;
    grouped.set(point.direction, current);
  }
  return Array.from(grouped.values()).sort((a, b) => b.bytes - a.bytes);
});
const protocolSummary = computed(() => {
  const grouped = new Map<string, TopItem>();
  for (const point of protocolSeries.value) {
    const current = grouped.get(point.protocol) ?? { key: point.protocol, bytes: 0, packets: 0 };
    current.bytes += point.bytes;
    current.packets += point.packets;
    grouped.set(point.protocol, current);
  }
  return Array.from(grouped.values()).sort((a, b) => b.bytes - a.bytes);
});
const aggregateTopItems = <T,>(rows: T[], keyOf: (row: T) => string, bytesOf: (row: T) => number, packetsOf: (row: T) => number) => {
  const grouped = new Map<string, TopItem>();
  for (const row of rows) {
    const key = keyOf(row) || '-';
    const current = grouped.get(key) ?? { key, bytes: 0, packets: 0 };
    current.bytes += bytesOf(row);
    current.packets += packetsOf(row);
    grouped.set(key, current);
  }
  return Array.from(grouped.values()).sort((a, b) => b.bytes - a.bytes);
};
const trafficChangeItems = computed(() =>
  trafficChanges.value
    .map((row) => ({ key: `${changeDimensionText(row.dimension)} / ${row.key}`, bytes: Math.abs(row.delta_bytes), packets: Math.abs(row.delta_packets) }))
    .sort((a, b) => b.bytes - a.bytes)
);
const anomalyDeltaItems = computed(() =>
  trafficAnomalies.value
    .map((row) => ({ key: `${changeDimensionText(row.dimension)} / ${row.key}`, bytes: Math.abs(row.delta_bytes), packets: Math.abs(row.delta_packets) }))
    .sort((a, b) => b.bytes - a.bytes)
);
const anomalyKindItems = computed(() => aggregateTopItems(trafficAnomalies.value, (row) => anomalyKindText(row.kind), (row) => Math.abs(row.delta_bytes), (row) => Math.abs(row.delta_packets)));
const anomalySeverityItems = computed(() => aggregateTopItems(trafficAnomalies.value, (row) => severityText(row.severity), () => 1, () => 0));
const criticalAnomalyCount = computed(() => trafficAnomalies.value.filter((row) => row.severity === 'critical').length);
const exposureRiskItems = computed(() => aggregateTopItems(serviceExposure.value, (row) => serviceRiskText(row.risk), (row) => row.bytes, (row) => row.packets));
const exposureCategoryItems = computed(() => aggregateTopItems(serviceExposure.value, (row) => row.category, (row) => row.bytes, (row) => row.packets));
const externalPublicItems = computed(() => aggregateTopItems(externalAccess.value, (row) => row.public_ip, (row) => row.bytes, (row) => row.packets));
const externalServiceItems = computed(() => aggregateTopItems(externalAccess.value, (row) => row.service, (row) => row.bytes, (row) => row.packets));
const externalDirectionItems = computed(() => aggregateTopItems(externalAccess.value, (row) => row.direction, (row) => row.bytes, (row) => row.packets));
const externalRiskItems = computed(() => aggregateTopItems(externalAccess.value, (row) => serviceRiskText(row.risk), (row) => row.bytes, (row) => row.packets));
const assetRoleItems = computed(() => aggregateTopItems(assets.value, (row) => row.role, (row) => row.total_bytes, (row) => row.total_packets));
const assetCriticalityItems = computed(() => aggregateTopItems(assets.value, (row) => criticalityText(row.criticality), (row) => row.total_bytes, (row) => row.total_packets));
const assetRiskScoreItems = computed(() => assetRisks.value.map((row) => ({ key: `${row.ip} / ${row.name || row.role}`, bytes: row.risk_score, packets: row.open_incidents })));
const assetRiskLevelItems = computed(() => aggregateTopItems(assetRisks.value, (row) => assetRiskLevelText(row.risk_level), () => 1, () => 0));
const assetRiskFindingItems = computed(() => aggregateTopItems(assetRisks.value, (row) => row.top_finding || '无显著风险', (row) => row.risk_score, (row) => row.open_incidents));
const assetRiskExposureItems = computed(() => aggregateTopItems(assetRisks.value, (row) => row.ip, (row) => row.external_bytes, (row) => row.external_sessions));
const insightKindItems = computed(() => aggregateTopItems(securityInsights.value, (row) => insightKindText(row.kind), (row) => row.bytes, (row) => row.packets));
const alertSeverityItems = computed(() => aggregateTopItems(alerts.value, (row) => severityText(row.severity), () => 1, () => 0));
const alertStatusItems = computed(() => aggregateTopItems(alerts.value, (row) => alertStatusText(row.status), () => 1, () => 0));
const auditActionItems = computed(() => aggregateTopItems(auditEvents.value, (row) => auditActionText(row.action), () => 1, () => 0));
const auditActorItems = computed(() => aggregateTopItems(auditEvents.value, (row) => row.actor || 'operator', () => 1, () => 0));
const auditTargetItems = computed(() => aggregateTopItems(auditEvents.value, (row) => row.target || '-', () => 1, () => 0));
const configScopeItems = computed(() => aggregateTopItems(configVersions.value, (row) => configScopeText(row.scope), () => 1, () => 0));
const configActionItems = computed(() => aggregateTopItems(configVersions.value, (row) => auditActionText(row.action), () => 1, () => 0));
const configActorItems = computed(() => aggregateTopItems(configVersions.value, (row) => row.actor || 'operator', () => 1, () => 0));
const enabledRuleCount = computed(() => detectionRules.value.filter((row) => row.enabled).length);
const criticalRuleFindingCount = computed(() => ruleFindings.value.filter((row) => row.severity === 'critical').length);
const ruleFindingRuleItems = computed(() => aggregateTopItems(ruleFindings.value, (row) => row.rule_name, () => 1, () => 0));
const ruleFindingSeverityItems = computed(() => aggregateTopItems(ruleFindings.value, (row) => severityText(row.severity), () => 1, () => 0));
const ruleFindingMetricItems = computed(() => aggregateTopItems(ruleFindings.value, (row) => ruleMetricText(row.metric), (row) => row.bytes || row.value, (row) => row.packets));
const aiRuleEffectivenessItems = computed(() =>
  aiRuleEffectiveness.value.rules.map((row) => ({
    key: `${row.name} / ${ruleNoiseText(row.noise_level)}`,
    bytes: row.score,
    packets: row.hit_count
  }))
);
const incidentSeverityItems = computed(() => aggregateTopItems(securityIncidents.value, (row) => severityText(row.severity), () => 1, () => 0));
const incidentSourceItems = computed(() => aggregateTopItems(securityIncidents.value, (row) => row.source, () => 1, () => 0));
const incidentCategoryItems = computed(() => aggregateTopItems(securityIncidents.value, (row) => row.category, (row) => row.bytes, (row) => row.packets));
const incidentKindItems = computed(() => aggregateTopItems(securityIncidents.value, (row) => incidentKindText(row.kind), (row) => row.bytes, (row) => row.packets));
const criticalIncidentCount = computed(() => securityIncidents.value.filter((row) => row.severity === 'critical').length);
const openIncidentCount = computed(() => securityIncidents.value.filter((row) => row.status === 'open').length);
const incidentTotalBytes = computed(() => securityIncidents.value.reduce((sum, row) => sum + row.bytes, 0));
const reportAssetRiskItems = computed(() =>
  reportOverview.value.asset_risks.map((row) => ({
    key: `${row.ip} / ${row.name || row.role || row.environment}`,
    bytes: row.risk_score,
    packets: row.open_incidents
  }))
);
const reportIncidentKindItems = computed(() =>
  aggregateTopItems(reportOverview.value.incidents, (row) => incidentKindText(row.kind), (row) => row.bytes, (row) => row.packets)
);
const reportIncidentSeverityItems = computed(() =>
  aggregateTopItems(reportOverview.value.incidents, (row) => severityText(row.severity), () => 1, () => 0)
);
const reportAnomalyItems = computed(() =>
  reportOverview.value.anomalies
    .map((row) => ({
      key: `${changeDimensionText(row.dimension)} / ${row.key}`,
      bytes: Math.abs(row.delta_bytes),
      packets: Math.abs(row.delta_packets)
    }))
    .sort((a, b) => b.bytes - a.bytes)
);
const reportExposureRiskItems = computed(() =>
  aggregateTopItems(reportOverview.value.exposures, (row) => serviceRiskText(row.risk), (row) => row.bytes, (row) => row.packets)
);
const reportExternalDirectionItems = computed(() =>
  aggregateTopItems(reportOverview.value.external_access, (row) => row.direction, (row) => row.bytes, (row) => row.packets)
);
const aiActionItems = computed(() =>
  [...reportAISummary.value.actions, ...incidentAISummary.value.actions, ...assetAISummary.value.actions]
    .filter(Boolean)
    .slice(0, 8)
    .map((item, index) => ({ key: item, bytes: 8 - index, packets: 1 }))
);
const aiQueryRows = computed(() => aiQueryResult.value.rows.slice(0, 8));
const incidentContextSessionItems = computed(() => incidentContext.value.sessions.map((row) => ({ key: row.key, bytes: row.bytes, packets: row.packets })));
const incidentContextInsightItems = computed(() =>
  incidentContext.value.insights.map((row) => ({
    key: `${severityText(row.severity)} / ${incidentKindText(row.kind)} / ${row.subject}`,
    bytes: row.bytes,
    packets: row.packets
  }))
);
const incidentContextAnomalyItems = computed(() =>
  incidentContext.value.anomalies.map((row) => ({
    key: `${changeDimensionText(row.dimension)} / ${row.key}`,
    bytes: Math.abs(row.delta_bytes),
    packets: Math.abs(row.delta_packets)
  }))
);
const searchResultItems = computed(() => aggregateTopItems(searchResults.value, (row) => `${row.kind}: ${row.key}`, (row) => row.bytes, (row) => row.packets));
const sessionServiceItems = computed(() => aggregateTopItems(sessions.value, (row) => row.service, (row) => row.bytes, (row) => row.packets));
const sessionDirectionItems = computed(() => aggregateTopItems(sessions.value, (row) => row.direction, (row) => row.bytes, (row) => row.packets));
const sessionRiskItems = computed(() => aggregateTopItems(sessions.value, (row) => serviceRiskText(row.risk), (row) => row.bytes, (row) => row.packets));
const sessionTotalBytes = computed(() => sessions.value.reduce((sum, row) => sum + row.bytes, 0));
const sessionTotalPackets = computed(() => sessions.value.reduce((sum, row) => sum + row.packets, 0));
const highRiskSessionCount = computed(() => sessions.value.filter((row) => row.risk === 'critical' || row.risk === 'high').length);
const relationTitle = computed(() => `${trendDimensionLabel.value}关联 / ${objectRelations.value.key || trendKey.value.trim() || 'Top 对象'}`);
const relationInsightItems = computed(() =>
  objectRelations.value.insights.map((row) => ({
    key: `${severityText(row.severity)} / ${insightKindText(row.kind)} / ${row.subject}`,
    bytes: row.bytes,
    packets: row.packets
  }))
);
const alertFlowSharePercent = computed({
  get: () => Math.round(alertConfig.value.flow_share * 100),
  set: (value: number) => {
    alertConfig.value.flow_share = value / 100;
  }
});
const alertLinkUtilPercent = computed({
  get: () => Math.round(alertConfig.value.link_utilization * 100),
  set: (value: number) => {
    alertConfig.value.link_utilization = value / 100;
  }
});

const avgPacketSize = computed(() => {
  if (!summary.value.packets) return '0 B';
  return formatBytes(summary.value.bytes / summary.value.packets);
});

const selectedTopN = computed(() => {
  if (activeTopN.value === 'dst_ip') return topDst.value;
  if (activeTopN.value === 'dst_port') return topPorts.value;
  if (activeTopN.value === 'service') return topServices.value;
  if (activeTopN.value === 'service_category') return topServiceCategories.value;
  if (activeTopN.value === 'service_risk') return topServiceRisks.value;
  if (activeTopN.value === 'vlan') return topVLANs.value;
  if (activeTopN.value === 'dscp') return topDSCP.value;
  if (activeTopN.value === 'ecn') return topECN.value;
  if (activeTopN.value === 'protocol') return topProtocols.value;
  if (activeTopN.value === 'packet_len') return topPacketLens.value;
  if (activeTopN.value === 'flow') return topFlows.value;
  if (activeTopN.value === 'pair') return topPairs.value;
  return topSrc.value;
});

const selectedTopNTitle = computed(() => {
  if (activeTopN.value === 'dst_ip') return '目的 IP 排行';
  if (activeTopN.value === 'dst_port') return '目的端口排行';
  if (activeTopN.value === 'service') return '应用服务排行';
  if (activeTopN.value === 'service_category') return '服务类别排行';
  if (activeTopN.value === 'service_risk') return '服务风险排行';
  if (activeTopN.value === 'vlan') return 'VLAN 流量排行';
  if (activeTopN.value === 'dscp') return 'DSCP/QoS 排行';
  if (activeTopN.value === 'ecn') return 'ECN 标记排行';
  if (activeTopN.value === 'protocol') return '协议排行';
  if (activeTopN.value === 'packet_len') return '包长分布排行';
  if (activeTopN.value === 'flow') return '会话排行';
  if (activeTopN.value === 'pair') return '主机对排行';
  return '源 IP 排行';
});

const statusText = (status: string) => {
  const labels: Record<string, string> = {
    online: '在线',
    offline: '离线',
    degraded: '降级'
  };
  return labels[status] ?? status;
};

const dataQualityStatusText = (status: string) => {
  const labels: Record<string, string> = {
    healthy: '健康',
    warning: '警告',
    critical: '严重',
    unknown: '未知'
  };
  return labels[status] ?? status;
};

const aiConfidenceText = (confidence: number) => `${(confidence * 100).toFixed(0)}% 置信度`;

const capacityRiskText = (risk: string) => {
  const labels: Record<string, string> = {
    healthy: '健康',
    warning: '关注',
    critical: '严重'
  };
  return labels[risk] ?? risk;
};

const modeText = (mode: string) => {
  const labels: Record<string, string> = {
    mock: '模拟流量',
    pcap_replay: 'PCAP 回放',
    live_pcap: '网卡采集'
  };
  return labels[mode] ?? mode;
};

const severityText = (severity: string) => {
  const labels: Record<string, string> = {
    info: '提示',
    warning: '警告',
    critical: '严重'
  };
  return labels[severity] ?? severity;
};

const baselineStatusText = (status: string) => {
  const labels: Record<string, string> = {
    stable: '稳定',
    elevated: '偏高',
    critical: '严重偏离',
    new: '新增',
    learning: '学习中'
  };
  return labels[status] ?? status;
};

const changeDimensionText = (dimension: string) => {
  const labels: Record<string, string> = {
    link: '链路',
    src_ip: '源 IP',
    dst_ip: '目的 IP',
    dst_port: '目的端口',
    protocol: '协议',
    service: '应用服务'
  };
  return labels[dimension] ?? dimension;
};

const anomalyKindText = (kind: string) => {
  const labels: Record<string, string> = {
    link_burst: '链路突增',
    dimension_growth: '对象突增',
    new_dimension: '新增对象'
  };
  return labels[kind] ?? kind;
};

const formatChangeRatio = (value: number) => {
  if (value >= 999) return '新增';
  const sign = value > 0 ? '+' : '';
  return `${sign}${(value * 100).toFixed(1)}%`;
};

const insightKindText = (kind: string) => {
  const labels: Record<string, string> = {
    heavy_flow: '重流量会话',
    fanout: '主机扇出',
    sensitive_port: '敏感端口',
    service_risk: '高风险服务',
    qos_mark: 'QoS 标记',
    ecn_mark: 'ECN 标记',
    external_port_scan: '公网端口探测',
    external_session_burst: '公网会话突增',
    outbound_probe: '外联探测'
  };
  return labels[kind] ?? kind;
};

const incidentKindText = (kind: string) => {
  const labels: Record<string, string> = {
    threshold_alert: '阈值告警',
    collector_offline: '采集离线',
    link_burst: '链路突增',
    dimension_growth: '对象突增',
    new_dimension: '新增对象',
    heavy_flow: '重流量会话',
    fanout: '主机扇出',
    sensitive_port: '敏感端口',
    service_risk: '高风险服务',
    qos_mark: 'QoS 标记',
    ecn_mark: 'ECN 标记',
    external_port_scan: '公网端口探测',
    external_session_burst: '公网会话突增',
    outbound_probe: '外联探测'
  };
  return labels[kind] ?? insightKindText(kind);
};

const ruleMetricText = (metric: string) => ruleMetricOptions.find((item) => item.value === metric)?.label ?? metric;

const ruleNoiseText = (level: string) => {
  if (level === 'noisy') return '噪声偏高';
  if (level === 'quiet') return '静默';
  if (level === 'critical') return '严重命中';
  if (level === 'focused') return '聚焦';
  if (level === 'disabled') return '未启用';
  return '活跃';
};

const alertStatusText = (status: string) => {
  const labels: Record<string, string> = {
    open: '未处理',
    ack: '已确认',
    resolved: '已恢复'
  };
  return labels[status] ?? status;
};

const auditActionText = (action: string) => {
  const labels: Record<string, string> = {
    'asset.metadata.update': '资产元数据更新',
    'incident.status.update': '事件状态更新',
    'incident.note.add': '事件备注新增',
    'detection_rule.upsert': '检测规则保存',
    'detection_rule.delete': '检测规则删除',
    'collector.config.update': '采集配置更新',
    'config.version.restore': '配置版本恢复',
    'alert.status.update': '告警状态更新',
    'alert.config.update': '告警阈值更新',
    'alert.silence.add': '加入白名单',
    'alert.silence.remove': '移出白名单'
  };
  return labels[action] ?? action;
};

const configScopeText = (scope: string) => {
  const labels: Record<string, string> = {
    collector: '采集器配置',
    alerts: '告警配置',
    rules: '检测规则',
    assets: '资产配置',
    runtime: '运行时配置'
  };
  return labels[scope] ?? (scope || '-');
};

const serviceRiskText = (risk: string) => {
  const labels: Record<string, string> = {
    critical: '严重',
    high: '高',
    medium: '中',
    low: '低',
    observe: '观察'
  };
  return labels[risk] ?? risk;
};

const assetRiskLevelText = (level: string) => {
  const labels: Record<string, string> = {
    critical: '严重',
    high: '高',
    warning: '警告',
    low: '低'
  };
  return labels[level] ?? level;
};

const criticalityText = (value: string) => {
  const labels: Record<string, string> = {
    low: '低',
    normal: '普通',
    high: '高',
    critical: '核心'
  };
  return labels[value] ?? value ?? '普通';
};

const aiApprovalTypeText = (value: string) => {
  const labels: Record<string, string> = {
    rule: '检测规则',
    silence: '白名单',
    asset_enrichment: '资产画像'
  };
  return labels[value] ?? value;
};

const aiApprovalStatusText = (value: string) => {
  const labels: Record<string, string> = {
    pending: '待审批',
    approved: '已批准',
    rejected: '已驳回'
  };
  return labels[value] ?? value;
};

const exposureSubject = (row: ServiceExposure) => `dst_port:${row.port}`;

const exposureObject = (row: ServiceExposure) => `${row.ip}:${row.port} / ${row.protocol}`;

const isExposureSilenced = (row: ServiceExposure) => {
  const subject = exposureSubject(row);
  return Boolean(alertConfig.value.silenced_subjects?.includes(subject));
};

const formatTime = (ts: number) => {
  if (!ts) return '-';
  return new Date(ts * 1000).toLocaleString();
};

const setView = (view: string) => {
  currentView.value = view;
  window.requestAnimationFrame(() => window.scrollTo({ top: 0, behavior: 'smooth' }));
};

const applyCaptureConfig = async () => {
  if (!canWrite.value) return;
  switching.value = true;
  try {
    const config: CollectorConfig = {
      mode: selectedMode.value,
      iface: selectedIface.value,
      source_id: `${selectedMode.value}-${selectedIface.value}`,
      bpf_filter: selectedFilter.value.trim() || 'ip or ip6',
      pcap_file: selectedPcapFile.value.trim() || '/var/lib/nexaflow/replay.pcap',
      replay_speed: selectedReplaySpeed.value || 1,
      session_topn: Math.max(20, Math.min(5000, Math.trunc(selectedSessionTopN.value || 500)))
    };
    await api.updateCollectorConfig(config);
    await refresh();
  } finally {
    switching.value = false;
  }
};

const loadProfile = async () => {
  if (!profileIP.value.trim()) return;
  loading.value = true;
  try {
    const profileRes = await api.ipProfile(profileIP.value.trim(), selectedMinutes.value);
    ipProfile.value = profileRes.data;
    degraded.value = profileRes.degraded;
  } finally {
    loading.value = false;
  }
};

const loadPortProfile = async () => {
  if (!profilePort.value.trim()) return;
  loading.value = true;
  try {
    const profileRes = await api.portProfile(profilePort.value.trim(), selectedMinutes.value);
    portProfile.value = profileRes.data;
    degraded.value = profileRes.degraded;
  } finally {
    loading.value = false;
  }
};

const runSearch = async () => {
  if (!searchTerm.value.trim()) return;
  loading.value = true;
  try {
    const result = await api.search(searchTerm.value.trim(), selectedMinutes.value, 80);
    searchResults.value = result.data;
    degraded.value = result.degraded;
  } finally {
    loading.value = false;
  }
};

const loadSessions = async () => {
  loading.value = true;
  try {
    const result = await api.sessions(sessionSearch.value.trim(), selectedMinutes.value, 120);
    sessions.value = result.data;
    degraded.value = result.degraded;
  } finally {
    loading.value = false;
  }
};

const openSessionIP = async (ip: string) => {
  if (!ip) return;
  profileIP.value = ip;
  currentView.value = 'profile';
  await loadProfile();
};

const openSessionPort = async (port: string) => {
  if (!port) return;
  profilePort.value = port;
  currentView.value = 'port';
  await loadPortProfile();
};

const inspectSession = async (row: SessionRow) => {
  trendDimension.value = 'flow';
  trendKey.value = row.key;
  trendDirection.value = 'src';
  currentView.value = 'traffic';
  await loadDimensionTrend();
};

const inspectIncident = async (incident: SecurityIncident) => {
  const subject = incident.subject || '';
  if (subject.startsWith('dst_port:')) {
    profilePort.value = subject.replace('dst_port:', '');
    currentView.value = 'port';
    await loadPortProfile();
    return;
  }
  const ip = subject.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)?.[0];
  if (ip) {
    profileIP.value = ip;
    currentView.value = 'profile';
    await loadProfile();
    return;
  }
  searchTerm.value = subject;
  currentView.value = 'search';
  await runSearch();
};

const loadIncidentContext = async (incident: SecurityIncident) => {
  selectedIncident.value = incident;
  loadingIncidentContext.value = true;
  try {
    const [contextResult, timelineResult, aiResult, investigationResult] = await Promise.all([
      api.securityIncidentContext(incident.subject, incident.kind, selectedMinutes.value, 12),
      api.incidentTimeline(incident.id, 50),
      api.aiIncidentSummary(incident.subject, incident.kind, incident.id, selectedMinutes.value, 12),
      api.aiIncidentInvestigation(incident.subject, incident.kind, incident.id, selectedMinutes.value, 12)
    ]);
    incidentContext.value = contextResult.data;
    incidentTimeline.value = timelineResult.data;
    incidentAISummary.value = aiResult.data;
    incidentInvestigation.value = investigationResult.data;
    incidentNoteText.value = '';
    degraded.value = contextResult.degraded || timelineResult.degraded || aiResult.degraded || investigationResult.degraded;
  } finally {
    loadingIncidentContext.value = false;
  }
};

const openPrimaryIncidentContext = async () => {
  const incident = securityIncidents.value[0];
  currentView.value = 'incidents';
  if (incident) {
    await loadIncidentContext(incident);
  }
};

const runAIQuery = async (question = aiQuestion.value) => {
  const text = question.trim();
  if (!text) return;
  aiQuestion.value = text;
  queryingAI.value = true;
  try {
    const result = await api.aiQuery(text, selectedMinutes.value, 8);
    aiQueryResult.value = result.data;
    degraded.value = degraded.value || result.degraded || Boolean(result.data.degraded);
  } finally {
    queryingAI.value = false;
  }
};

const openPrimaryAssetProfile = async () => {
  const asset = assetRisks.value[0];
  if (!asset) return;
  profileIP.value = asset.ip;
  currentView.value = 'profile';
  await loadProfile();
};

const updateIncidentStatus = async (incident: SecurityIncident, status: string) => {
  if (!canWrite.value) return;
  handlingAlert.value = true;
  try {
    await api.updateIncidentStatus(incident.id, status);
    const [incidentRes, assetRiskRes] = await Promise.all([
      api.securityIncidents(selectedMinutes.value, 120),
      api.assetRiskPosture(selectedMinutes.value, 120)
    ]);
    securityIncidents.value = incidentRes.data;
    assetRisks.value = assetRiskRes.data;
    degraded.value = incidentRes.degraded || assetRiskRes.degraded;
    if (selectedIncident.value?.id === incident.id) {
      selectedIncident.value = securityIncidents.value.find((item) => item.id === incident.id) ?? null;
      const timelineRes = await api.incidentTimeline(incident.id, 50);
      incidentTimeline.value = timelineRes.data;
    }
  } finally {
    handlingAlert.value = false;
  }
};

const saveIncidentNote = async () => {
  if (!canWrite.value) return;
  const note = incidentNoteText.value.trim();
  if (!selectedIncident.value || !note) return;
  savingIncidentNote.value = true;
  try {
    await api.addIncidentNote(selectedIncident.value.id, note, 'operator');
    const timelineRes = await api.incidentTimeline(selectedIncident.value.id, 50);
    incidentTimeline.value = timelineRes.data;
    incidentNoteText.value = '';
  } finally {
    savingIncidentNote.value = false;
  }
};

const loadDimensionTrend = async () => {
  loading.value = true;
  try {
    const [trendResult, relationResult] = await Promise.all([
      api.dimensionTimeseries(
        trendDimension.value,
        trendKey.value.trim(),
        selectedMinutes.value,
        trendDirection.value,
        5
      ),
      api.objectRelations(trendDimension.value, trendKey.value.trim(), selectedMinutes.value, trendDirection.value, 8)
    ]);
    dimensionTrend.value = trendResult.data;
    objectRelations.value = relationResult.data;
    degraded.value = trendResult.degraded || relationResult.degraded;
  } finally {
    loading.value = false;
  }
};

const newRule = () => {
  if (!canWrite.value) return;
  ruleEditor.value = {
    id: '',
    name: '',
    category: '自定义检测',
    metric: 'src_ip_bytes',
    match: '',
    operator: 'gte',
    threshold: 100 * 1024 * 1024,
    severity: 'warning',
    enabled: true,
    description: '',
    recommended_action: '确认命中对象的业务用途、访问来源和近期变更背景',
    updated_at: 0
  };
};

const useGovernanceRule = (suggestion: AIGovernanceSuggestion) => {
  if (!canWrite.value || !suggestion.proposed_rule) return;
  ruleEditor.value = { ...suggestion.proposed_rule, id: '' };
  currentView.value = 'rules';
};

const reviewGovernanceSilence = (suggestion: AIGovernanceSuggestion) => {
  if (!canWrite.value || !suggestion.proposed_silence?.subject) return;
  whitelistSubject.value = suggestion.proposed_silence.subject;
  currentView.value = 'alerts';
};

const submitGovernanceApproval = async (suggestion: AIGovernanceSuggestion) => {
  if (!canWrite.value) return;
  const type = suggestion.proposed_rule ? 'rule' : suggestion.proposed_silence ? 'silence' : '';
  if (!type) return;
  aiApprovalBusy.value = suggestion.id;
  try {
    await api.createAIApprovalRequest({
      type,
      severity: suggestion.severity,
      title: suggestion.title,
      target: suggestion.target,
      summary: suggestion.summary,
      confidence: suggestion.confidence,
      evidence: suggestion.evidence,
      actions: suggestion.actions,
      payload: {
        proposed_rule: suggestion.proposed_rule,
        proposed_silence: suggestion.proposed_silence
      }
    });
    const result = await api.aiApprovalRequests('');
    aiApprovals.value = result.data;
  } finally {
    aiApprovalBusy.value = '';
  }
};

const submitAssetEnrichmentApproval = async (suggestion: AIAssetEnrichmentSuggestion) => {
  if (!canWrite.value) return;
  aiApprovalBusy.value = suggestion.id;
  try {
    await api.createAIApprovalRequest({
      type: 'asset_enrichment',
      severity: suggestion.severity,
      title: suggestion.title,
      target: suggestion.ip,
      summary: suggestion.summary,
      confidence: suggestion.confidence,
      evidence: suggestion.evidence,
      actions: suggestion.actions,
      payload: {
        proposed_metadata: suggestion.proposed_metadata
      }
    });
    const result = await api.aiApprovalRequests('');
    aiApprovals.value = result.data;
  } finally {
    aiApprovalBusy.value = '';
  }
};

const reviewAIApproval = async (request: AIApprovalRequest, action: 'approve' | 'reject') => {
  if (!canWrite.value) return;
  aiApprovalBusy.value = request.id;
  try {
    await api.reviewAIApprovalRequest(request.id, action, action === 'approve' ? '管理员确认执行' : '管理员驳回建议');
    await refresh();
  } finally {
    aiApprovalBusy.value = '';
  }
};

const editRule = (rule: DetectionRule) => {
  if (!canWrite.value) return;
  ruleEditor.value = { ...rule };
};

const saveRule = async () => {
  if (!canWrite.value) return;
  if (!ruleEditor.value || !ruleEditor.value.name.trim() || !ruleEditor.value.metric || ruleEditor.value.threshold <= 0) return;
  savingRule.value = true;
  try {
    const result = await api.saveDetectionRule({ ...ruleEditor.value, name: ruleEditor.value.name.trim(), match: ruleEditor.value.match.trim() });
    detectionRules.value = result.data;
    alertConfig.value.detection_rules = result.data;
    ruleEditor.value = null;
    const findingRes = await api.ruleFindings(selectedMinutes.value, 100);
    ruleFindings.value = findingRes.data;
    degraded.value = findingRes.degraded;
  } finally {
    savingRule.value = false;
  }
};

const deleteRule = async (rule: DetectionRule) => {
  if (!canWrite.value) return;
  savingRule.value = true;
  try {
    const result = await api.deleteDetectionRule(rule.id);
    detectionRules.value = result.data;
    alertConfig.value.detection_rules = result.data;
    if (ruleEditor.value?.id === rule.id) {
      ruleEditor.value = null;
    }
    const findingRes = await api.ruleFindings(selectedMinutes.value, 100);
    ruleFindings.value = findingRes.data;
    degraded.value = findingRes.degraded;
  } finally {
    savingRule.value = false;
  }
};

const toggleRule = async (rule: DetectionRule) => {
  if (!canWrite.value) return;
  const next = { ...rule, enabled: !rule.enabled };
  const result = await api.saveDetectionRule(next);
  detectionRules.value = result.data;
  alertConfig.value.detection_rules = result.data;
  const findingRes = await api.ruleFindings(selectedMinutes.value, 100);
  ruleFindings.value = findingRes.data;
  degraded.value = findingRes.degraded;
};

const saveAlertConfig = async () => {
  if (!canWrite.value) return;
  savingAlerts.value = true;
  try {
    const result = await api.updateAlertConfig(alertConfig.value);
    alertConfig.value = result.data;
    await refresh();
  } finally {
    savingAlerts.value = false;
  }
};

const restoreConfigVersion = async (version: ConfigVersion) => {
  if (!canWrite.value || !version.id) return;
  const confirmed = window.confirm(`恢复配置版本 ${version.id}？当前运行时配置会被该快照覆盖。`);
  if (!confirmed) return;
  restoringConfigVersion.value = version.id;
  try {
    await api.restoreConfigVersion(version.id);
    await refresh();
  } finally {
    restoringConfigVersion.value = '';
  }
};

const loadConfigVersionDiff = async (version: ConfigVersion) => {
  if (!version.id) return;
  diffingConfigVersion.value = version.id;
  try {
    const result = await api.configVersionDiff(version.id);
    selectedConfigDiff.value = result.data;
  } finally {
    diffingConfigVersion.value = '';
  }
};

const updateAlertStatus = async (alert: AlertEvent, status: string) => {
  if (!canWrite.value) return;
  handlingAlert.value = true;
  try {
    await api.updateAlertStatus(alert.id, status);
    await refresh();
  } finally {
    handlingAlert.value = false;
  }
};

const silenceSubject = async (subject: string) => {
  if (!canWrite.value) return;
  if (!subject.trim()) return;
  handlingAlert.value = true;
  try {
    const result = await api.addAlertSilence(subject.trim());
    alertConfig.value.silenced_subjects = result.data;
    await refresh();
  } finally {
    handlingAlert.value = false;
  }
};

const addWhitelistSubject = async () => {
  const subject = whitelistSubject.value.trim();
  if (!subject) return;
  await silenceSubject(subject);
  whitelistSubject.value = '';
};

const removeSilence = async (subject: string) => {
  if (!canWrite.value) return;
  handlingAlert.value = true;
  try {
    const result = await api.removeAlertSilence(subject);
    alertConfig.value.silenced_subjects = result.data;
    await refresh();
  } finally {
    handlingAlert.value = false;
  }
};

const editAsset = (asset: AssetRow) => {
  if (!canWrite.value) return;
  assetEditor.value = {
    ip: asset.ip,
    name: asset.name || '',
    owner: asset.owner || '',
    business: asset.business || '',
    environment: asset.environment || '未分类',
    criticality: asset.criticality || 'normal',
    tags: [...(asset.tags || [])],
    note: asset.note || '',
    metadata_updated_at: asset.metadata_updated_at || 0
  };
  assetTagsText.value = (asset.tags || []).join(', ');
};

const useAssetEnrichmentSuggestion = (suggestion: AIAssetEnrichmentSuggestion) => {
  if (!canWrite.value) return;
  const metadata = suggestion.proposed_metadata;
  assetEditor.value = {
    ip: metadata.ip,
    name: metadata.name || '',
    owner: metadata.owner || '',
    business: metadata.business || '',
    environment: metadata.environment || '未分类',
    criticality: metadata.criticality || 'normal',
    tags: [...(metadata.tags || [])],
    note: metadata.note || '',
    metadata_updated_at: metadata.metadata_updated_at || 0
  };
  assetTagsText.value = (metadata.tags || []).join(', ');
  currentView.value = 'assets';
};

const saveAssetMetadata = async () => {
  if (!canWrite.value) return;
  if (!assetEditor.value) return;
  savingAsset.value = true;
  try {
    const payload: AssetMetadata = {
      ...assetEditor.value,
      tags: assetTagsText.value
        .split(/[,，;；]/)
        .map((tag) => tag.trim())
        .filter(Boolean)
    };
    await api.updateAssetMetadata(payload);
    assetEditor.value = null;
    assetTagsText.value = '';
    await refresh();
  } finally {
    savingAsset.value = false;
  }
};

const openServiceTrend = async (service: string) => {
  trendDimension.value = 'service';
  trendKey.value = service;
  trendDirection.value = 'src';
  currentView.value = 'traffic';
  await loadDimensionTrend();
};

const openServicePort = async (port: string) => {
  profilePort.value = port;
  currentView.value = 'port';
  await loadPortProfile();
};

const searchServiceFlow = async (flow: string, fallback: string) => {
  searchTerm.value = flow || fallback;
  currentView.value = 'search';
  await runSearch();
};

const openExposureIP = async (row: ServiceExposure) => {
  profileIP.value = row.ip;
  currentView.value = 'profile';
  await loadProfile();
};

const openExposurePort = async (row: ServiceExposure) => {
  profilePort.value = row.port;
  currentView.value = 'port';
  await loadPortProfile();
};

const searchExposureFlow = async (row: ServiceExposure) => {
  searchTerm.value = row.sample_flow || `${row.ip}:${row.port}`;
  currentView.value = 'search';
  await runSearch();
};

const openExternalInternal = async (row: ExternalAccess) => {
  profileIP.value = row.internal_ip;
  currentView.value = 'profile';
  await loadProfile();
};

const openExternalPort = async (row: ExternalAccess) => {
  profilePort.value = row.port;
  currentView.value = 'port';
  await loadPortProfile();
};

const searchExternalFlow = async (row: ExternalAccess) => {
  searchTerm.value = row.sample_flow || row.public_ip;
  currentView.value = 'search';
  await runSearch();
};

const resetExposureFilters = () => {
  exposureSearch.value = '';
  exposureRiskFilter.value = 'all';
  exposureCategoryFilter.value = 'all';
};

const exportServiceExposure = () => {
  const rows = [
    ['服务对象', 'IP', '端口', '协议', '服务', '类别', '风险', '方向', '可信度', '客户端数', '流量字节', '包数', '样例客户端', '样例会话'],
    ...filteredServiceExposure.value.map((row) => [
      exposureObject(row),
      row.ip,
      row.port,
      row.protocol,
      row.service,
      row.category,
      serviceRiskText(row.risk),
      row.direction,
      row.confidence,
      String(row.client_count),
      String(row.bytes),
      String(row.packets),
      row.sample_client,
      row.sample_flow
    ])
  ];
  exportCSV(`nexaflow-service-exposure-${selectedMinutes.value}m.csv`, rows);
};

const exportServiceAnalytics = () => {
  const rows = [
    ['类型', '服务', '类别', '风险', '端口', '客户端数', '服务端数', '会话数', '流量字节', '包数', '样例会话', '最近出现'],
    ...serviceAnalytics.value.details.map((row) => [
      '服务详情',
      row.service,
      row.category,
      serviceRiskText(row.risk),
      row.top_port,
      String(row.client_count),
      String(row.server_count),
      String(row.session_count),
      String(row.bytes),
      String(row.packets),
      row.sample_flow,
      formatTime(row.last_seen)
    ]),
    ...serviceAnalytics.value.ports.map((row) => [
      '服务端口',
      row.service,
      row.category,
      serviceRiskText(row.risk),
      `${row.port}/${row.protocol}`,
      '',
      '',
      '',
      String(row.bytes),
      String(row.packets),
      row.sample_flow,
      formatTime(row.last_seen)
    ]),
    ...serviceAnalytics.value.growth.map((row) => [
      '服务增长',
      row.key,
      '',
      '',
      '',
      '',
      '',
      '',
      String(row.delta_bytes),
      String(row.delta_packets),
      `当前 ${row.current_bytes} / 上一周期 ${row.previous_bytes} / 变化率 ${formatChangeRatio(row.change_ratio)}`,
      ''
    ])
  ];
  exportCSV(`nexaflow-service-analytics-${selectedMinutes.value}m.csv`, rows);
};

const exportExternalAccess = () => {
  const rows = [
    ['公网对端', '内部资产', '方向', '端口', '协议', '服务', '类别', '风险', '会话数', '流量字节', '包数', '首次出现', '最近出现', '样例会话'],
    ...externalAccess.value.map((row) => [
      row.public_ip,
      row.internal_ip,
      row.direction,
      row.port,
      row.protocol,
      row.service,
      row.category,
      serviceRiskText(row.risk),
      String(row.session_count),
      String(row.bytes),
      String(row.packets),
      formatTime(row.first_seen),
      formatTime(row.last_seen),
      row.sample_flow
    ])
  ];
  exportCSV(`nexaflow-external-access-${selectedMinutes.value}m.csv`, rows);
};

const exportWindows = () => {
  const rows = [
    ['时间', '采集源', '网卡', '流量字节', '包数', '利用率'],
    ...historyWindows.value.map((row) => [
      formatTime(row.window_ts),
      row.source_id,
      row.iface,
      String(row.bytes),
      String(row.packets),
      String(row.utilization)
    ])
  ];
  exportCSV(`nexaflow-windows-${selectedMinutes.value}m.csv`, rows);
};

const exportDataQuality = () => {
  const rows = [
    ['类型', '采集源', '网卡', '状态', '窗口数', '覆盖率', '最新延迟秒', '流量字节', '包数', 'Drops', '开始时间', '结束时间', '摘要'],
    ['摘要', '-', '-', dataQualityStatusText(dataQuality.value.status), String(dataQuality.value.summary.observed_windows), String(dataQuality.value.summary.coverage_ratio), String(dataQuality.value.summary.freshness_seconds), String(dataQuality.value.summary.bytes), String(dataQuality.value.summary.packets), String(dataQuality.value.summary.drops), '', formatTime(dataQuality.value.summary.latest_window_ts), `${dataQuality.value.summary.gap_count} 个断档 / ${dataQuality.value.summary.stale_sources} 个异常源`],
    ...dataQuality.value.sources.map((row) => [
      '采集源',
      row.source_id,
      row.iface,
      dataQualityStatusText(row.status),
      String(row.windows),
      String(row.coverage_ratio),
      String(row.freshness_seconds),
      String(row.bytes),
      String(row.packets),
      String(row.drops),
      formatTime(row.first_window_ts),
      formatTime(row.latest_window_ts),
      ''
    ]),
    ...captureQuality.value.sources.map((row) => [
      '采集队列',
      row.source_id,
      row.iface,
      dataQualityStatusText(row.status),
      String(row.windows),
      String(row.queue_pressure || 0),
      String(row.freshness_seconds),
      String(row.rx_bytes + row.tx_bytes),
      String(row.rx_packets + row.tx_packets),
      String(row.rx_dropped + row.tx_dropped),
      formatTime(row.first_window_ts),
      formatTime(row.latest_window_ts),
      `packet ${row.packet_queue_len}/${row.packet_queue_capacity}; window ${row.window_queue_len}/${row.window_queue_capacity}`
    ]),
    ...dataQuality.value.gaps.map((row) => [
      '断档',
      row.source_id,
      row.iface,
      'warning',
      String(row.missing_windows),
      '',
      '',
      '',
      '',
      '',
      formatTime(row.start_ts),
      formatTime(row.end_ts),
      `断档 ${row.duration_seconds} 秒`
    ])
  ];
  exportCSV(`nexaflow-data-quality-${selectedMinutes.value}m.csv`, rows);
};

const exportCapacityPlanning = () => {
  const summary = capacityPlanning.value.summary;
  const rows = [
    ['类型', '对象', '当前值', '上一周期', '增量', '变化率', '流量字节', '包数', '摘要'],
    ['摘要', '链路容量', `${summary.bandwidth_mbps} Mbps`, '', '', '', '', '', `峰值 ${summary.peak_mbps.toFixed(2)} Mbps / P95 ${summary.p95_mbps.toFixed(2)} Mbps / 余量 ${summary.headroom_mbps.toFixed(2)} Mbps`],
    ['摘要', '容量风险', capacityRiskText(summary.risk_level), '', `${summary.growth_mbps.toFixed(2)} Mbps`, `${(summary.growth_ratio * 100).toFixed(1)}%`, '', '', `预计触顶 ${summary.saturation_eta_mins ? summary.saturation_eta_mins.toFixed(0) : '-'} 分钟`],
    ...capacityPlanning.value.top_src_growth.map((row) => ['源 IP 增长', row.key, String(row.current_bytes), String(row.previous_bytes), String(row.delta_bytes), formatChangeRatio(row.change_ratio), String(row.current_bytes), String(row.current_packets), '']),
    ...capacityPlanning.value.top_port_growth.map((row) => ['端口增长', row.key, String(row.current_bytes), String(row.previous_bytes), String(row.delta_bytes), formatChangeRatio(row.change_ratio), String(row.current_bytes), String(row.current_packets), '']),
    ...capacityPlanning.value.top_service_growth.map((row) => ['服务增长', row.key, String(row.current_bytes), String(row.previous_bytes), String(row.delta_bytes), formatChangeRatio(row.change_ratio), String(row.current_bytes), String(row.current_packets), ''])
  ];
  exportCSV(`nexaflow-capacity-${selectedMinutes.value}m.csv`, rows);
};

const exportSelectedTopN = () => {
  const rows = [
    ['对象', '流量字节', '包数'],
    ...selectedTopN.value.map((item) => [item.key, String(item.bytes), String(item.packets)])
  ];
  exportCSV(`nexaflow-${activeTopN.value}-${selectedMinutes.value}m.csv`, rows);
};

const exportSessions = () => {
  const rows = [
    ['会话', '源IP', '源端口', '目的IP', '目的端口', '协议', '服务', '类别', '风险', '方向', '服务端', '客户端', '流量字节', '包数', '平均包长', '首次出现', '最近出现'],
    ...sessions.value.map((row) => [
      row.key,
      row.src_ip,
      row.src_port,
      row.dst_ip,
      row.dst_port,
      row.protocol,
      row.service,
      row.category,
      serviceRiskText(row.risk),
      row.direction,
      `${row.server_ip}:${row.server_port}`,
      row.client_ip,
      String(row.bytes),
      String(row.packets),
      String(row.avg_packet_size),
      formatTime(row.first_seen),
      formatTime(row.last_seen)
    ])
  ];
  exportCSV(`nexaflow-sessions-${selectedMinutes.value}m.csv`, rows);
};

const exportReportOverview = () => {
  const report = reportOverview.value;
  const rows = [
    ['类型', '对象', '级别/状态', '指标', '流量字节', '包数/会话', '摘要', '建议'],
    ['摘要', '观察范围', rangeLabel.value, `${report.summary.avg_mbps.toFixed(2)} Mbps 平均 / ${report.summary.peak_mbps.toFixed(2)} Mbps 峰值`, String(report.summary.bytes), String(report.summary.packets), `资产 ${report.summary.asset_count} / 事件 ${report.summary.open_incidents} / 异常 ${report.summary.anomaly_count}`, ''],
    ...report.recommendations.map((row) => ['建议', row.title, severityText(row.level), '', '', '', row.detail, row.detail]),
    ...report.asset_risks.map((row) => [
      '资产风险',
      `${row.ip} ${row.name || row.business || ''}`.trim(),
      assetRiskLevelText(row.risk_level),
      `评分 ${row.risk_score} / 暴露 ${row.exposed_services} / 事件 ${row.open_incidents}`,
      String(row.total_bytes),
      String(row.total_packets),
      row.top_finding || '',
      row.recommended_action || ''
    ]),
    ...report.incidents.map((row) => [
      '安全事件',
      row.subject,
      `${severityText(row.severity)} / ${alertStatusText(row.status)}`,
      `${row.source} / ${incidentKindText(row.kind)} / 评分 ${row.score}`,
      String(row.bytes),
      String(row.packets),
      row.summary,
      row.recommended_action
    ]),
    ...report.anomalies.map((row) => [
      '异常波动',
      `${changeDimensionText(row.dimension)} / ${row.key}`,
      severityText(row.severity),
      `${anomalyKindText(row.kind)} / ${formatChangeRatio(row.change_ratio)} / 评分 ${row.score}`,
      String(row.current_bytes),
      String(row.current_packets),
      row.summary,
      '确认是否符合变更计划，必要时进入对象画像或检索分析'
    ]),
    ...report.exposures.map((row) => [
      '服务暴露',
      `${row.ip}:${row.port} / ${row.protocol}`,
      serviceRiskText(row.risk),
      `${row.service} / ${row.category} / ${row.direction}`,
      String(row.bytes),
      String(row.packets),
      row.sample_flow,
      '核对服务用途、访问来源和防火墙策略'
    ]),
    ...report.external_access.map((row) => [
      '公网访问',
      `${row.public_ip} -> ${row.internal_ip}:${row.port}`,
      serviceRiskText(row.risk),
      `${row.direction} / ${row.service} / ${row.category}`,
      String(row.bytes),
      String(row.session_count),
      row.sample_flow,
      '核对公网对端可信度和会话数量'
    ])
  ];
  exportCSV(`nexaflow-overview-report-${selectedMinutes.value}m.csv`, rows);
};

const exportRuleFindings = () => {
  const rows = [
    ['规则', '对象', '级别', '指标', '当前值', '阈值', '流量字节', '包数', '摘要', '建议', '命中时间'],
    ...ruleFindings.value.map((row) => [
      row.rule_name,
      row.subject,
      severityText(row.severity),
      ruleMetricText(row.metric),
      String(row.value),
      String(row.threshold),
      String(row.bytes),
      String(row.packets),
      row.summary,
      row.recommended_action,
      formatTime(row.matched_at)
    ])
  ];
  exportCSV(`nexaflow-rule-findings-${selectedMinutes.value}m.csv`, rows);
};

const exportCSV = (filename: string, rows: string[][]) => {
  const csv = rows.map((row) => row.map((cell) => `"${cell.replace(/"/g, '""')}"`).join(',')).join('\n');
  const blob = new Blob([`\ufeff${csv}`], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
};
</script>

<template>
  <main class="app-shell">
    <section v-if="authChecking" class="login-screen">
      <div class="login-panel">
        <div class="brand-mark">
          <RadioTower :size="24" />
        </div>
        <h1>NexaFlow</h1>
        <p>正在校验访问状态</p>
      </div>
    </section>

    <section v-else-if="authStatus.enabled && !authStatus.authenticated" class="login-screen">
      <form class="login-panel" @submit.prevent="login">
        <div class="brand-mark">
          <RadioTower :size="24" />
        </div>
        <h1>NexaFlow</h1>
        <p>请输入访问凭据进入流量分析控制台</p>
        <label>
          <span>操作人</span>
          <input v-model="loginActor" autocomplete="username" placeholder="operator" />
        </label>
        <label>
          <span>访问密码</span>
          <input v-model="loginPassword" type="password" autocomplete="current-password" placeholder="输入访问密码" />
        </label>
        <button type="submit" :disabled="loggingIn">{{ loggingIn ? '登录中...' : '登录' }}</button>
        <small v-if="loginError" class="login-error">{{ loginError }}</small>
      </form>
    </section>

    <template v-else>
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-mark">
          <RadioTower :size="22" />
        </div>
        <div>
          <span>NexaFlow</span>
          <small>流量分析控制台</small>
        </div>
      </div>
      <nav>
        <section v-for="group in navGroups" :key="group.title" class="nav-group">
          <p>{{ group.title }}</p>
          <button
            v-for="item in group.items"
            :key="item.id"
            type="button"
            :class="{ active: currentView === item.id }"
            @click="setView(item.id)"
          >
            <component :is="item.icon" :size="17" />
            <span>{{ item.label }}</span>
          </button>
        </section>
      </nav>
      <div class="sidebar-status">
        <span class="status-dot" :class="{ offline: systemStatus.database !== 'ok' }"></span>
        <div>
          <strong>{{ systemStatus.database === 'ok' ? '系统正常' : '系统降级' }}</strong>
          <small>{{ onlineCollectorCount }} / {{ collectors.length }} 采集器在线</small>
        </div>
      </div>
    </aside>

    <section class="workspace">
      <header class="topbar">
        <div>
          <h1>{{ pageTitle }}</h1>
          <p>{{ pageSubtitle }}</p>
        </div>
        <div class="topbar-actions">
          <div class="status-chip auth-chip">
            <span>{{ authStatus.enabled ? `${authStatus.actor} / ${authRoleText}` : authRoleText }}</span>
            <button v-if="authStatus.enabled" type="button" @click="logout">退出</button>
          </div>
          <div class="status-chip" :class="{ warning: degraded }">
            <span class="status-dot" :class="{ offline: degraded }"></span>
            {{ degraded ? '降级数据' : '实时数据' }}
          </div>
          <label class="range-control">
            <span>时间范围</span>
            <select v-model="selectedMinutes" @change="refresh">
              <option v-for="item in rangeOptions" :key="item.value" :value="item.value">{{ item.label }}</option>
            </select>
          </label>
          <button class="icon-button" :class="{ spinning: loading }" type="button" @click="refresh" aria-label="刷新">
            <RefreshCw :size="18" />
          </button>
        </div>
      </header>

      <section class="status-strip">
        <div>
          <span>数据库</span>
          <strong>{{ systemStatus.database === 'ok' ? '正常' : systemStatus.database }}</strong>
        </div>
        <div>
          <span>最近窗口</span>
          <strong>{{ formatTime(systemStatus.latest_window_ts) }}</strong>
        </div>
        <div>
          <span>采集器</span>
          <strong>{{ onlineCollectorCount }} / {{ collectors.length || 0 }}</strong>
        </div>
        <div>
          <span>活跃资产</span>
          <strong>{{ activeAssetCount.toLocaleString() }}</strong>
        </div>
      </section>

      <div v-if="degraded" class="notice">
        <AlertTriangle :size="18" />
        API 当前处于降级模式，ClickHouse 写入实时窗口后将自动展示真实数据。
      </div>

      <section class="metrics-grid">
        <article class="metric">
          <Gauge :size="22" />
          <div>
            <span>近 {{ rangeLabel }} 吞吐</span>
            <strong>{{ formatRate(summary.bytes) }}</strong>
          </div>
        </article>
        <article class="metric">
          <Activity :size="22" />
          <div>
            <span>包数</span>
            <strong>{{ summary.packets.toLocaleString() }}</strong>
          </div>
        </article>
        <article class="metric">
          <Database :size="22" />
          <div>
            <span>总流量</span>
            <strong>{{ formatBytes(summary.bytes) }}</strong>
          </div>
        </article>
        <article class="metric">
          <RadioTower :size="22" />
          <div>
            <span>链路利用率</span>
            <strong>{{ (summary.utilization * 100).toFixed(2) }}%</strong>
          </div>
        </article>
      </section>

      <template v-if="currentView === 'dashboard'">
        <section class="command-grid">
          <LiveFlowMap :nodes="serviceMap.nodes" :links="matrixRows" />
          <HealthGaugePanel :utilization="summary.utilization" :pps="pps" :online="onlineCollectorCount" :total="collectors.length" />
        </section>
        <section class="command-grid">
          <TrafficCompositionPanel
            :protocols="topProtocols"
            :ports="topPorts"
            :directions="trafficAnalysis.directions"
            :packet-sizes="trafficAnalysis.packet_sizes"
          />
          <TrafficHeatmap :points="series" />
        </section>

        <section class="main-grid">
          <DashboardChart class="chart-panel" :points="series" />
          <section class="collector-panel">
            <h2>采集器状态</h2>
            <div v-for="collector in collectors" :key="collector.id" class="collector-row">
              <span class="status-dot" :class="{ offline: collector.status !== 'online' }"></span>
              <div>
                <strong>{{ collector.id }}</strong>
                <small>{{ collector.source_id }} / {{ collector.iface ?? '-' }} / {{ modeText(collector.mode) }}</small>
              </div>
              <b :class="{ warning: collector.status !== 'online' }">{{ statusText(collector.status) }}</b>
            </div>
          </section>
        </section>

        <section class="tables-grid">
          <TopNTable title="源 IP 排行" :items="topSrc" />
          <TopNTable title="目的 IP 排行" :items="topDst" />
          <TopNTable title="目的端口排行" :items="topPorts" />
          <TopNTable title="协议排行" :items="topProtocols" />
        </section>
      </template>

      <template v-else-if="currentView === 'ai'">
        <section class="metrics-grid">
          <article class="metric">
            <Sparkles :size="22" />
            <div>
              <span>AI 模式</span>
              <strong>{{ reportAISummary.mode || 'local_mock' }}</strong>
            </div>
          </article>
          <article class="metric">
            <Gauge :size="22" />
            <div>
              <span>巡检置信度</span>
              <strong>{{ aiConfidenceText(reportAISummary.confidence) }}</strong>
            </div>
          </article>
          <article class="metric">
            <AlertTriangle :size="22" />
            <div>
              <span>开放事件</span>
              <strong>{{ openIncidentCount.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Shield :size="22" />
            <div>
              <span>严重资产</span>
              <strong>{{ criticalAssetRiskCount.toLocaleString() }}</strong>
            </div>
          </article>
        </section>

        <section class="ai-workbench-actions">
          <button class="command-button" type="button" @click="openPrimaryIncidentContext">查看首要事件上下文</button>
          <button class="command-button" type="button" @click="openPrimaryAssetProfile">查看最高风险资产</button>
          <button class="command-button" type="button" @click="currentView = 'reports'">进入报表中心</button>
        </section>

        <section class="table-panel ai-query-panel">
          <div class="panel-heading">
            <h2>自然语言查询</h2>
            <span>{{ aiQueryResult.intent.title }} / {{ aiConfidenceText(aiQueryResult.confidence) }}</span>
          </div>
          <form class="ai-query-form" @submit.prevent="runAIQuery()">
            <input v-model="aiQuestion" type="text" placeholder="最近 30 分钟哪个公网 IP 访问最多？" />
            <button class="command-button" type="submit" :disabled="queryingAI || !aiQuestion.trim()">
              {{ queryingAI ? '查询中...' : '查询' }}
            </button>
          </form>
          <div class="ai-workbench-actions">
            <button v-for="item in aiQueryResult.followups" :key="`ai-followup-${item}`" class="inline-button" type="button" @click="runAIQuery(item)">
              {{ item }}
            </button>
          </div>
          <p class="ai-summary-lead">{{ aiQueryResult.summary }}</p>
          <div class="ai-summary-grid">
            <div>
              <span>查询发现</span>
              <ul>
                <li v-for="item in aiQueryResult.findings" :key="`ai-query-finding-${item}`">{{ item }}</li>
              </ul>
            </div>
            <div>
              <span>证据与建议</span>
              <ul>
                <li v-for="item in [...aiQueryResult.evidence.slice(0, 3), ...aiQueryResult.actions.slice(0, 2)]" :key="`ai-query-evidence-${item}`">{{ item }}</li>
              </ul>
            </div>
          </div>
          <div v-if="aiQueryRows.length === 0" class="empty-state">暂无查询结果</div>
          <table v-else>
            <thead>
              <tr>
                <th>对象</th>
                <th>流量</th>
                <th>包数/计数</th>
                <th>说明</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(row, index) in aiQueryRows" :key="`ai-query-row-${index}`">
                <td>{{ aiRowObject(row) }}</td>
                <td>{{ aiRowBytes(row) }}</td>
                <td>{{ aiRowPackets(row) }}</td>
                <td>{{ aiRowDetail(row) }}</td>
              </tr>
            </tbody>
          </table>
        </section>

        <section class="table-panel ai-approval-panel">
          <div class="panel-heading">
            <h2>AI 审批队列</h2>
            <span>{{ pendingAIApprovals.length.toLocaleString() }} 待审批 / {{ aiApprovals.length.toLocaleString() }} 总数</span>
          </div>
          <div v-if="aiApprovals.length === 0" class="empty-state">暂无 AI 审批请求</div>
          <div v-else class="governance-list">
            <article v-for="item in aiApprovals.slice(0, 8)" :key="item.id" class="governance-card">
              <div class="governance-card-header">
                <div>
                  <strong>{{ item.title }}</strong>
                  <span>{{ aiApprovalTypeText(item.type) }} / {{ item.target }}</span>
                </div>
                <b class="severity-pill" :class="item.severity">{{ aiApprovalStatusText(item.status) }} / {{ aiConfidenceText(item.confidence) }}</b>
              </div>
              <p>{{ item.summary }}</p>
              <div class="ai-summary-grid">
                <div>
                  <span>证据</span>
                  <ul>
                    <li v-for="evidence in item.evidence.slice(0, 3)" :key="`ai-approval-evidence-${item.id}-${evidence}`">{{ evidence }}</li>
                  </ul>
                </div>
                <div>
                  <span>执行记录</span>
                  <ul>
                    <li>提交：{{ item.created_by || '-' }} / {{ formatTime(item.created_at) }}</li>
                    <li v-if="item.reviewed_at">处理：{{ item.reviewed_by || '-' }} / {{ formatTime(item.reviewed_at) }}</li>
                    <li v-if="item.apply_result">结果：{{ item.apply_result }}</li>
                  </ul>
                </div>
              </div>
              <div v-if="item.status === 'pending'" class="ai-workbench-actions">
                <button class="command-button" type="button" :disabled="!canWrite || aiApprovalBusy === item.id" @click="reviewAIApproval(item, 'approve')">批准执行</button>
                <button class="inline-button" type="button" :disabled="!canWrite || aiApprovalBusy === item.id" @click="reviewAIApproval(item, 'reject')">驳回</button>
              </div>
            </article>
          </div>
        </section>

        <section class="table-panel ai-governance-panel">
          <div class="panel-heading">
            <h2>AI 治理建议</h2>
            <span>{{ aiGovernance.suggestions.length.toLocaleString() }} 条 / {{ aiGovernance.mode }}</span>
          </div>
          <p class="ai-summary-lead">{{ aiGovernance.summary }}</p>
          <div v-if="aiGovernance.suggestions.length === 0" class="empty-state">暂无治理建议</div>
          <div v-else class="governance-list">
            <article v-for="item in aiGovernance.suggestions" :key="item.id" class="governance-card">
              <div class="governance-card-header">
                <div>
                  <strong>{{ item.title }}</strong>
                  <span>{{ item.target }}</span>
                </div>
                <b class="severity-pill" :class="item.severity">{{ severityText(item.severity) }} / {{ aiConfidenceText(item.confidence) }}</b>
              </div>
              <p>{{ item.summary }}</p>
              <div class="ai-summary-grid">
                <div>
                  <span>证据</span>
                  <ul>
                    <li v-for="evidence in item.evidence.slice(0, 4)" :key="`governance-evidence-${item.id}-${evidence}`">{{ evidence }}</li>
                  </ul>
                </div>
                <div>
                  <span>动作</span>
                  <ul>
                    <li v-for="action in item.actions.slice(0, 4)" :key="`governance-action-${item.id}-${action}`">{{ action }}</li>
                  </ul>
                </div>
              </div>
              <div class="ai-workbench-actions">
                <button v-if="item.proposed_rule" class="command-button" type="button" :disabled="!canWrite" @click="useGovernanceRule(item)">填入规则草案</button>
                <button v-if="item.proposed_silence" class="command-button" type="button" :disabled="!canWrite" @click="reviewGovernanceSilence(item)">复核白名单</button>
                <button v-if="item.proposed_rule || item.proposed_silence" class="inline-button" type="button" :disabled="!canWrite || aiApprovalBusy === item.id" @click="submitGovernanceApproval(item)">提交审批</button>
              </div>
            </article>
          </div>
        </section>

        <section class="table-panel ai-asset-enrichment-panel">
          <div class="panel-heading">
            <h2>AI 资产画像补全</h2>
            <span>{{ aiAssetEnrichment.suggestions.length.toLocaleString() }} 条 / {{ aiAssetEnrichment.mode }}</span>
          </div>
          <p class="ai-summary-lead">{{ aiAssetEnrichment.summary }}</p>
          <div v-if="aiAssetEnrichment.suggestions.length === 0" class="empty-state">暂无资产补全建议</div>
          <div v-else class="governance-list">
            <article v-for="item in aiAssetEnrichment.suggestions" :key="item.id" class="governance-card">
              <div class="governance-card-header">
                <div>
                  <strong>{{ item.title }}</strong>
                  <span>缺失字段：{{ item.missing_fields.join('、') || '需复核现有画像' }}</span>
                </div>
                <b class="severity-pill" :class="item.severity">{{ severityText(item.severity) }} / {{ aiConfidenceText(item.confidence) }}</b>
              </div>
              <p>{{ item.summary }}</p>
              <div class="ai-summary-grid">
                <div>
                  <span>建议画像</span>
                  <ul>
                    <li>名称：{{ item.proposed_metadata.name }}</li>
                    <li>负责人：{{ item.proposed_metadata.owner }}</li>
                    <li>业务：{{ item.proposed_metadata.business }}</li>
                    <li>环境/重要性：{{ item.proposed_metadata.environment }} / {{ criticalityText(item.proposed_metadata.criticality) }}</li>
                  </ul>
                </div>
                <div>
                  <span>证据</span>
                  <ul>
                    <li v-for="evidence in item.evidence.slice(0, 5)" :key="`asset-enrich-evidence-${item.id}-${evidence}`">{{ evidence }}</li>
                  </ul>
                </div>
              </div>
              <div class="asset-tag-preview">
                <span v-for="tag in item.proposed_metadata.tags" :key="`asset-enrich-tag-${item.id}-${tag}`">{{ tag }}</span>
              </div>
              <div class="ai-workbench-actions">
                <button class="command-button" type="button" :disabled="!canWrite" @click="useAssetEnrichmentSuggestion(item)">填入资产台账</button>
                <button class="inline-button" type="button" :disabled="!canWrite || aiApprovalBusy === item.id" @click="submitAssetEnrichmentApproval(item)">提交审批</button>
                <button class="inline-button" type="button" @click="profileIP = item.ip; currentView = 'asset-risk'">查看资产风险</button>
              </div>
            </article>
          </div>
        </section>

        <section class="table-panel ai-rule-effectiveness-panel">
          <div class="panel-heading">
            <h2>AI 规则效果评估</h2>
            <span>{{ aiRuleEffectiveness.summary.health }} / {{ aiRuleEffectiveness.mode }}</span>
          </div>
          <section class="metrics-grid compact-metrics">
            <article class="metric">
              <Settings2 :size="20" />
              <div>
                <span>启用规则</span>
                <strong>{{ aiRuleEffectiveness.summary.enabled_rules }} / {{ aiRuleEffectiveness.summary.rule_count }}</strong>
              </div>
            </article>
            <article class="metric">
              <Activity :size="20" />
              <div>
                <span>命中总数</span>
                <strong>{{ aiRuleEffectiveness.summary.total_hits.toLocaleString() }}</strong>
              </div>
            </article>
            <article class="metric">
              <AlertTriangle :size="20" />
              <div>
                <span>噪声规则</span>
                <strong>{{ aiRuleEffectiveness.summary.noisy_rules.toLocaleString() }}</strong>
              </div>
            </article>
            <article class="metric">
              <Shield :size="20" />
              <div>
                <span>严重命中</span>
                <strong>{{ aiRuleEffectiveness.summary.critical_hits.toLocaleString() }}</strong>
              </div>
            </article>
          </section>
          <section class="command-grid">
            <HorizontalBarChart title="规则效果评分" eyebrow="Rule Score" :items="aiRuleEffectivenessItems" unit="count" />
            <section class="ai-action-panel">
              <div class="panel-heading">
                <h2>调优建议</h2>
                <span>{{ aiRuleEffectiveness.tuning_suggestions.length.toLocaleString() }} 项</span>
              </div>
              <div v-if="aiRuleEffectiveness.tuning_suggestions.length === 0" class="empty-state">暂无调优建议</div>
              <article v-for="item in aiRuleEffectiveness.tuning_suggestions.slice(0, 5)" :key="`rule-tuning-${item.rule_id}-${item.noise_level}`">
                <strong>{{ item.title }}</strong>
                <span>{{ ruleNoiseText(item.noise_level) }} / 评分 {{ item.score }}</span>
                <small>{{ item.summary }}</small>
              </article>
            </section>
          </section>
          <div v-if="aiRuleEffectiveness.rules.length === 0" class="empty-state">暂无检测规则</div>
          <table v-else>
            <thead>
              <tr>
                <th>规则</th>
                <th>状态</th>
                <th>命中</th>
                <th>对象</th>
                <th>重复率</th>
                <th>评分</th>
                <th>建议</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in aiRuleEffectiveness.rules.slice(0, 8)" :key="`rule-effect-${row.id}`">
                <td>
                  <strong>{{ row.name }}</strong>
                  <span class="cell-subtle">{{ ruleMetricText(row.metric) }} / {{ row.match || '全部对象' }}</span>
                </td>
                <td><span class="severity-pill" :class="row.severity">{{ ruleNoiseText(row.noise_level) }}</span></td>
                <td>{{ row.hit_count.toLocaleString() }} / 严重 {{ row.critical_count.toLocaleString() }}</td>
                <td>{{ row.unique_subjects.toLocaleString() }} / 静默 {{ row.silenced_hits.toLocaleString() }}</td>
                <td>{{ (row.duplicate_ratio * 100).toFixed(0) }}%</td>
                <td>{{ row.score }}</td>
                <td>{{ row.recommendations[0] || row.summary }}</td>
              </tr>
            </tbody>
          </table>
        </section>

        <section class="command-grid">
          <section class="ai-summary-card featured">
            <div class="panel-heading">
              <h2>{{ reportAISummary.title }}</h2>
              <span>{{ reportAISummary.mode }} / {{ aiConfidenceText(reportAISummary.confidence) }}</span>
            </div>
            <p class="ai-summary-lead">{{ reportAISummary.summary }}</p>
            <div class="ai-summary-grid">
              <div>
                <span>巡检发现</span>
                <ul>
                  <li v-for="item in reportAISummary.findings" :key="`ai-report-finding-${item}`">{{ item }}</li>
                </ul>
              </div>
              <div>
                <span>处置建议</span>
                <ul>
                  <li v-for="item in reportAISummary.actions" :key="`ai-report-action-${item}`">{{ item }}</li>
                </ul>
              </div>
            </div>
          </section>
          <section class="ai-summary-card">
            <div class="panel-heading">
              <h2>{{ incidentAISummary.title }}</h2>
              <span>{{ incidentAISummary.mode }} / {{ aiConfidenceText(incidentAISummary.confidence) }}</span>
            </div>
            <p class="ai-summary-lead">{{ incidentAISummary.summary }}</p>
            <div class="ai-summary-grid">
              <div>
                <span>调查发现</span>
                <ul>
                  <li v-for="item in incidentAISummary.findings" :key="`ai-incident-finding-${item}`">{{ item }}</li>
                </ul>
              </div>
              <div>
                <span>下一步</span>
                <ul>
                  <li v-for="item in incidentAISummary.actions" :key="`ai-incident-action-${item}`">{{ item }}</li>
                </ul>
              </div>
            </div>
          </section>
        </section>

        <section class="command-grid">
          <section class="ai-summary-card">
            <div class="panel-heading">
              <h2>{{ assetAISummary.title }}</h2>
              <span>{{ assetAISummary.mode }} / {{ aiConfidenceText(assetAISummary.confidence) }}</span>
            </div>
            <p class="ai-summary-lead">{{ assetAISummary.summary }}</p>
            <div class="ai-summary-grid">
              <div>
                <span>关键发现</span>
                <ul>
                  <li v-for="item in assetAISummary.findings" :key="`ai-asset-finding-${item}`">{{ item }}</li>
                </ul>
              </div>
              <div>
                <span>建议动作</span>
                <ul>
                  <li v-for="item in assetAISummary.actions" :key="`ai-asset-action-${item}`">{{ item }}</li>
                </ul>
              </div>
            </div>
          </section>
          <section class="table-panel ai-action-panel">
            <div class="panel-heading">
              <h2>AI 行动清单</h2>
              <span>{{ aiActionItems.length.toLocaleString() }} 项</span>
            </div>
            <div v-if="aiActionItems.length === 0" class="empty-state">暂无行动建议</div>
            <article v-for="item in aiActionItems" :key="`ai-action-${item.key}`">
              <strong>{{ item.key }}</strong>
            </article>
          </section>
        </section>

        <section class="command-grid">
          <section class="ai-summary-card">
            <div class="panel-heading">
              <h2>AI 事件调查包</h2>
              <span>{{ incidentInvestigation.mode }} / {{ incidentInvestigation.subject || '未选择事件' }}</span>
            </div>
            <p class="ai-summary-lead">{{ incidentInvestigation.summary.summary }}</p>
            <div class="ai-summary-grid">
              <div>
                <span>根因候选</span>
                <ul>
                  <li v-for="item in incidentInvestigation.root_causes.slice(0, 4)" :key="`ai-invest-root-${item}`">{{ item }}</li>
                </ul>
              </div>
              <div>
                <span>证据链</span>
                <ul>
                  <li v-for="item in incidentInvestigation.evidence_chain" :key="`ai-invest-evidence-${item}`">{{ item }}</li>
                </ul>
              </div>
            </div>
          </section>
          <section class="ai-summary-card">
            <div class="panel-heading">
              <h2>调查下一步</h2>
              <span>{{ incidentInvestigation.timeline.length.toLocaleString() }} 条时间线</span>
            </div>
            <div class="ai-summary-grid single">
              <div>
                <span>建议动作</span>
                <ul>
                  <li v-for="item in incidentInvestigation.next_steps" :key="`ai-invest-step-${item}`">{{ item }}</li>
                </ul>
              </div>
            </div>
          </section>
        </section>

        <section class="tables-grid analysis-grid">
          <section class="table-panel">
            <div class="panel-heading">
              <h2>首要事件</h2>
              <span>{{ securityIncidents.length.toLocaleString() }} 条 / {{ rangeLabel }}</span>
            </div>
            <div v-if="securityIncidents.length === 0" class="empty-state">暂无事件</div>
            <table v-else>
              <thead>
                <tr>
                  <th>对象</th>
                  <th>级别</th>
                  <th>摘要</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="incident in securityIncidents.slice(0, 5)" :key="incident.id">
                  <td>{{ incident.subject }}</td>
                  <td><span class="severity-pill" :class="incident.severity">{{ severityText(incident.severity) }}</span></td>
                  <td>{{ incident.summary }}</td>
                  <td><button class="inline-button" type="button" @click="loadIncidentContext(incident); currentView = 'incidents'">上下文</button></td>
                </tr>
              </tbody>
            </table>
          </section>
          <section class="table-panel">
            <div class="panel-heading">
              <h2>重点资产</h2>
              <span>{{ assetRisks.length.toLocaleString() }} 个 / {{ rangeLabel }}</span>
            </div>
            <div v-if="assetRisks.length === 0" class="empty-state">暂无资产风险数据</div>
            <table v-else>
              <thead>
                <tr>
                  <th>资产</th>
                  <th>等级</th>
                  <th>评分</th>
                  <th>主要原因</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="asset in assetRisks.slice(0, 5)" :key="asset.ip">
                  <td>{{ asset.ip }}</td>
                  <td><span class="severity-pill" :class="asset.risk_level">{{ assetRiskLevelText(asset.risk_level) }}</span></td>
                  <td>{{ asset.risk_score }}</td>
                  <td>{{ asset.top_finding || '-' }}</td>
                </tr>
              </tbody>
            </table>
          </section>
        </section>
      </template>

      <template v-else-if="currentView === 'realtime'">
        <section class="command-grid realtime-grid">
          <TrafficHeatmap :points="series" />
          <TrafficCompositionPanel
            :protocols="protocolSummary"
            :ports="portTrendSummary"
            :directions="directionTrendSummary"
            :packet-sizes="topPacketLens"
          />
        </section>

        <section class="main-grid">
          <DashboardChart class="chart-panel" :points="series" />
          <section class="collector-panel">
            <h2>实时窗口指标</h2>
            <div class="kv-list">
              <div><span>当前 PPS</span><strong>{{ pps.toLocaleString() }}</strong></div>
              <div><span>平均包长</span><strong>{{ avgPacketSize }}</strong></div>
              <div><span>刷新周期</span><strong>5 秒</strong></div>
              <div><span>数据状态</span><strong>{{ degraded ? '降级' : '实时' }}</strong></div>
            </div>
          </section>
        </section>
        <section class="table-panel">
          <h2>最近窗口</h2>
          <table>
            <thead>
              <tr>
                <th>时间</th>
                <th>吞吐</th>
                <th>流量</th>
                <th>包数</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="point in series.slice().reverse()" :key="point.ts">
                <td>{{ formatTime(point.ts) }}</td>
                <td>{{ formatRate(point.bytes, 5) }}</td>
                <td>{{ formatBytes(point.bytes) }}</td>
                <td>{{ point.packets.toLocaleString() }}</td>
              </tr>
            </tbody>
          </table>
        </section>
        <section class="tables-grid analysis-grid">
          <TopNTable title="协议趋势汇总" :items="protocolSummary" />
          <section class="table-panel">
            <h2>协议窗口明细</h2>
            <table>
              <thead>
                <tr>
                  <th>时间</th>
                  <th>协议</th>
                  <th>流量</th>
                  <th>包数</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="point in protocolSeries.slice().reverse().slice(0, 12)" :key="`${point.ts}-${point.protocol}`">
                  <td>{{ formatTime(point.ts) }}</td>
                  <td>{{ point.protocol }}</td>
                  <td>{{ formatBytes(point.bytes) }}</td>
                  <td>{{ point.packets.toLocaleString() }}</td>
                </tr>
              </tbody>
            </table>
          </section>
        </section>
      </template>

      <template v-else-if="currentView === 'quality'">
        <section class="toolbar-panel">
          <button class="command-button" type="button" @click="exportDataQuality">导出数据质量</button>
          <div class="toolbar-summary">
            {{ rangeLabel }} / 生成时间 {{ formatTime(dataQuality.generated_at) }} / 窗口间隔 {{ dataQuality.window_interval }} 秒
          </div>
        </section>
        <section class="metrics-grid">
          <article class="metric">
            <Radar :size="22" />
            <div>
              <span>链路诊断</span>
              <strong>{{ dataQualityStatusText(captureDiagnostics.status) }}</strong>
            </div>
          </article>
          <article class="metric">
            <AlertTriangle :size="22" />
            <div>
              <span>严重层</span>
              <strong>{{ captureDiagnostics.summary.critical_layers.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Gauge :size="22" />
            <div>
              <span>警告层</span>
              <strong>{{ captureDiagnostics.summary.warning_layers.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <ClipboardList :size="22" />
            <div>
              <span>检查层</span>
              <strong>{{ captureDiagnostics.summary.layer_count.toLocaleString() }}</strong>
            </div>
          </article>
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="采集链路诊断" eyebrow="Capture Diagnostics" :items="captureDiagnosticItems" unit="count" />
          <section class="table-panel capture-diagnostics-table">
            <div class="panel-heading">
              <h2>分层诊断</h2>
              <span>生成时间 {{ formatTime(captureDiagnostics.generated_at) }}</span>
            </div>
            <table>
              <thead>
                <tr>
                  <th>层级</th>
                  <th>状态</th>
                  <th>评分</th>
                  <th>指标</th>
                  <th>诊断说明</th>
                  <th>建议动作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="row in captureDiagnostics.layers" :key="row.id">
                  <td><strong>{{ row.name }}</strong></td>
                  <td><span class="severity-pill" :class="row.status">{{ dataQualityStatusText(row.status) }}</span></td>
                  <td>{{ row.score.toLocaleString() }}</td>
                  <td>{{ row.metric }}</td>
                  <td>{{ row.detail }}</td>
                  <td>{{ row.recommendation }}</td>
                </tr>
              </tbody>
            </table>
            <div v-if="captureDiagnostics.layers.length === 0" class="empty-state">暂无采集链路诊断数据</div>
          </section>
        </section>
        <section class="metrics-grid">
          <article class="metric">
            <Database :size="22" />
            <div>
              <span>质量状态</span>
              <strong>{{ dataQualityStatusText(dataQuality.status) }}</strong>
            </div>
          </article>
          <article class="metric">
            <History :size="22" />
            <div>
              <span>窗口覆盖率</span>
              <strong>{{ (dataQuality.summary.coverage_ratio * 100).toFixed(1) }}%</strong>
            </div>
          </article>
          <article class="metric">
            <RefreshCw :size="22" />
            <div>
              <span>最新延迟</span>
              <strong>{{ dataQuality.summary.freshness_seconds.toLocaleString() }} 秒</strong>
            </div>
          </article>
          <article class="metric">
            <AlertTriangle :size="22" />
            <div>
              <span>断档数量</span>
              <strong>{{ dataQuality.summary.gap_count.toLocaleString() }}</strong>
            </div>
          </article>
        </section>
        <section class="metrics-grid">
          <article class="metric">
            <RadioTower :size="22" />
            <div>
              <span>采集源 / 网卡</span>
              <strong>{{ dataQuality.summary.source_count.toLocaleString() }} / {{ dataQuality.summary.interface_count.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Activity :size="22" />
            <div>
              <span>采集窗口</span>
              <strong>{{ dataQuality.summary.observed_windows.toLocaleString() }} / {{ dataQuality.summary.expected_windows.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Gauge :size="22" />
            <div>
              <span>最大利用率</span>
              <strong>{{ (dataQuality.summary.max_utilization * 100).toFixed(2) }}%</strong>
            </div>
          </article>
          <article class="metric">
            <Shield :size="22" />
            <div>
              <span>Drops</span>
              <strong>{{ dataQuality.summary.drops.toLocaleString() }}</strong>
            </div>
          </article>
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="采集源覆盖率" eyebrow="Window Coverage" :items="dataQualitySourceItems" unit="count" />
          <HorizontalBarChart title="采集源最新延迟" eyebrow="Freshness Seconds" :items="dataQualityFreshnessItems" unit="count" />
        </section>
        <section class="command-grid">
          <TrafficHeatmap :points="series" />
          <HorizontalBarChart title="采集 Drops 分布" eyebrow="Capture Drops" :items="dataQualityDropItems" unit="count" />
        </section>
        <section class="metrics-grid">
          <article class="metric">
            <Database :size="22" />
            <div>
              <span>接口质量</span>
              <strong>{{ dataQualityStatusText(captureQuality.status) }}</strong>
            </div>
          </article>
          <article class="metric">
            <Activity :size="22" />
            <div>
              <span>RX / TX 包</span>
              <strong>{{ captureQuality.summary.rx_packets.toLocaleString() }} / {{ captureQuality.summary.tx_packets.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <AlertTriangle :size="22" />
            <div>
              <span>接口 Dropped</span>
              <strong>{{ (captureQuality.summary.rx_dropped + captureQuality.summary.tx_dropped).toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Shield :size="22" />
            <div>
              <span>接口 Errors</span>
              <strong>{{ (captureQuality.summary.rx_errors + captureQuality.summary.tx_errors).toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Gauge :size="22" />
            <div>
              <span>用户态队列压力</span>
              <strong>{{ ((captureQuality.summary.queue_pressure || 0) * 100).toFixed(1) }}%</strong>
            </div>
          </article>
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="接口 RX/TX 流量" eyebrow="Interface Traffic" :items="captureQualityTrafficItems" />
          <HorizontalBarChart title="接口 Dropped" eyebrow="Interface Drops" :items="captureQualityDropItems" unit="count" />
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="接口 Errors" eyebrow="Interface Errors" :items="captureQualityErrorItems" unit="count" />
          <HorizontalBarChart title="用户态队列压力" eyebrow="Queue Pressure" :items="captureQualityQueueItems" unit="count" />
          <section class="table-panel report-recommendations">
            <div class="panel-heading">
              <h2>接口质量建议</h2>
              <span>{{ captureQuality.recommendations.length.toLocaleString() }} 条</span>
            </div>
            <article v-for="item in captureQuality.recommendations" :key="`capture-${item.level}-${item.title}`" class="report-recommendation">
              <span class="severity-pill" :class="item.level">{{ severityText(item.level) }}</span>
              <strong>{{ item.title }}</strong>
              <p>{{ item.detail }}</p>
            </article>
          </section>
        </section>
        <section class="tables-grid analysis-grid">
          <section class="table-panel report-recommendations">
            <div class="panel-heading">
              <h2>质量建议</h2>
              <span>{{ dataQuality.recommendations.length.toLocaleString() }} 条</span>
            </div>
            <article v-for="item in dataQuality.recommendations" :key="`${item.level}-${item.title}`" class="report-recommendation">
              <span class="severity-pill" :class="item.level">{{ severityText(item.level) }}</span>
              <strong>{{ item.title }}</strong>
              <p>{{ item.detail }}</p>
            </article>
          </section>
          <section class="table-panel">
            <div class="panel-heading">
              <h2>窗口摘要</h2>
              <span>{{ formatBytes(dataQuality.summary.bytes) }} / {{ dataQuality.summary.packets.toLocaleString() }} 包</span>
            </div>
            <div class="kv-list">
              <div><span>最近窗口</span><strong>{{ formatTime(dataQuality.summary.latest_window_ts) }}</strong></div>
              <div><span>异常采集源</span><strong>{{ dataQuality.summary.stale_sources.toLocaleString() }}</strong></div>
              <div><span>断档数量</span><strong>{{ dataQuality.summary.gap_count.toLocaleString() }}</strong></div>
              <div><span>覆盖率</span><strong>{{ (dataQuality.summary.coverage_ratio * 100).toFixed(1) }}%</strong></div>
            </div>
          </section>
        </section>
        <section class="table-panel wide-key-table capture-quality-table">
          <div class="panel-heading">
            <h2>接口采集质量</h2>
            <span>{{ captureQuality.sources.length.toLocaleString() }} 个接口 / {{ rangeLabel }}</span>
          </div>
          <table>
            <thead>
              <tr>
                <th>采集源</th>
                <th>网卡</th>
                <th>状态</th>
                <th>窗口</th>
                <th>RX 流量</th>
                <th>RX 包</th>
                <th>RX Dropped</th>
                <th>RX Errors</th>
                <th>TX 流量</th>
                <th>TX 包</th>
                <th>TX Dropped</th>
                <th>TX Errors</th>
                <th>Packet 队列</th>
                <th>Window 队列</th>
                <th>队列压力</th>
                <th>最近窗口</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in captureQuality.sources" :key="`capture-${row.source_id}-${row.iface}`">
                <td>{{ row.source_id }}</td>
                <td>{{ row.iface }}</td>
                <td><span class="severity-pill" :class="row.status">{{ dataQualityStatusText(row.status) }}</span></td>
                <td>{{ row.windows.toLocaleString() }}</td>
                <td>{{ formatBytes(row.rx_bytes) }}</td>
                <td>{{ row.rx_packets.toLocaleString() }}</td>
                <td>{{ row.rx_dropped.toLocaleString() }}</td>
                <td>{{ row.rx_errors.toLocaleString() }}</td>
                <td>{{ formatBytes(row.tx_bytes) }}</td>
                <td>{{ row.tx_packets.toLocaleString() }}</td>
                <td>{{ row.tx_dropped.toLocaleString() }}</td>
                <td>{{ row.tx_errors.toLocaleString() }}</td>
                <td>{{ row.packet_queue_len.toLocaleString() }} / {{ row.packet_queue_capacity.toLocaleString() }}</td>
                <td>{{ row.window_queue_len.toLocaleString() }} / {{ row.window_queue_capacity.toLocaleString() }}</td>
                <td>{{ ((row.queue_pressure || 0) * 100).toFixed(1) }}%</td>
                <td>{{ formatTime(row.latest_window_ts) }}</td>
              </tr>
            </tbody>
          </table>
          <div v-if="captureQuality.sources.length === 0" class="empty-state">暂无接口采集质量数据</div>
        </section>
        <section class="table-panel wide-key-table data-quality-table">
          <div class="panel-heading">
            <h2>采集源健康</h2>
            <span>{{ dataQuality.sources.length.toLocaleString() }} 个采集源 / {{ rangeLabel }}</span>
          </div>
          <table>
            <thead>
              <tr>
                <th>采集源</th>
                <th>网卡</th>
                <th>状态</th>
                <th>窗口数</th>
                <th>覆盖率</th>
                <th>最新延迟</th>
                <th>流量</th>
                <th>包数</th>
                <th>Drops</th>
                <th>最近窗口</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in dataQuality.sources" :key="`${row.source_id}-${row.iface}`">
                <td>{{ row.source_id }}</td>
                <td>{{ row.iface }}</td>
                <td><span class="severity-pill" :class="row.status">{{ dataQualityStatusText(row.status) }}</span></td>
                <td>{{ row.windows.toLocaleString() }}</td>
                <td>{{ (row.coverage_ratio * 100).toFixed(1) }}%</td>
                <td>{{ row.freshness_seconds.toLocaleString() }} 秒</td>
                <td>{{ formatBytes(row.bytes) }}</td>
                <td>{{ row.packets.toLocaleString() }}</td>
                <td>{{ row.drops.toLocaleString() }}</td>
                <td>{{ formatTime(row.latest_window_ts) }}</td>
              </tr>
            </tbody>
          </table>
          <div v-if="dataQuality.sources.length === 0" class="empty-state">暂无采集源窗口数据</div>
        </section>
        <section class="table-panel wide-key-table data-gap-table">
          <div class="panel-heading">
            <h2>采集断档</h2>
            <span>{{ dataQuality.gaps.length.toLocaleString() }} 条</span>
          </div>
          <div v-if="dataQuality.gaps.length === 0" class="empty-state">暂无明显采集断档</div>
          <table v-else>
            <thead>
              <tr>
                <th>采集源</th>
                <th>网卡</th>
                <th>开始窗口</th>
                <th>恢复窗口</th>
                <th>断档秒数</th>
                <th>缺失窗口</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in dataQuality.gaps" :key="`${row.source_id}-${row.iface}-${row.start_ts}-${row.end_ts}`">
                <td>{{ row.source_id }}</td>
                <td>{{ row.iface }}</td>
                <td>{{ formatTime(row.start_ts) }}</td>
                <td>{{ formatTime(row.end_ts) }}</td>
                <td>{{ row.duration_seconds.toLocaleString() }}</td>
                <td>{{ row.missing_windows.toLocaleString() }}</td>
              </tr>
            </tbody>
          </table>
        </section>
      </template>

      <template v-else-if="currentView === 'capacity'">
        <section class="toolbar-panel">
          <button class="command-button" type="button" @click="exportCapacityPlanning">导出容量趋势</button>
          <div class="toolbar-summary">
            {{ rangeLabel }} / 生成时间 {{ formatTime(capacityPlanning.generated_at) }} / 标称带宽 {{ capacityPlanning.summary.bandwidth_mbps.toLocaleString() }} Mbps
          </div>
        </section>
        <section class="metrics-grid">
          <article class="metric">
            <Gauge :size="22" />
            <div>
              <span>容量风险</span>
              <strong>{{ capacityRiskText(capacityPlanning.summary.risk_level) }}</strong>
            </div>
          </article>
          <article class="metric">
            <Activity :size="22" />
            <div>
              <span>峰值吞吐</span>
              <strong>{{ capacityPlanning.summary.peak_mbps.toFixed(2) }} Mbps</strong>
            </div>
          </article>
          <article class="metric">
            <Database :size="22" />
            <div>
              <span>P95 吞吐</span>
              <strong>{{ capacityPlanning.summary.p95_mbps.toFixed(2) }} Mbps</strong>
            </div>
          </article>
          <article class="metric">
            <Shield :size="22" />
            <div>
              <span>带宽余量</span>
              <strong>{{ capacityPlanning.summary.headroom_mbps.toFixed(2) }} Mbps</strong>
            </div>
          </article>
        </section>
        <section class="metrics-grid">
          <article class="metric">
            <RadioTower :size="22" />
            <div>
              <span>峰值利用率</span>
              <strong>{{ (capacityPlanning.summary.peak_utilization * 100).toFixed(2) }}%</strong>
            </div>
          </article>
          <article class="metric">
            <History :size="22" />
            <div>
              <span>P95 利用率</span>
              <strong>{{ (capacityPlanning.summary.p95_utilization * 100).toFixed(2) }}%</strong>
            </div>
          </article>
          <article class="metric">
            <RefreshCw :size="22" />
            <div>
              <span>峰值增长</span>
              <strong>{{ capacityPlanning.summary.growth_mbps.toFixed(2) }} Mbps</strong>
            </div>
          </article>
          <article class="metric">
            <AlertTriangle :size="22" />
            <div>
              <span>预计触顶</span>
              <strong>{{ capacityPlanning.summary.saturation_eta_mins > 0 ? `${capacityPlanning.summary.saturation_eta_mins.toFixed(0)} 分钟` : '未增长' }}</strong>
            </div>
          </article>
        </section>
        <section class="command-grid">
          <DashboardChart class="chart-panel" :points="capacityTrendSeries" />
          <HorizontalBarChart title="源 IP 增长排行" eyebrow="Source Growth" :items="capacitySrcGrowthItems" />
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="端口增长排行" eyebrow="Port Growth" :items="capacityPortGrowthItems" />
          <HorizontalBarChart title="服务增长排行" eyebrow="Service Growth" :items="capacityServiceGrowthItems" />
        </section>
        <section class="tables-grid analysis-grid">
          <section class="table-panel report-recommendations">
            <div class="panel-heading">
              <h2>容量建议</h2>
              <span>{{ capacityPlanning.recommendations.length.toLocaleString() }} 条</span>
            </div>
            <article v-for="item in capacityPlanning.recommendations" :key="`${item.level}-${item.title}`" class="report-recommendation">
              <span class="severity-pill" :class="item.level">{{ severityText(item.level) }}</span>
              <strong>{{ item.title }}</strong>
              <p>{{ item.detail }}</p>
            </article>
          </section>
          <section class="table-panel">
            <div class="panel-heading">
              <h2>容量摘要</h2>
              <span>{{ capacityPlanning.summary.bandwidth_mbps.toLocaleString() }} Mbps</span>
            </div>
            <div class="kv-list">
              <div><span>平均吞吐</span><strong>{{ capacityPlanning.summary.avg_mbps.toFixed(2) }} Mbps</strong></div>
              <div><span>上一峰值</span><strong>{{ capacityPlanning.summary.previous_peak_mbps.toFixed(2) }} Mbps</strong></div>
              <div><span>增长率</span><strong>{{ (capacityPlanning.summary.growth_ratio * 100).toFixed(1) }}%</strong></div>
              <div><span>余量比例</span><strong>{{ (capacityPlanning.summary.headroom_ratio * 100).toFixed(1) }}%</strong></div>
            </div>
          </section>
        </section>
        <section class="table-panel wide-key-table capacity-growth-table">
          <div class="panel-heading">
            <h2>容量增长对象</h2>
            <span>{{ rangeLabel }} / 当前周期对比上一周期</span>
          </div>
          <table>
            <thead>
              <tr>
                <th>类型</th>
                <th>对象</th>
                <th>当前流量</th>
                <th>上一周期</th>
                <th>增量</th>
                <th>变化率</th>
                <th>当前包数</th>
                <th>包增量</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in capacityPlanning.top_src_growth" :key="`src-${row.key}`">
                <td>源 IP</td>
                <td>{{ row.key }}</td>
                <td>{{ formatBytes(row.current_bytes) }}</td>
                <td>{{ formatBytes(row.previous_bytes) }}</td>
                <td>{{ formatBytes(Math.abs(row.delta_bytes)) }}</td>
                <td>{{ formatChangeRatio(row.change_ratio) }}</td>
                <td>{{ row.current_packets.toLocaleString() }}</td>
                <td>{{ Math.abs(row.delta_packets).toLocaleString() }}</td>
              </tr>
              <tr v-for="row in capacityPlanning.top_port_growth" :key="`port-${row.key}`">
                <td>目的端口</td>
                <td>{{ row.key }}</td>
                <td>{{ formatBytes(row.current_bytes) }}</td>
                <td>{{ formatBytes(row.previous_bytes) }}</td>
                <td>{{ formatBytes(Math.abs(row.delta_bytes)) }}</td>
                <td>{{ formatChangeRatio(row.change_ratio) }}</td>
                <td>{{ row.current_packets.toLocaleString() }}</td>
                <td>{{ Math.abs(row.delta_packets).toLocaleString() }}</td>
              </tr>
              <tr v-for="row in capacityPlanning.top_service_growth" :key="`service-${row.key}`">
                <td>应用服务</td>
                <td>{{ row.key }}</td>
                <td>{{ formatBytes(row.current_bytes) }}</td>
                <td>{{ formatBytes(row.previous_bytes) }}</td>
                <td>{{ formatBytes(Math.abs(row.delta_bytes)) }}</td>
                <td>{{ formatChangeRatio(row.change_ratio) }}</td>
                <td>{{ row.current_packets.toLocaleString() }}</td>
                <td>{{ Math.abs(row.delta_packets).toLocaleString() }}</td>
              </tr>
            </tbody>
          </table>
        </section>
      </template>

      <template v-else-if="currentView === 'traffic'">
        <section class="metrics-grid">
          <article class="metric">
            <Gauge :size="22" />
            <div>
              <span>平均吞吐</span>
              <strong>{{ trafficAnalysis.baseline.avg_mbps.toFixed(2) }} Mbps</strong>
            </div>
          </article>
          <article class="metric">
            <Activity :size="22" />
            <div>
              <span>P95 吞吐</span>
              <strong>{{ trafficAnalysis.baseline.p95_mbps.toFixed(2) }} Mbps</strong>
            </div>
          </article>
          <article class="metric">
            <Database :size="22" />
            <div>
              <span>峰值吞吐</span>
              <strong>{{ trafficAnalysis.baseline.peak_mbps.toFixed(2) }} Mbps</strong>
            </div>
          </article>
          <article class="metric">
            <RadioTower :size="22" />
            <div>
              <span>突发倍数</span>
              <strong>{{ trafficAnalysis.baseline.burst_ratio.toFixed(2) }}x</strong>
            </div>
          </article>
        </section>
        <section class="command-grid">
          <TrafficHeatmap :points="series" />
          <HorizontalBarChart title="变化对象排行" eyebrow="Change Ranking" :items="trafficChangeItems" />
        </section>
        <section class="toolbar-panel profile-toolbar">
          <label>
            <span>下钻维度</span>
            <select v-model="trendDimension">
              <option v-for="option in trendDimensionOptions" :key="option.value" :value="option.value">{{ option.label }}</option>
            </select>
          </label>
          <label v-if="trendDimension === 'ip'">
            <span>IP 方向</span>
            <select v-model="trendDirection">
              <option value="src">源 IP</option>
              <option value="dst">目的 IP</option>
            </select>
          </label>
          <label class="filter-field">
            <span>对象值</span>
            <input v-model="trendKey" placeholder="留空查看 Top 对象，或输入 HTTPS / 443 / BE / 10.2.0.12" @keyup.enter="loadDimensionTrend" />
          </label>
          <button type="button" @click="loadDimensionTrend">查看趋势</button>
        </section>
        <DimensionTrendChart :title="trendTitle" :points="dimensionTrend" />
        <section class="metrics-grid relation-metrics">
          <article class="metric">
            <Route :size="22" />
            <div>
              <span>关联对象</span>
              <strong>{{ relationTitle }}</strong>
            </div>
          </article>
          <article class="metric">
            <Activity :size="22" />
            <div>
              <span>对象流量</span>
              <strong>{{ formatBytes(objectRelations.summary.bytes) }}</strong>
            </div>
          </article>
          <article class="metric">
            <ListOrdered :size="22" />
            <div>
              <span>对象包数</span>
              <strong>{{ objectRelations.summary.packets.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Shield :size="22" />
            <div>
              <span>风险线索</span>
              <strong>{{ objectRelations.insights.length.toLocaleString() }}</strong>
            </div>
          </article>
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="关联 IP" eyebrow="Related IP" :items="objectRelations.related_ips" />
          <HorizontalBarChart title="关联端口" eyebrow="Related Port" :items="objectRelations.related_ports" />
        </section>
        <section class="tables-grid analysis-grid">
          <TopNTable title="关联服务" :items="objectRelations.related_services" />
          <TopNTable title="关联会话" :items="objectRelations.related_flows" />
          <TopNTable title="关联风险线索" :items="relationInsightItems" />
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="应用服务排行" eyebrow="Service Ranking" :items="topServices" />
          <HorizontalBarChart title="服务风险流量" eyebrow="Service Risk" :items="topServiceRisks" />
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="VLAN 流量分布" eyebrow="Layer 2 Segment" :items="topVLANs" />
          <HorizontalBarChart title="DSCP/QoS 分布" eyebrow="QoS Marking" :items="topDSCP" />
        </section>
        <section class="main-grid">
          <section class="collector-panel">
            <h2>基线摘要</h2>
            <div class="kv-list">
              <div><span>观察窗口</span><strong>{{ trafficAnalysis.baseline.windows.toLocaleString() }}</strong></div>
              <div><span>平均窗口流量</span><strong>{{ formatBytes(trafficAnalysis.baseline.avg_bytes) }}</strong></div>
              <div><span>峰值窗口流量</span><strong>{{ formatBytes(trafficAnalysis.baseline.peak_bytes) }}</strong></div>
              <div><span>P95 窗口流量</span><strong>{{ formatBytes(trafficAnalysis.baseline.p95_bytes) }}</strong></div>
              <div><span>峰值包数</span><strong>{{ trafficAnalysis.baseline.peak_packets.toLocaleString() }}</strong></div>
              <div><span>峰值利用率</span><strong>{{ (trafficAnalysis.baseline.peak_utilization * 100).toFixed(2) }}%</strong></div>
            </div>
          </section>
          <section class="collector-panel">
            <h2>结构摘要</h2>
            <div class="kv-list">
              <div><span>主导方向</span><strong>{{ dominantDirection?.key ?? '-' }}</strong></div>
              <div><span>方向流量</span><strong>{{ dominantDirection ? formatBytes(dominantDirection.bytes) : '0 B' }}</strong></div>
              <div><span>主导协议</span><strong>{{ dominantProtocol?.key ?? '-' }}</strong></div>
              <div><span>协议流量</span><strong>{{ dominantProtocol ? formatBytes(dominantProtocol.bytes) : '0 B' }}</strong></div>
              <div><span>包长样本流量</span><strong>{{ formatBytes(packetSizeTotal) }}</strong></div>
              <div><span>端口样本流量</span><strong>{{ formatBytes(portMixTotal) }}</strong></div>
            </div>
          </section>
        </section>
        <section class="tables-grid analysis-grid">
          <TopNTable title="方向分布" :items="trafficAnalysis.directions" />
          <TopNTable title="协议占比" :items="trafficAnalysis.protocol_mix" />
          <TopNTable title="应用服务" :items="topServices" />
          <TopNTable title="服务类别" :items="topServiceCategories" />
          <TopNTable title="VLAN 分布" :items="topVLANs" />
          <TopNTable title="DSCP/QoS" :items="topDSCP" />
          <TopNTable title="包长分布" :items="trafficAnalysis.packet_sizes" />
          <TopNTable title="端口服务混合" :items="trafficAnalysis.port_mix" />
        </section>
        <section class="tables-grid analysis-grid">
          <TopNTable title="方向趋势汇总" :items="directionTrendSummary" />
          <TopNTable title="端口趋势汇总" :items="portTrendSummary" />
        </section>
        <section class="tables-grid analysis-grid">
          <section class="table-panel">
            <h2>方向趋势明细</h2>
            <table>
              <thead>
                <tr>
                  <th>时间</th>
                  <th>方向</th>
                  <th>流量</th>
                  <th>包数</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="point in directionSeries.slice().reverse().slice(0, 16)" :key="`${point.ts}-${point.direction}`">
                  <td>{{ formatTime(point.ts) }}</td>
                  <td>{{ point.direction }}</td>
                  <td>{{ formatBytes(point.bytes) }}</td>
                  <td>{{ point.packets.toLocaleString() }}</td>
                </tr>
              </tbody>
            </table>
          </section>
          <section class="table-panel">
            <h2>端口趋势明细</h2>
            <table>
              <thead>
                <tr>
                  <th>时间</th>
                  <th>端口</th>
                  <th>流量</th>
                  <th>包数</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="point in portSeries.slice().reverse().slice(0, 16)" :key="`${point.ts}-${point.port}`">
                  <td>{{ formatTime(point.ts) }}</td>
                  <td>{{ point.port }}</td>
                  <td>{{ formatBytes(point.bytes) }}</td>
                  <td>{{ point.packets.toLocaleString() }}</td>
                </tr>
              </tbody>
            </table>
          </section>
        </section>
        <section class="table-panel wide-key-table change-table">
          <h2>变化检测</h2>
          <table>
            <thead>
              <tr>
                <th>对象</th>
                <th>维度</th>
                <th>当前流量</th>
                <th>上一段</th>
                <th>增量</th>
                <th>变化率</th>
                <th>包数增量</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in trafficChanges" :key="`${row.dimension}-${row.key}`">
                <td>{{ row.key }}</td>
                <td>{{ changeDimensionText(row.dimension) }}</td>
                <td>{{ formatBytes(row.current_bytes) }}</td>
                <td>{{ formatBytes(row.previous_bytes) }}</td>
                <td :class="{ positive: row.delta_bytes > 0, negative: row.delta_bytes < 0 }">{{ formatBytes(Math.abs(row.delta_bytes)) }}</td>
                <td :class="{ positive: row.change_ratio > 0, negative: row.change_ratio < 0 }">{{ formatChangeRatio(row.change_ratio) }}</td>
                <td :class="{ positive: row.delta_packets > 0, negative: row.delta_packets < 0 }">{{ row.delta_packets.toLocaleString() }}</td>
              </tr>
            </tbody>
          </table>
        </section>
      </template>

      <template v-else-if="currentView === 'analysis'">
        <section class="command-grid">
          <FlowMatrixChart :rows="matrixRows" />
          <HorizontalBarChart title="目的端口流量" eyebrow="Port Ranking" :items="topPorts" />
        </section>
        <section class="tables-grid analysis-grid">
          <TopNTable title="主机对排行" :items="topPairs" />
          <TopNTable title="会话排行" :items="topFlows" />
          <TopNTable title="目的端口排行" :items="topPorts" />
          <TopNTable title="协议排行" :items="topProtocols" />
        </section>
      </template>

      <template v-else-if="currentView === 'baseline'">
        <section class="metrics-grid">
          <article class="metric">
            <Radar :size="22" />
            <div>
              <span>基线窗口</span>
              <strong>{{ behaviorBaseline.window_count.toLocaleString() }} 组</strong>
            </div>
          </article>
          <article class="metric">
            <AlertTriangle :size="22" />
            <div>
              <span>严重偏离</span>
              <strong>{{ behaviorBaseline.summary.critical_count.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Activity :size="22" />
            <div>
              <span>新增对象</span>
              <strong>{{ behaviorBaseline.summary.new_count.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Database :size="22" />
            <div>
              <span>链路当前</span>
              <strong>{{ formatBytes(behaviorBaseline.summary.link_current_bytes) }}</strong>
            </div>
          </article>
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="基线偏离排行" eyebrow="Baseline Deviation" :items="baselineDeviationItems" />
          <HorizontalBarChart title="偏离级别分布" eyebrow="Severity" :items="baselineSeverityItems" unit="count" />
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="行为状态分布" eyebrow="Behavior State" :items="baselineStatusItems" unit="count" />
          <section class="table-panel report-recommendations">
            <div class="panel-heading">
              <h2>基线建议</h2>
              <span>{{ behaviorBaseline.recommendations.length.toLocaleString() }} 条</span>
            </div>
            <article v-for="item in behaviorBaseline.recommendations" :key="`${item.level}-${item.title}`" class="report-recommendation">
              <span class="severity-pill" :class="item.level">{{ severityText(item.level) }}</span>
              <strong>{{ item.title }}</strong>
              <p>{{ item.detail }}</p>
            </article>
          </section>
        </section>
        <section class="main-grid">
          <section class="collector-panel">
            <h2>链路行为基线</h2>
            <div class="kv-list">
              <div><span>状态</span><strong>{{ baselineStatusText(behaviorBaseline.link.status) }}</strong></div>
              <div><span>当前流量</span><strong>{{ formatBytes(behaviorBaseline.link.current_bytes) }}</strong></div>
              <div><span>历史均值</span><strong>{{ formatBytes(behaviorBaseline.link.baseline_bytes) }}</strong></div>
              <div><span>历史 P95</span><strong>{{ formatBytes(behaviorBaseline.link.p95_bytes) }}</strong></div>
              <div><span>偏离倍数</span><strong>{{ behaviorBaseline.link.deviation_ratio.toFixed(2) }}x</strong></div>
              <div><span>样本数</span><strong>{{ behaviorBaseline.link.samples.toLocaleString() }}</strong></div>
            </div>
          </section>
          <section class="collector-panel">
            <h2>最高偏离对象</h2>
            <div class="kv-list">
              <div><span>维度</span><strong>{{ behaviorBaseline.summary.top_dimension || '-' }}</strong></div>
              <div><span>对象</span><strong>{{ behaviorBaseline.summary.top_key || '-' }}</strong></div>
              <div><span>偏离倍数</span><strong>{{ behaviorBaseline.summary.top_deviation.toFixed(2) }}x</strong></div>
              <div><span>警告对象</span><strong>{{ behaviorBaseline.summary.warning_count.toLocaleString() }}</strong></div>
              <div><span>学习样本</span><strong>{{ behaviorBaseline.summary.learning_count.toLocaleString() }}</strong></div>
              <div><span>基线跨度</span><strong>{{ behaviorBaseline.baseline_minutes.toLocaleString() }} 分钟</strong></div>
            </div>
          </section>
        </section>
        <section class="table-panel wide-key-table anomaly-table">
          <div class="panel-heading">
            <h2>行为基线明细</h2>
            <span>{{ rangeLabel }} / 历史 {{ behaviorBaseline.baseline_minutes.toLocaleString() }} 分钟</span>
          </div>
          <div v-if="behaviorBaseline.deviations.length === 0" class="empty-state">暂无行为基线数据</div>
          <table v-else>
            <thead>
              <tr>
                <th>对象</th>
                <th>维度</th>
                <th>状态</th>
                <th>级别</th>
                <th>当前流量</th>
                <th>历史均值</th>
                <th>P95</th>
                <th>偏离</th>
                <th>样本</th>
                <th>解释</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in behaviorBaseline.deviations" :key="`${row.dimension}-${row.key}`">
                <td>{{ row.key }}</td>
                <td>{{ row.dimension_title }}</td>
                <td>{{ baselineStatusText(row.status) }}</td>
                <td><span class="severity-pill" :class="row.severity">{{ severityText(row.severity) }}</span></td>
                <td>{{ formatBytes(row.current_bytes) }}</td>
                <td>{{ formatBytes(row.baseline_bytes) }}</td>
                <td>{{ formatBytes(row.p95_bytes) }}</td>
                <td>{{ row.deviation_ratio.toFixed(2) }}x</td>
                <td>{{ row.samples.toLocaleString() }}</td>
                <td>{{ row.summary }}</td>
              </tr>
            </tbody>
          </table>
        </section>
      </template>

      <template v-else-if="currentView === 'anomalies'">
        <section class="metrics-grid">
          <article class="metric">
            <AlertTriangle :size="22" />
            <div>
              <span>严重异常</span>
              <strong>{{ criticalAnomalyCount.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Activity :size="22" />
            <div>
              <span>异常对象</span>
              <strong>{{ trafficAnomalies.length.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Database :size="22" />
            <div>
              <span>最大增量</span>
              <strong>{{ anomalyDeltaItems[0] ? formatBytes(anomalyDeltaItems[0].bytes) : '0 B' }}</strong>
            </div>
          </article>
          <article class="metric">
            <History :size="22" />
            <div>
              <span>对比周期</span>
              <strong>{{ rangeLabel }} / 上一周期</strong>
            </div>
          </article>
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="异常增量排行" eyebrow="Anomaly Delta" :items="anomalyDeltaItems" />
          <HorizontalBarChart title="异常类型分布" eyebrow="Anomaly Type" :items="anomalyKindItems" />
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="异常级别分布" eyebrow="Severity" :items="anomalySeverityItems" unit="count" />
          <HorizontalBarChart title="变化对象排行" eyebrow="Change Ranking" :items="trafficChangeItems" />
        </section>
        <section class="table-panel wide-key-table anomaly-table">
          <h2>异常波动明细</h2>
          <div v-if="trafficAnomalies.length === 0" class="empty-state">暂无异常波动</div>
          <table v-else>
            <thead>
              <tr>
                <th>对象</th>
                <th>类型</th>
                <th>级别</th>
                <th>摘要</th>
                <th>当前流量</th>
                <th>基线流量</th>
                <th>增量</th>
                <th>变化率</th>
                <th>评分</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in trafficAnomalies" :key="`${row.kind}-${row.dimension}-${row.key}`">
                <td>{{ row.key }}</td>
                <td>{{ anomalyKindText(row.kind) }} / {{ changeDimensionText(row.dimension) }}</td>
                <td><span class="severity-pill" :class="row.severity">{{ severityText(row.severity) }}</span></td>
                <td>{{ row.summary }}</td>
                <td>{{ formatBytes(row.current_bytes) }}</td>
                <td>{{ formatBytes(row.baseline_bytes) }}</td>
                <td>{{ formatBytes(Math.abs(row.delta_bytes)) }}</td>
                <td>{{ formatChangeRatio(row.change_ratio) }}</td>
                <td>{{ row.score }}</td>
              </tr>
            </tbody>
          </table>
        </section>
      </template>

      <template v-else-if="currentView === 'service-analytics'">
        <section class="toolbar-panel">
          <button class="command-button" type="button" @click="exportServiceAnalytics">导出应用分析</button>
          <div class="toolbar-summary">
            {{ rangeLabel }} / 生成时间 {{ formatTime(serviceAnalytics.generated_at) }} / {{ formatBytes(serviceAnalytics.summary.total_bytes) }}
          </div>
        </section>
        <section class="metrics-grid">
          <article class="metric">
            <ServerCog :size="22" />
            <div>
              <span>识别服务</span>
              <strong>{{ serviceAnalytics.summary.service_count.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Database :size="22" />
            <div>
              <span>服务类别</span>
              <strong>{{ serviceAnalytics.summary.category_count.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <AlertTriangle :size="22" />
            <div>
              <span>高风险服务</span>
              <strong>{{ serviceAnalytics.summary.high_risk_services.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Activity :size="22" />
            <div>
              <span>主导服务</span>
              <strong>{{ serviceAnalytics.summary.top_service }}</strong>
            </div>
          </article>
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="应用服务排行" eyebrow="Service Ranking" :items="serviceAnalytics.services" />
          <HorizontalBarChart title="服务增长排行" eyebrow="Service Growth" :items="serviceAnalyticsGrowthItems" />
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="服务类别分布" eyebrow="Category Mix" :items="serviceAnalytics.categories" />
          <HorizontalBarChart title="服务风险分布" eyebrow="Risk Mix" :items="serviceAnalytics.risks" />
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="服务端口排行" eyebrow="Service Port" :items="serviceAnalyticsPortItems" />
          <HorizontalBarChart title="高风险服务" eyebrow="High Risk" :items="serviceAnalyticsHighRiskItems" />
        </section>
        <section class="table-panel wide-key-table service-analytics-table">
          <div class="panel-heading">
            <h2>应用服务详情</h2>
            <span>{{ serviceAnalytics.details.length.toLocaleString() }} 个服务 / {{ rangeLabel }}</span>
          </div>
          <div v-if="serviceAnalytics.details.length === 0" class="empty-state">暂无应用服务数据</div>
          <table v-else>
            <thead>
              <tr>
                <th>服务</th>
                <th>类别/风险</th>
                <th>客户端</th>
                <th>服务端</th>
                <th>会话</th>
                <th>主端口</th>
                <th>流量</th>
                <th>包数</th>
                <th>最近出现</th>
                <th>样例会话</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in serviceAnalytics.details" :key="row.service">
                <td><strong>{{ row.service }}</strong></td>
                <td>
                  {{ row.category }}
                  <span class="severity-pill" :class="row.risk">{{ serviceRiskText(row.risk) }}</span>
                </td>
                <td>{{ row.client_count.toLocaleString() }}</td>
                <td>{{ row.server_count.toLocaleString() }}</td>
                <td>{{ row.session_count.toLocaleString() }}</td>
                <td>{{ row.top_port }}</td>
                <td>{{ formatBytes(row.bytes) }}</td>
                <td>{{ row.packets.toLocaleString() }}</td>
                <td>{{ formatTime(row.last_seen) }}</td>
                <td>{{ row.sample_flow }}</td>
                <td class="action-cell">
                  <button class="inline-button" type="button" @click="openServiceTrend(row.service)">趋势</button>
                  <button class="inline-button" type="button" @click="openServicePort(row.top_port.split('/')[0])">端口</button>
                  <button class="inline-button" type="button" @click="searchServiceFlow(row.sample_flow, row.service)">检索</button>
                </td>
              </tr>
            </tbody>
          </table>
        </section>
        <section class="table-panel wide-key-table service-port-table">
          <div class="panel-heading">
            <h2>服务端口明细</h2>
            <span>{{ serviceAnalytics.ports.length.toLocaleString() }} 个端口</span>
          </div>
          <table>
            <thead>
              <tr>
                <th>服务</th>
                <th>端口</th>
                <th>类别</th>
                <th>风险</th>
                <th>流量</th>
                <th>包数</th>
                <th>最近出现</th>
                <th>样例会话</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in serviceAnalytics.ports" :key="`${row.service}-${row.port}-${row.protocol}`">
                <td>{{ row.service }}</td>
                <td>{{ row.port }} / {{ row.protocol }}</td>
                <td>{{ row.category }}</td>
                <td><span class="severity-pill" :class="row.risk">{{ serviceRiskText(row.risk) }}</span></td>
                <td>{{ formatBytes(row.bytes) }}</td>
                <td>{{ row.packets.toLocaleString() }}</td>
                <td>{{ formatTime(row.last_seen) }}</td>
                <td>{{ row.sample_flow }}</td>
              </tr>
            </tbody>
          </table>
        </section>
      </template>

      <template v-else-if="currentView === 'topology'">
        <section class="metrics-grid">
          <article class="metric">
            <Database :size="22" />
            <div>
              <span>拓扑链路流量</span>
              <strong>{{ formatBytes(topologyTotalBytes) }}</strong>
            </div>
          </article>
          <article class="metric">
            <Activity :size="22" />
            <div>
              <span>节点数</span>
              <strong>{{ topologyNodeCount.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Gauge :size="22" />
            <div>
              <span>最重链路</span>
              <strong>{{ topTopologyLink ? formatBytes(topTopologyLink.bytes) : '0 B' }}</strong>
            </div>
          </article>
          <article class="metric">
            <RadioTower :size="22" />
            <div>
              <span>链路数</span>
              <strong>{{ matrixRows.length.toLocaleString() }}</strong>
            </div>
          </article>
        </section>
        <section class="command-grid">
          <LiveFlowMap :nodes="serviceMap.nodes" :links="matrixRows" />
          <FlowMatrixChart :rows="matrixRows" />
        </section>
        <section class="tables-grid analysis-grid">
          <section class="table-panel">
            <h2>拓扑链路</h2>
            <table>
              <thead>
                <tr>
                  <th>源</th>
                  <th>目的</th>
                  <th>流量</th>
                  <th>包数</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="row in matrixRows" :key="`${row.src}-${row.dst}`">
                  <td>{{ row.src }}</td>
                  <td>{{ row.dst }}</td>
                  <td>{{ formatBytes(row.bytes) }}</td>
                  <td>{{ row.packets.toLocaleString() }}</td>
                </tr>
              </tbody>
            </table>
          </section>
          <section class="table-panel">
            <h2>拓扑节点</h2>
            <table>
              <thead>
                <tr>
                  <th>节点</th>
                  <th>关联流量</th>
                  <th>关联包数</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="node in serviceMap.nodes" :key="node.ip">
                  <td>{{ node.ip }}</td>
                  <td>{{ formatBytes(node.bytes) }}</td>
                  <td>{{ node.packets.toLocaleString() }}</td>
                </tr>
              </tbody>
            </table>
          </section>
        </section>
      </template>

      <template v-else-if="currentView === 'external'">
        <section class="metrics-grid">
          <article class="metric">
            <RadioTower :size="22" />
            <div>
              <span>公网对端</span>
              <strong>{{ externalPublicCount.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Database :size="22" />
            <div>
              <span>内部资产</span>
              <strong>{{ externalInternalCount.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <AlertTriangle :size="22" />
            <div>
              <span>入站对象</span>
              <strong>{{ externalInboundCount.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Activity :size="22" />
            <div>
              <span>公网流量</span>
              <strong>{{ formatBytes(externalTotalBytes) }}</strong>
            </div>
          </article>
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="公网对端排行" eyebrow="Public Peer" :items="externalPublicItems" />
          <HorizontalBarChart title="访问方向分布" eyebrow="Direction" :items="externalDirectionItems" />
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="公网服务分布" eyebrow="Service" :items="externalServiceItems" />
          <HorizontalBarChart title="公网风险分布" eyebrow="Risk" :items="externalRiskItems" />
        </section>
        <section class="toolbar-panel">
          <button class="command-button" type="button" @click="exportExternalAccess">导出公网访问</button>
          <div class="toolbar-summary">
            {{ rangeLabel }} / {{ externalAccess.length.toLocaleString() }} 个访问对象 / {{ formatBytes(externalTotalBytes) }}
          </div>
        </section>
        <section class="table-panel wide-key-table external-table">
          <h2>公网访问明细</h2>
          <div v-if="externalAccess.length === 0" class="empty-state">暂无公网访问数据</div>
          <table v-else>
            <thead>
              <tr>
                <th>公网对端</th>
                <th>内部资产</th>
                <th>方向</th>
                <th>服务</th>
                <th>风险</th>
                <th>会话数</th>
                <th>流量</th>
                <th>包数</th>
                <th>最近出现</th>
                <th>样例会话</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in externalAccess" :key="`${row.public_ip}-${row.internal_ip}-${row.port}-${row.direction}`">
                <td>{{ row.public_ip }}</td>
                <td>{{ row.internal_ip }}</td>
                <td>{{ row.direction }}</td>
                <td>
                  <strong>{{ row.service }}</strong>
                  <span class="cell-subtle">{{ row.port }} / {{ row.protocol }} / {{ row.category }}</span>
                </td>
                <td><span class="severity-pill" :class="row.risk">{{ serviceRiskText(row.risk) }}</span></td>
                <td>{{ row.session_count.toLocaleString() }}</td>
                <td>{{ formatBytes(row.bytes) }}</td>
                <td>{{ row.packets.toLocaleString() }}</td>
                <td>{{ formatTime(row.last_seen) }}</td>
                <td>{{ row.sample_flow }}</td>
                <td class="action-cell">
                  <button class="inline-button" type="button" @click="openExternalInternal(row)">资产</button>
                  <button class="inline-button" type="button" @click="openExternalPort(row)">端口</button>
                  <button class="inline-button" type="button" @click="searchExternalFlow(row)">检索</button>
                </td>
              </tr>
            </tbody>
          </table>
        </section>
      </template>

      <template v-else-if="currentView === 'exposure'">
        <section class="metrics-grid">
          <article class="metric">
            <Database :size="22" />
            <div>
              <span>暴露服务</span>
              <strong>{{ exposedServiceCount.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <AlertTriangle :size="22" />
            <div>
              <span>高风险服务</span>
              <strong>{{ highRiskServiceCount.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Gauge :size="22" />
            <div>
              <span>待识别端口</span>
              <strong>{{ unknownServiceCount.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <RadioTower :size="22" />
            <div>
              <span>服务流量</span>
              <strong>{{ formatBytes(exposureTotalBytes) }}</strong>
            </div>
          </article>
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="风险级别流量" eyebrow="Risk Mix" :items="exposureRiskItems" />
          <HorizontalBarChart title="服务类别流量" eyebrow="Service Category" :items="exposureCategoryItems" />
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="识别服务排行" eyebrow="Recognized Service" :items="topServices" />
          <HorizontalBarChart title="服务风险排行" eyebrow="Recognized Risk" :items="topServiceRisks" />
        </section>
        <section class="toolbar-panel exposure-toolbar">
          <label class="filter-field">
            <span>服务搜索</span>
            <input v-model="exposureSearch" placeholder="搜索 IP、端口、服务、类别或会话" />
          </label>
          <label>
            <span>风险级别</span>
            <select v-model="exposureRiskFilter">
              <option v-for="option in exposureRiskOptions" :key="option.value" :value="option.value">{{ option.label }}</option>
            </select>
          </label>
          <label>
            <span>服务类别</span>
            <select v-model="exposureCategoryFilter">
              <option v-for="option in exposureCategoryOptions" :key="option.value" :value="option.value">{{ option.label }}</option>
            </select>
          </label>
          <button type="button" @click="resetExposureFilters">重置</button>
          <button class="command-button" type="button" @click="exportServiceExposure">导出结果</button>
          <div class="toolbar-summary">
            匹配 {{ exposureFilteredCount.toLocaleString() }} 项 / {{ formatBytes(exposureFilteredBytes) }}
          </div>
        </section>
        <section class="table-panel wide-key-table exposure-table">
          <h2>服务暴露面</h2>
          <table>
            <thead>
              <tr>
                <th>服务对象</th>
                <th>服务</th>
                <th>类别</th>
                <th>风险</th>
                <th>方向</th>
                <th>可信度</th>
                <th>客户端数</th>
                <th>流量</th>
                <th>包数</th>
                <th>样例会话</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in filteredServiceExposure" :key="`${row.ip}-${row.port}-${row.protocol}`">
                <td>{{ exposureObject(row) }}</td>
                <td>{{ row.service }}</td>
                <td>{{ row.category }}</td>
                <td>
                  <span class="severity-pill" :class="row.risk">{{ serviceRiskText(row.risk) }}</span>
                </td>
                <td>{{ row.direction || '-' }}</td>
                <td>{{ row.confidence || '-' }}</td>
                <td>{{ row.client_count.toLocaleString() }}</td>
                <td>{{ formatBytes(row.bytes) }}</td>
                <td>{{ row.packets.toLocaleString() }}</td>
                <td>{{ row.sample_flow }}</td>
                <td>
                  <div class="row-actions">
                    <button class="inline-button" type="button" @click="openExposureIP(row)">IP</button>
                    <button class="inline-button" type="button" @click="openExposurePort(row)">端口</button>
                    <button class="inline-button" type="button" @click="searchExposureFlow(row)">检索</button>
                    <button
                      class="inline-button"
                      type="button"
                      :disabled="handlingAlert || isExposureSilenced(row) || !canWrite"
                      @click="silenceSubject(exposureSubject(row))"
                    >
                      {{ isExposureSilenced(row) ? '已忽略' : '忽略端口' }}
                    </button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
          <div v-if="!filteredServiceExposure.length" class="empty-state">暂无匹配的服务暴露数据</div>
        </section>
      </template>

      <template v-else-if="currentView === 'assets'">
        <section class="metrics-grid">
          <article class="metric">
            <Database :size="22" />
            <div>
              <span>资产总流量</span>
              <strong>{{ formatBytes(assetTotalBytes) }}</strong>
            </div>
          </article>
          <article class="metric">
            <Activity :size="22" />
            <div>
              <span>活跃资产</span>
              <strong>{{ activeAssetCount.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Gauge :size="22" />
            <div>
              <span>已建档资产</span>
              <strong>{{ annotatedAssetCount.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <RadioTower :size="22" />
            <div>
              <span>观察范围</span>
              <strong>{{ rangeLabel }}</strong>
            </div>
          </article>
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="资产角色流量" eyebrow="Asset Role" :items="assetRoleItems" />
          <HorizontalBarChart title="重要性流量" eyebrow="Criticality" :items="assetCriticalityItems" />
        </section>
        <section v-if="assetEditor" class="table-panel asset-editor">
          <div class="panel-heading">
            <h2>资产台账编辑</h2>
            <span>{{ assetEditor.ip }}</span>
          </div>
          <div class="asset-editor-grid">
            <label>
              <span>资产名称</span>
              <input v-model="assetEditor.name" placeholder="例如 Web 控制台" />
            </label>
            <label>
              <span>负责人</span>
              <input v-model="assetEditor.owner" placeholder="负责人或团队" />
            </label>
            <label>
              <span>业务系统</span>
              <input v-model="assetEditor.business" placeholder="业务名称" />
            </label>
            <label>
              <span>环境</span>
              <select v-model="assetEditor.environment">
                <option value="生产">生产</option>
                <option value="测试">测试</option>
                <option value="办公">办公</option>
                <option value="未分类">未分类</option>
              </select>
            </label>
            <label>
              <span>重要性</span>
              <select v-model="assetEditor.criticality">
                <option value="critical">核心</option>
                <option value="high">高</option>
                <option value="normal">普通</option>
                <option value="low">低</option>
              </select>
            </label>
            <label>
              <span>标签</span>
              <input v-model="assetTagsText" placeholder="逗号分隔，例如 web, 公网, 核心" />
            </label>
            <label class="asset-note-field">
              <span>备注</span>
              <input v-model="assetEditor.note" placeholder="补充用途、变更或排查备注" />
            </label>
          </div>
          <div class="form-actions">
            <button type="button" :disabled="savingAsset || !canWrite" @click="saveAssetMetadata">{{ savingAsset ? '保存中...' : '保存台账' }}</button>
            <button type="button" :disabled="savingAsset" @click="assetEditor = null">取消</button>
          </div>
        </section>
        <section class="table-panel asset-table">
          <h2>活跃资产清单</h2>
          <table>
            <thead>
              <tr>
                <th>IP</th>
                <th>名称</th>
                <th>角色</th>
                <th>业务</th>
                <th>负责人</th>
                <th>重要性</th>
                <th>总流量</th>
                <th>包数</th>
                <th>标签</th>
                <th>最近出现</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="asset in assets" :key="asset.ip">
                <td>{{ asset.ip }}</td>
                <td>{{ asset.name || '-' }}</td>
                <td>{{ asset.role }}</td>
                <td>{{ asset.business || '-' }}</td>
                <td>{{ asset.owner || '-' }}</td>
                <td>{{ criticalityText(asset.criticality) }}</td>
                <td>{{ formatBytes(asset.total_bytes) }}</td>
                <td>{{ asset.total_packets.toLocaleString() }}</td>
                <td>{{ asset.tags.length ? asset.tags.join(', ') : '-' }}</td>
                <td>{{ formatTime(asset.last_seen) }}</td>
                <td>
                  <div class="row-actions">
                    <button class="inline-button" type="button" :disabled="!canWrite" @click="editAsset(asset)">编辑</button>
                    <button class="inline-button" type="button" @click="profileIP = asset.ip; currentView = 'profile'; loadProfile()">画像</button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </section>
      </template>

      <template v-else-if="currentView === 'asset-risk'">
        <section class="metrics-grid">
          <article class="metric">
            <AlertTriangle :size="22" />
            <div>
              <span>严重资产</span>
              <strong>{{ criticalAssetRiskCount.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <RadioTower :size="22" />
            <div>
              <span>暴露资产</span>
              <strong>{{ exposedAssetRiskCount.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <HardDrive :size="22" />
            <div>
              <span>未归属资产</span>
              <strong>{{ unownedAssetRiskCount.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Database :size="22" />
            <div>
              <span>资产流量</span>
              <strong>{{ formatBytes(assetRiskTotalBytes) }}</strong>
            </div>
          </article>
        </section>
        <section class="ai-summary-card">
          <div class="panel-heading">
            <h2>{{ assetAISummary.title }}</h2>
            <span>{{ assetAISummary.mode }} / {{ aiConfidenceText(assetAISummary.confidence) }}</span>
          </div>
          <p class="ai-summary-lead">{{ assetAISummary.summary }}</p>
          <div class="ai-summary-grid">
            <div>
              <span>关键发现</span>
              <ul>
                <li v-for="item in assetAISummary.findings" :key="`asset-finding-${item}`">{{ item }}</li>
              </ul>
            </div>
            <div>
              <span>建议动作</span>
              <ul>
                <li v-for="item in assetAISummary.actions" :key="`asset-action-${item}`">{{ item }}</li>
              </ul>
            </div>
          </div>
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="资产风险评分" eyebrow="Risk Score" :items="assetRiskScoreItems" unit="count" />
          <HorizontalBarChart title="资产风险等级" eyebrow="Risk Level" :items="assetRiskLevelItems" unit="count" />
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="公网暴露流量" eyebrow="External Exposure" :items="assetRiskExposureItems" />
          <HorizontalBarChart title="主要风险原因" eyebrow="Top Finding" :items="assetRiskFindingItems" unit="count" />
        </section>
        <section class="table-panel wide-key-table asset-risk-table">
          <div class="panel-heading">
            <h2>资产风险态势</h2>
            <span>{{ assetRisks.length.toLocaleString() }} 个资产 / {{ rangeLabel }}</span>
          </div>
          <div v-if="assetRisks.length === 0" class="empty-state">暂无资产风险数据</div>
          <table v-else>
            <thead>
              <tr>
                <th>资产</th>
                <th>等级</th>
                <th>评分</th>
                <th>负责人</th>
                <th>角色</th>
                <th>暴露服务</th>
                <th>公网对端</th>
                <th>事件</th>
                <th>异常</th>
                <th>主要原因</th>
                <th>建议动作</th>
                <th>最近出现</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="asset in assetRisks" :key="asset.ip">
                <td>
                  <strong>{{ asset.ip }}</strong>
                  <span class="cell-subtle">{{ asset.name || asset.business || asset.environment }}</span>
                </td>
                <td><span class="severity-pill" :class="asset.risk_level">{{ assetRiskLevelText(asset.risk_level) }}</span></td>
                <td>{{ asset.risk_score }}</td>
                <td>{{ asset.owner || '-' }}</td>
                <td>{{ asset.role || '-' }}</td>
                <td>{{ asset.exposed_services.toLocaleString() }} / 高危 {{ asset.high_risk_services.toLocaleString() }}</td>
                <td>{{ asset.external_peers.toLocaleString() }} / {{ asset.external_sessions.toLocaleString() }} 会话</td>
                <td>{{ asset.open_incidents.toLocaleString() }} / 严重 {{ asset.critical_incidents.toLocaleString() }}</td>
                <td>{{ asset.anomaly_count.toLocaleString() }}</td>
                <td>{{ asset.top_finding || '-' }}</td>
                <td>{{ asset.recommended_action }}</td>
                <td>{{ formatTime(asset.last_seen) }}</td>
                <td class="action-cell">
                  <button class="inline-button" type="button" @click="profileIP = asset.ip; currentView = 'profile'; loadProfile()">画像</button>
                  <button class="inline-button" type="button" @click="searchTerm = asset.ip; currentView = 'search'; runSearch()">检索</button>
                  <button class="inline-button" type="button" :disabled="!canWrite" @click="editAsset({ ...asset, tags: [], note: '', metadata_updated_at: 0, inbound_bytes: 0, inbound_packets: 0, outbound_bytes: 0, outbound_packets: 0, total_packets: asset.total_packets, avg_packet_size: 0, first_seen: 0 })">建档</button>
                </td>
              </tr>
            </tbody>
          </table>
        </section>
      </template>

      <template v-else-if="currentView === 'security'">
        <section class="metrics-grid">
          <article class="metric">
            <AlertTriangle :size="22" />
            <div>
              <span>严重线索</span>
              <strong>{{ criticalInsightCount.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Activity :size="22" />
            <div>
              <span>警告线索</span>
              <strong>{{ warningInsightCount.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Database :size="22" />
            <div>
              <span>线索总数</span>
              <strong>{{ securityInsights.length.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <RadioTower :size="22" />
            <div>
              <span>观察范围</span>
              <strong>{{ rangeLabel }}</strong>
            </div>
          </article>
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="线索类型流量" eyebrow="Insight Type" :items="insightKindItems" />
          <HorizontalBarChart title="告警级别分布" eyebrow="Alert Severity" :items="alertSeverityItems" unit="count" />
        </section>
        <section class="table-panel wide-key-table risk-table">
          <h2>风险线索</h2>
          <div v-if="securityInsights.length === 0" class="empty-state">暂无风险线索</div>
          <table v-else>
            <thead>
              <tr>
                <th>对象</th>
                <th>类型</th>
                <th>级别</th>
                <th>摘要</th>
                <th>流量</th>
                <th>包数</th>
                <th>评分</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="item in securityInsights" :key="`${item.kind}-${item.subject}`">
                <td>{{ item.subject }}</td>
                <td>{{ insightKindText(item.kind) }}</td>
                <td>
                  <span class="severity-pill" :class="item.severity">{{ severityText(item.severity) }}</span>
                </td>
                <td>{{ item.summary }}</td>
                <td>{{ formatBytes(item.bytes) }}</td>
                <td>{{ item.packets.toLocaleString() }}</td>
                <td>{{ item.score }}</td>
                <td>
                  <button class="inline-button" type="button" :disabled="handlingAlert || !canWrite" @click="silenceSubject(item.subject)">忽略</button>
                </td>
              </tr>
            </tbody>
          </table>
        </section>
      </template>

      <template v-else-if="currentView === 'incidents'">
        <section class="metrics-grid">
          <article class="metric">
            <Shield :size="22" />
            <div>
              <span>开放事件</span>
              <strong>{{ openIncidentCount.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <AlertTriangle :size="22" />
            <div>
              <span>严重事件</span>
              <strong>{{ criticalIncidentCount.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Database :size="22" />
            <div>
              <span>关联流量</span>
              <strong>{{ formatBytes(incidentTotalBytes) }}</strong>
            </div>
          </article>
          <article class="metric">
            <History :size="22" />
            <div>
              <span>观察范围</span>
              <strong>{{ rangeLabel }}</strong>
            </div>
          </article>
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="事件来源分布" eyebrow="Incident Source" :items="incidentSourceItems" unit="count" />
          <HorizontalBarChart title="事件级别分布" eyebrow="Severity" :items="incidentSeverityItems" unit="count" />
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="事件类别流量" eyebrow="Category Traffic" :items="incidentCategoryItems" />
          <HorizontalBarChart title="事件类型流量" eyebrow="Kind Traffic" :items="incidentKindItems" />
        </section>
        <section v-if="selectedIncident" class="table-panel incident-context-panel">
          <div class="panel-heading">
            <h2>事件上下文</h2>
            <span>{{ loadingIncidentContext ? '加载中...' : `${incidentContext.selector.dimension} / ${incidentContext.selector.key || incidentContext.subject}` }}</span>
          </div>
          <div class="incident-context-summary">
            <div>
              <span>事件对象</span>
              <strong>{{ selectedIncident.subject }}</strong>
            </div>
            <div>
              <span>事件类型</span>
              <strong>{{ incidentKindText(selectedIncident.kind) }}</strong>
            </div>
            <div>
              <span>关联流量</span>
              <strong>{{ formatBytes(incidentContext.relations.summary.bytes || selectedIncident.bytes) }}</strong>
            </div>
            <div>
              <span>关联会话</span>
              <strong>{{ incidentContext.sessions.length.toLocaleString() }}</strong>
            </div>
            <div>
              <span>源 IP</span>
              <strong>{{ incidentContext.selector.src_ip || '-' }}</strong>
            </div>
            <div>
              <span>目的 IP / 端口</span>
              <strong>{{ incidentContext.selector.dst_ip || '-' }}{{ incidentContext.selector.dst_port ? `:${incidentContext.selector.dst_port}` : '' }}</strong>
            </div>
          </div>
          <div class="ai-summary-card compact">
            <div class="panel-heading">
              <h2>{{ incidentAISummary.title }}</h2>
              <span>{{ incidentAISummary.mode }} / {{ aiConfidenceText(incidentAISummary.confidence) }}</span>
            </div>
            <p class="ai-summary-lead">{{ incidentAISummary.summary }}</p>
            <div class="ai-summary-grid">
              <div>
                <span>调查发现</span>
                <ul>
                  <li v-for="item in incidentAISummary.findings" :key="`incident-finding-${item}`">{{ item }}</li>
                </ul>
              </div>
              <div>
                <span>下一步</span>
                <ul>
                  <li v-for="item in incidentAISummary.actions" :key="`incident-action-${item}`">{{ item }}</li>
                </ul>
              </div>
            </div>
          </div>
          <div class="playbook-list">
            <article v-for="action in incidentContext.playbook_actions" :key="action.label">
              <strong>{{ action.label }}</strong>
              <span>{{ action.description }}</span>
            </article>
          </div>
          <div class="incident-note-editor">
            <label class="filter-field">
              <span>处置备注</span>
              <input v-model="incidentNoteText" placeholder="记录排查进展、责任人、结论或后续动作" @keyup.enter="saveIncidentNote" />
            </label>
            <button type="button" :disabled="savingIncidentNote || !incidentNoteText.trim() || !canWrite" @click="saveIncidentNote">
              {{ savingIncidentNote ? '保存中...' : '添加备注' }}
            </button>
          </div>
          <div class="incident-timeline">
            <h3>处置时间线</h3>
            <div v-if="incidentTimeline.length === 0" class="empty-state">暂无处置记录</div>
            <article v-for="entry in incidentTimeline" :key="`${entry.type}-${entry.created_at}-${entry.summary}`">
              <span>{{ formatTime(entry.created_at) }} / {{ entry.author || 'operator' }}</span>
              <strong>{{ entry.type === 'status' ? alertStatusText(entry.status) : '备注' }}</strong>
              <p>{{ entry.summary || entry.note || '-' }}</p>
            </article>
          </div>
          <section class="command-grid">
            <HorizontalBarChart title="上下文关联 IP" eyebrow="Related IP" :items="incidentContext.relations.related_ips" />
            <HorizontalBarChart title="上下文关联端口" eyebrow="Related Port" :items="incidentContext.relations.related_ports" />
          </section>
          <section class="tables-grid analysis-grid">
            <TopNTable title="关联服务" :items="incidentContext.relations.related_services" />
            <TopNTable title="关联会话" :items="incidentContextSessionItems" />
            <TopNTable title="关联风险线索" :items="incidentContextInsightItems" />
            <TopNTable title="关联异常波动" :items="incidentContextAnomalyItems" />
          </section>
          <div v-if="incidentContext.sessions.length" class="context-session-list">
            <h3>会话明细</h3>
            <table>
              <thead>
                <tr>
                  <th>会话</th>
                  <th>服务</th>
                  <th>风险</th>
                  <th>方向</th>
                  <th>流量</th>
                  <th>最近出现</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="row in incidentContext.sessions" :key="row.key">
                  <td>{{ row.key }}</td>
                  <td>{{ row.service }}</td>
                  <td><span class="severity-pill" :class="row.risk">{{ serviceRiskText(row.risk) }}</span></td>
                  <td>{{ row.direction }}</td>
                  <td>{{ formatBytes(row.bytes) }}</td>
                  <td>{{ formatTime(row.last_seen) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>
        <section class="table-panel wide-key-table incident-table">
          <div class="panel-heading">
            <h2>统一事件流</h2>
            <span>{{ securityIncidents.length.toLocaleString() }} 条事件 / {{ rangeLabel }}</span>
          </div>
          <div v-if="securityIncidents.length === 0" class="empty-state">暂无安全事件</div>
          <table v-else>
            <thead>
              <tr>
                <th>对象</th>
                <th>来源</th>
                <th>类别</th>
                <th>级别</th>
                <th>状态</th>
                <th>摘要</th>
                <th>建议动作</th>
                <th>关联流量</th>
                <th>评分</th>
                <th>最近出现</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="incident in securityIncidents" :key="incident.id">
                <td :title="incident.subject">{{ incident.subject }}</td>
                <td>{{ incident.source }}</td>
                <td>{{ incident.category }}</td>
                <td><span class="severity-pill" :class="incident.severity">{{ severityText(incident.severity) }}</span></td>
                <td>{{ alertStatusText(incident.status) }}</td>
                <td>{{ incident.summary }}</td>
                <td>{{ incident.recommended_action }}</td>
                <td>{{ formatBytes(incident.bytes) }}</td>
                <td>{{ incident.score }}</td>
                <td>{{ formatTime(incident.last_seen) }}</td>
                <td class="action-cell">
                  <button class="inline-button" type="button" :disabled="loadingIncidentContext" @click="loadIncidentContext(incident)">上下文</button>
                  <button class="inline-button" type="button" @click="inspectIncident(incident)">追踪</button>
                  <button class="inline-button" type="button" :disabled="handlingAlert || incident.status === 'ack' || !canWrite" @click="updateIncidentStatus(incident, 'ack')">确认</button>
                  <button class="inline-button" type="button" :disabled="handlingAlert || incident.status === 'resolved' || !canWrite" @click="updateIncidentStatus(incident, 'resolved')">恢复</button>
                  <button class="inline-button" type="button" :disabled="handlingAlert || incident.status === 'open' || !canWrite" @click="updateIncidentStatus(incident, 'open')">重开</button>
                  <button class="inline-button" type="button" :disabled="handlingAlert || !canWrite" @click="silenceSubject(incident.subject)">忽略</button>
                </td>
              </tr>
            </tbody>
          </table>
        </section>
      </template>

      <template v-else-if="currentView === 'profile'">
        <section class="toolbar-panel profile-toolbar">
          <label class="filter-field">
            <span>IP 地址</span>
            <input v-model="profileIP" placeholder="输入 IP，例如 10.2.0.12" @keyup.enter="loadProfile" />
          </label>
          <button type="button" @click="loadProfile">查询画像</button>
        </section>
        <section class="metrics-grid">
          <article class="metric">
            <Database :size="22" />
            <div>
              <span>总流量</span>
              <strong>{{ formatBytes(profileTotalBytes) }}</strong>
            </div>
          </article>
          <article class="metric">
            <Activity :size="22" />
            <div>
              <span>总包数</span>
              <strong>{{ profileTotalPackets.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Gauge :size="22" />
            <div>
              <span>出站 / 入站</span>
              <strong>{{ formatBytes(ipProfile.outbound_bytes) }} / {{ formatBytes(ipProfile.inbound_bytes) }}</strong>
            </div>
          </article>
          <article class="metric">
            <RadioTower :size="22" />
            <div>
              <span>最近出现</span>
              <strong>{{ formatTime(ipProfile.last_seen) }}</strong>
            </div>
          </article>
        </section>
        <section class="command-grid">
          <HorizontalBarChart :title="`${ipProfile.ip} 主机对流量`" eyebrow="IP Pair Flow" :items="ipProfile.top_pairs" />
          <HorizontalBarChart :title="`${ipProfile.ip} 会话流量`" eyebrow="IP Session Flow" :items="ipProfile.top_flows" />
        </section>
        <section class="tables-grid analysis-grid">
          <TopNTable :title="`${ipProfile.ip} 主机对`" :items="ipProfile.top_pairs" />
          <TopNTable :title="`${ipProfile.ip} 会话`" :items="ipProfile.top_flows" />
        </section>
      </template>

      <template v-else-if="currentView === 'port'">
        <section class="toolbar-panel profile-toolbar">
          <label class="filter-field">
            <span>目的端口</span>
            <input v-model="profilePort" placeholder="输入端口，例如 8081 / 443 / 80" @keyup.enter="loadPortProfile" />
          </label>
          <button type="button" @click="loadPortProfile">查询端口</button>
        </section>
        <section class="metrics-grid">
          <article class="metric">
            <Database :size="22" />
            <div>
              <span>端口流量</span>
              <strong>{{ formatBytes(portProfile.bytes) }}</strong>
            </div>
          </article>
          <article class="metric">
            <Activity :size="22" />
            <div>
              <span>端口包数</span>
              <strong>{{ portProfile.packets.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Gauge :size="22" />
            <div>
              <span>平均包长</span>
              <strong>{{ portProfile.packets ? formatBytes(portProfile.bytes / portProfile.packets) : '0 B' }}</strong>
            </div>
          </article>
          <article class="metric">
            <RadioTower :size="22" />
            <div>
              <span>观察范围</span>
              <strong>{{ rangeLabel }}</strong>
            </div>
          </article>
        </section>
        <HorizontalBarChart :title="`目的端口 ${portProfile.port} 会话排行`" eyebrow="Port Sessions" :items="portProfile.flows" />
        <TopNTable :title="`目的端口 ${portProfile.port} 关联会话`" :items="portProfile.flows" />
      </template>

      <template v-else-if="currentView === 'sessions'">
        <section class="toolbar-panel profile-toolbar">
          <label class="filter-field">
            <span>会话关键字</span>
            <input v-model="sessionSearch" placeholder="源/目的 IP、端口、协议或会话片段" @keyup.enter="loadSessions" />
          </label>
          <button type="button" @click="loadSessions">追踪会话</button>
          <button type="button" class="command-button" @click="exportSessions">导出 CSV</button>
        </section>
        <section class="metrics-grid">
          <article class="metric">
            <Waypoints :size="22" />
            <div>
              <span>会话数量</span>
              <strong>{{ sessions.length.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Activity :size="22" />
            <div>
              <span>会话流量</span>
              <strong>{{ formatBytes(sessionTotalBytes) }}</strong>
            </div>
          </article>
          <article class="metric">
            <ListOrdered :size="22" />
            <div>
              <span>会话包数</span>
              <strong>{{ sessionTotalPackets.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Shield :size="22" />
            <div>
              <span>高风险会话</span>
              <strong>{{ highRiskSessionCount.toLocaleString() }}</strong>
            </div>
          </article>
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="会话服务分布" eyebrow="Session Service" :items="sessionServiceItems" />
          <HorizontalBarChart title="会话方向分布" eyebrow="Session Direction" :items="sessionDirectionItems" />
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="会话风险分布" eyebrow="Session Risk" :items="sessionRiskItems" />
          <HorizontalBarChart title="会话流量排行" eyebrow="Session Ranking" :items="topFlows" />
        </section>
        <section class="table-panel wide-key-table session-table">
          <div class="panel-heading">
            <h2>结构化会话</h2>
            <span>{{ rangeLabel }} / {{ sessionSearch.trim() || '全部会话' }}</span>
          </div>
          <div v-if="sessions.length === 0" class="empty-state">暂无会话数据</div>
          <table v-else>
            <thead>
              <tr>
                <th>会话</th>
                <th>服务</th>
                <th>风险</th>
                <th>方向</th>
                <th>服务端</th>
                <th>客户端</th>
                <th>流量</th>
                <th>包数</th>
                <th>最近出现</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in sessions" :key="row.key">
                <td :title="row.key">{{ row.key }}</td>
                <td>
                  <strong>{{ row.service }}</strong>
                  <span class="cell-subtle">{{ row.category }} / {{ row.protocol }}</span>
                </td>
                <td><span class="severity-pill" :class="row.risk">{{ serviceRiskText(row.risk) }}</span></td>
                <td>{{ row.direction }}</td>
                <td>{{ row.server_ip }}:{{ row.server_port }}</td>
                <td>{{ row.client_ip || row.src_ip }}</td>
                <td>{{ formatBytes(row.bytes) }}</td>
                <td>{{ row.packets.toLocaleString() }}</td>
                <td>{{ formatTime(row.last_seen) }}</td>
                <td class="action-cell">
                  <button class="inline-button" type="button" @click="openSessionIP(row.src_ip)">源</button>
                  <button class="inline-button" type="button" @click="openSessionIP(row.dst_ip)">目的</button>
                  <button class="inline-button" type="button" @click="openSessionPort(row.dst_port)">端口</button>
                  <button class="inline-button" type="button" @click="inspectSession(row)">关联</button>
                </td>
              </tr>
            </tbody>
          </table>
        </section>
      </template>

      <template v-else-if="currentView === 'topn'">
        <section class="toolbar-panel">
          <button type="button" :class="{ active: activeTopN === 'src_ip' }" @click="activeTopN = 'src_ip'">源 IP</button>
          <button type="button" :class="{ active: activeTopN === 'dst_ip' }" @click="activeTopN = 'dst_ip'">目的 IP</button>
          <button type="button" :class="{ active: activeTopN === 'pair' }" @click="activeTopN = 'pair'">主机对</button>
          <button type="button" :class="{ active: activeTopN === 'dst_port' }" @click="activeTopN = 'dst_port'">目的端口</button>
          <button type="button" :class="{ active: activeTopN === 'service' }" @click="activeTopN = 'service'">应用服务</button>
          <button type="button" :class="{ active: activeTopN === 'service_category' }" @click="activeTopN = 'service_category'">服务类别</button>
          <button type="button" :class="{ active: activeTopN === 'service_risk' }" @click="activeTopN = 'service_risk'">服务风险</button>
          <button type="button" :class="{ active: activeTopN === 'vlan' }" @click="activeTopN = 'vlan'">VLAN</button>
          <button type="button" :class="{ active: activeTopN === 'dscp' }" @click="activeTopN = 'dscp'">DSCP</button>
          <button type="button" :class="{ active: activeTopN === 'ecn' }" @click="activeTopN = 'ecn'">ECN</button>
          <button type="button" :class="{ active: activeTopN === 'protocol' }" @click="activeTopN = 'protocol'">协议</button>
          <button type="button" :class="{ active: activeTopN === 'packet_len' }" @click="activeTopN = 'packet_len'">包长</button>
          <button type="button" :class="{ active: activeTopN === 'flow' }" @click="activeTopN = 'flow'">会话</button>
          <button type="button" class="command-button" @click="exportSelectedTopN">导出 CSV</button>
        </section>
        <HorizontalBarChart :title="selectedTopNTitle" eyebrow="TopN Chart" :items="selectedTopN" />
        <DimensionTrendChart :title="trendTitle" :points="dimensionTrend" />
        <section class="command-grid">
          <HorizontalBarChart title="关联 IP" eyebrow="Related IP" :items="objectRelations.related_ips" />
          <HorizontalBarChart title="关联端口" eyebrow="Related Port" :items="objectRelations.related_ports" />
        </section>
        <section class="tables-grid analysis-grid">
          <TopNTable title="关联服务" :items="objectRelations.related_services" />
          <TopNTable title="关联会话" :items="objectRelations.related_flows" />
          <TopNTable title="关联风险线索" :items="relationInsightItems" />
        </section>
        <TopNTable :title="selectedTopNTitle" :items="selectedTopN" />
      </template>

      <template v-else-if="currentView === 'rules'">
        <section class="toolbar-panel">
          <button class="command-button" type="button" :disabled="!canWrite" @click="newRule">新增规则</button>
          <button type="button" @click="exportRuleFindings">导出命中</button>
          <div class="toolbar-summary">
            {{ rangeLabel }} / {{ detectionRules.length.toLocaleString() }} 条规则 / {{ ruleFindings.length.toLocaleString() }} 条命中
          </div>
        </section>
        <section class="metrics-grid">
          <article class="metric">
            <Settings2 :size="22" />
            <div>
              <span>检测规则</span>
              <strong>{{ detectionRules.length.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Shield :size="22" />
            <div>
              <span>启用规则</span>
              <strong>{{ enabledRuleCount.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <AlertTriangle :size="22" />
            <div>
              <span>严重命中</span>
              <strong>{{ criticalRuleFindingCount.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Activity :size="22" />
            <div>
              <span>命中对象</span>
              <strong>{{ ruleFindings.length.toLocaleString() }}</strong>
            </div>
          </article>
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="规则命中分布" eyebrow="Rule Hits" :items="ruleFindingRuleItems" unit="count" />
          <HorizontalBarChart title="命中级别分布" eyebrow="Severity" :items="ruleFindingSeverityItems" unit="count" />
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="命中指标流量" eyebrow="Metric Traffic" :items="ruleFindingMetricItems" />
          <HorizontalBarChart title="规则关联服务" eyebrow="Service Context" :items="topServices" />
        </section>
        <section v-if="ruleEditor" class="table-panel rule-editor-panel">
          <div class="panel-heading">
            <h2>{{ ruleEditor.id ? '编辑检测规则' : '新增检测规则' }}</h2>
            <span>{{ ruleEditor.id || '新规则' }}</span>
          </div>
          <div class="asset-editor-grid rule-editor-grid">
            <label>
              <span>规则名称</span>
              <input v-model="ruleEditor.name" placeholder="例如 公网会话突增" />
            </label>
            <label>
              <span>分类</span>
              <input v-model="ruleEditor.category" placeholder="例如 公网访问 / 链路健康" />
            </label>
            <label>
              <span>指标</span>
              <select v-model="ruleEditor.metric">
                <option v-for="option in ruleMetricOptions" :key="option.value" :value="option.value">{{ option.label }}</option>
              </select>
            </label>
            <label>
              <span>匹配对象</span>
              <input v-model="ruleEditor.match" placeholder="可选：IP、端口、服务名或关键字" />
            </label>
            <label>
              <span>条件</span>
              <select v-model="ruleEditor.operator">
                <option v-for="option in ruleOperatorOptions" :key="option.value" :value="option.value">{{ option.label }}</option>
              </select>
            </label>
            <label>
              <span>阈值</span>
              <input v-model.number="ruleEditor.threshold" type="number" min="1" />
            </label>
            <label>
              <span>级别</span>
              <select v-model="ruleEditor.severity">
                <option v-for="option in ruleSeverityOptions" :key="option.value" :value="option.value">{{ option.label }}</option>
              </select>
            </label>
            <label>
              <span>启用状态</span>
              <select v-model="ruleEditor.enabled">
                <option :value="true">启用</option>
                <option :value="false">停用</option>
              </select>
            </label>
            <label class="asset-note-field">
              <span>规则说明</span>
              <input v-model="ruleEditor.description" placeholder="说明规则目的、适用场景或排查依据" />
            </label>
            <label class="asset-note-field">
              <span>建议动作</span>
              <input v-model="ruleEditor.recommended_action" placeholder="命中后建议执行的核查或处置动作" />
            </label>
          </div>
          <div class="form-actions">
            <button type="button" :disabled="savingRule || !ruleEditor.name.trim() || ruleEditor.threshold <= 0 || !canWrite" @click="saveRule">
              {{ savingRule ? '保存中...' : '保存规则' }}
            </button>
            <button type="button" :disabled="savingRule" @click="ruleEditor = null">取消</button>
          </div>
        </section>
        <section class="table-panel wide-key-table rules-table">
          <div class="panel-heading">
            <h2>检测规则</h2>
            <span>{{ enabledRuleCount.toLocaleString() }} 条启用</span>
          </div>
          <table>
            <thead>
              <tr>
                <th>规则</th>
                <th>分类</th>
                <th>指标</th>
                <th>匹配</th>
                <th>阈值</th>
                <th>级别</th>
                <th>状态</th>
                <th>建议动作</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="rule in detectionRules" :key="rule.id">
                <td>
                  <strong>{{ rule.name }}</strong>
                  <span class="cell-subtle">{{ rule.description || rule.id }}</span>
                </td>
                <td>{{ rule.category }}</td>
                <td>{{ ruleMetricText(rule.metric) }}</td>
                <td>{{ rule.match || '全部对象' }}</td>
                <td>{{ ruleOperatorOptions.find((item) => item.value === rule.operator)?.label ?? rule.operator }} {{ rule.threshold.toLocaleString() }}</td>
                <td><span class="severity-pill" :class="rule.severity">{{ severityText(rule.severity) }}</span></td>
                <td>{{ rule.enabled ? '启用' : '停用' }}</td>
                <td>{{ rule.recommended_action }}</td>
                <td class="action-cell">
                  <button class="inline-button" type="button" :disabled="!canWrite" @click="editRule(rule)">编辑</button>
                  <button class="inline-button" type="button" :disabled="!canWrite" @click="toggleRule(rule)">{{ rule.enabled ? '停用' : '启用' }}</button>
                  <button class="inline-button" type="button" :disabled="savingRule || !canWrite" @click="deleteRule(rule)">删除</button>
                </td>
              </tr>
            </tbody>
          </table>
          <div v-if="detectionRules.length === 0" class="empty-state">暂无检测规则</div>
        </section>
        <section class="table-panel wide-key-table rule-finding-table">
          <div class="panel-heading">
            <h2>规则命中</h2>
            <span>{{ ruleFindings.length.toLocaleString() }} 条 / {{ rangeLabel }}</span>
          </div>
          <div v-if="ruleFindings.length === 0" class="empty-state">暂无规则命中</div>
          <table v-else>
            <thead>
              <tr>
                <th>对象</th>
                <th>规则</th>
                <th>级别</th>
                <th>指标</th>
                <th>当前值</th>
                <th>阈值</th>
                <th>流量</th>
                <th>摘要</th>
                <th>建议动作</th>
                <th>命中时间</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in ruleFindings" :key="row.id">
                <td>{{ row.subject }}</td>
                <td>{{ row.rule_name }}</td>
                <td><span class="severity-pill" :class="row.severity">{{ severityText(row.severity) }}</span></td>
                <td>{{ ruleMetricText(row.metric) }}</td>
                <td>{{ row.value.toLocaleString() }} {{ row.unit }}</td>
                <td>{{ row.threshold.toLocaleString() }} {{ row.unit }}</td>
                <td>{{ formatBytes(row.bytes) }}</td>
                <td>{{ row.summary }}</td>
                <td>{{ row.recommended_action }}</td>
                <td>{{ formatTime(row.matched_at) }}</td>
              </tr>
            </tbody>
          </table>
        </section>
      </template>

      <template v-else-if="currentView === 'alerts'">
        <section class="toolbar-panel alert-config-panel">
          <label>
            <span>单会话字节阈值</span>
            <input v-model.number="alertConfig.flow_bytes" type="number" min="1" />
          </label>
          <label>
            <span>单会话占比阈值</span>
            <input v-model.number="alertFlowSharePercent" type="number" min="1" max="100" />
          </label>
          <label>
            <span>源主机包数阈值</span>
            <input v-model.number="alertConfig.source_packets" type="number" min="1" />
          </label>
          <label>
            <span>链路利用率阈值</span>
            <input v-model.number="alertLinkUtilPercent" type="number" min="1" max="100" />
          </label>
          <button type="button" :disabled="savingAlerts || !canWrite" @click="saveAlertConfig">
            {{ savingAlerts ? '保存中...' : '保存阈值' }}
          </button>
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="告警级别分布" eyebrow="Severity" :items="alertSeverityItems" unit="count" />
          <HorizontalBarChart title="处理状态分布" eyebrow="Status" :items="alertStatusItems" unit="count" />
        </section>
        <section class="table-panel whitelist-panel">
          <div class="panel-heading">
            <h2>白名单管理</h2>
            <span>被忽略的对象不会再生成新告警，风险线索也会自动过滤。</span>
          </div>
          <div class="whitelist-form">
            <label class="filter-field">
              <span>对象</span>
              <input v-model="whitelistSubject" placeholder="输入 IP、会话、采集源或风险线索对象" @keyup.enter="addWhitelistSubject" />
            </label>
            <button type="button" :disabled="handlingAlert || !whitelistSubject.trim() || !canWrite" @click="addWhitelistSubject">加入白名单</button>
          </div>
          <div class="whitelist-list">
            <button
              v-for="subject in alertConfig.silenced_subjects ?? []"
              :key="subject"
              type="button"
              class="silence-chip"
              :disabled="handlingAlert || !canWrite"
              @click="removeSilence(subject)"
            >
              {{ subject }} ×
            </button>
            <span v-if="(alertConfig.silenced_subjects ?? []).length === 0" class="muted-text">暂无白名单对象</span>
          </div>
        </section>
        <section class="table-panel">
          <h2>告警事件</h2>
          <div v-if="alerts.length === 0" class="empty-state">暂无告警事件</div>
          <table v-else>
            <thead>
              <tr>
                <th>级别</th>
                <th>状态</th>
                <th>对象</th>
                <th>摘要</th>
                <th>最近出现</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="alert in alerts" :key="alert.id">
                <td>{{ severityText(alert.severity) }}</td>
                <td>{{ alertStatusText(alert.status) }}</td>
                <td>{{ alert.subject }}</td>
                <td>{{ alert.summary }}</td>
                <td>{{ formatTime(alert.last_seen) }}</td>
                <td class="action-cell">
                  <button class="inline-button" type="button" :disabled="handlingAlert || alert.status === 'ack' || !canWrite" @click="updateAlertStatus(alert, 'ack')">确认</button>
                  <button class="inline-button" type="button" :disabled="handlingAlert || alert.status === 'resolved' || !canWrite" @click="updateAlertStatus(alert, 'resolved')">恢复</button>
                  <button class="inline-button" type="button" :disabled="handlingAlert || !canWrite" @click="silenceSubject(alert.subject)">忽略</button>
                </td>
              </tr>
            </tbody>
          </table>
        </section>
      </template>

      <template v-else-if="currentView === 'reports'">
        <section class="toolbar-panel">
          <button class="command-button" type="button" @click="exportReportOverview">导出报表 CSV</button>
          <div class="toolbar-summary">
            {{ rangeLabel }} / 生成时间 {{ formatTime(reportOverview.generated_at) }} / {{ reportOverview.recommendations.length.toLocaleString() }} 条建议
          </div>
        </section>
        <section class="metrics-grid">
          <article class="metric">
            <Database :size="22" />
            <div>
              <span>总流量</span>
              <strong>{{ formatBytes(reportOverview.summary.bytes) }}</strong>
            </div>
          </article>
          <article class="metric">
            <Shield :size="22" />
            <div>
              <span>严重资产</span>
              <strong>{{ reportOverview.summary.critical_assets.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <AlertTriangle :size="22" />
            <div>
              <span>开放事件</span>
              <strong>{{ reportOverview.summary.open_incidents.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Activity :size="22" />
            <div>
              <span>异常波动</span>
              <strong>{{ reportOverview.summary.anomaly_count.toLocaleString() }}</strong>
            </div>
          </article>
        </section>
        <section class="metrics-grid">
          <article class="metric">
            <RadioTower :size="22" />
            <div>
              <span>暴露服务</span>
              <strong>{{ reportOverview.summary.exposed_services.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <ServerCog :size="22" />
            <div>
              <span>高风险服务</span>
              <strong>{{ reportOverview.summary.high_risk_services.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Waypoints :size="22" />
            <div>
              <span>公网访问</span>
              <strong>{{ reportOverview.summary.external_access.toLocaleString() }}</strong>
            </div>
          </article>
          <article class="metric">
            <Gauge :size="22" />
            <div>
              <span>峰值吞吐</span>
              <strong>{{ reportOverview.summary.peak_mbps.toFixed(2) }} Mbps</strong>
            </div>
          </article>
        </section>
        <section class="ai-summary-card">
          <div class="panel-heading">
            <h2>{{ reportAISummary.title }}</h2>
            <span>{{ reportAISummary.mode }} / {{ aiConfidenceText(reportAISummary.confidence) }}</span>
          </div>
          <p class="ai-summary-lead">{{ reportAISummary.summary }}</p>
          <div class="ai-summary-grid">
            <div>
              <span>巡检发现</span>
              <ul>
                <li v-for="item in reportAISummary.findings" :key="`report-finding-${item}`">{{ item }}</li>
              </ul>
            </div>
            <div>
              <span>处置建议</span>
              <ul>
                <li v-for="item in reportAISummary.actions" :key="`report-action-${item}`">{{ item }}</li>
              </ul>
            </div>
          </div>
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="报表资产风险评分" eyebrow="Asset Risk" :items="reportAssetRiskItems" unit="count" />
          <HorizontalBarChart title="报表异常增量" eyebrow="Anomaly Delta" :items="reportAnomalyItems" />
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="报表事件类型" eyebrow="Incident Kind" :items="reportIncidentKindItems" />
          <HorizontalBarChart title="报表事件级别" eyebrow="Severity" :items="reportIncidentSeverityItems" unit="count" />
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="报表暴露风险" eyebrow="Exposure Risk" :items="reportExposureRiskItems" />
          <HorizontalBarChart title="报表公网方向" eyebrow="External Direction" :items="reportExternalDirectionItems" />
        </section>
        <section class="tables-grid analysis-grid">
          <TopNTable title="报表 Top 源 IP" :items="reportOverview.top_src" />
          <TopNTable title="报表 Top 端口" :items="reportOverview.top_ports" />
          <TopNTable title="报表 Top 服务" :items="reportOverview.top_services" />
          <section class="table-panel report-recommendations">
            <div class="panel-heading">
              <h2>报表建议</h2>
              <span>{{ reportOverview.recommendations.length.toLocaleString() }} 条</span>
            </div>
            <div v-if="reportOverview.recommendations.length === 0" class="empty-state">暂无报表建议</div>
            <article v-for="item in reportOverview.recommendations" :key="`${item.level}-${item.title}`" class="report-recommendation">
              <span class="severity-pill" :class="item.level">{{ severityText(item.level) }}</span>
              <strong>{{ item.title }}</strong>
              <p>{{ item.detail }}</p>
            </article>
          </section>
        </section>
        <section class="table-panel wide-key-table report-asset-table">
          <div class="panel-heading">
            <h2>报表重点资产</h2>
            <span>{{ reportOverview.asset_risks.length.toLocaleString() }} 个资产 / {{ rangeLabel }}</span>
          </div>
          <div v-if="reportOverview.asset_risks.length === 0" class="empty-state">暂无资产风险数据</div>
          <table v-else>
            <thead>
              <tr>
                <th>资产</th>
                <th>等级</th>
                <th>评分</th>
                <th>负责人</th>
                <th>暴露面</th>
                <th>事件/异常</th>
                <th>主要原因</th>
                <th>建议动作</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="asset in reportOverview.asset_risks" :key="asset.ip">
                <td>
                  <strong>{{ asset.ip }}</strong>
                  <span class="cell-subtle">{{ asset.name || asset.business || asset.environment || asset.role }}</span>
                </td>
                <td><span class="severity-pill" :class="asset.risk_level">{{ assetRiskLevelText(asset.risk_level) }}</span></td>
                <td>{{ asset.risk_score }}</td>
                <td>{{ asset.owner || '-' }}</td>
                <td>{{ asset.exposed_services.toLocaleString() }} 服务 / {{ asset.external_peers.toLocaleString() }} 公网对端</td>
                <td>{{ asset.open_incidents.toLocaleString() }} 事件 / {{ asset.anomaly_count.toLocaleString() }} 异常</td>
                <td>{{ asset.top_finding || '-' }}</td>
                <td>{{ asset.recommended_action }}</td>
                <td class="action-cell">
                  <button class="inline-button" type="button" @click="profileIP = asset.ip; currentView = 'profile'; loadProfile()">画像</button>
                  <button class="inline-button" type="button" @click="searchTerm = asset.ip; currentView = 'search'; runSearch()">检索</button>
                </td>
              </tr>
            </tbody>
          </table>
        </section>
        <section class="table-panel wide-key-table report-incident-table">
          <div class="panel-heading">
            <h2>报表重点事件</h2>
            <span>{{ reportOverview.incidents.length.toLocaleString() }} 条事件 / 严重 {{ reportOverview.summary.critical_incidents.toLocaleString() }}</span>
          </div>
          <div v-if="reportOverview.incidents.length === 0" class="empty-state">暂无安全事件</div>
          <table v-else>
            <thead>
              <tr>
                <th>对象</th>
                <th>类型</th>
                <th>级别</th>
                <th>状态</th>
                <th>摘要</th>
                <th>建议动作</th>
                <th>流量</th>
                <th>评分</th>
                <th>最近出现</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="incident in reportOverview.incidents" :key="incident.id">
                <td :title="incident.subject">{{ incident.subject }}</td>
                <td>{{ incidentKindText(incident.kind) }}</td>
                <td><span class="severity-pill" :class="incident.severity">{{ severityText(incident.severity) }}</span></td>
                <td>{{ alertStatusText(incident.status) }}</td>
                <td>{{ incident.summary }}</td>
                <td>{{ incident.recommended_action }}</td>
                <td>{{ formatBytes(incident.bytes) }}</td>
                <td>{{ incident.score }}</td>
                <td>{{ formatTime(incident.last_seen) }}</td>
              </tr>
            </tbody>
          </table>
        </section>
      </template>

      <template v-else-if="currentView === 'search'">
        <section class="toolbar-panel profile-toolbar">
          <label class="filter-field">
            <span>检索关键字</span>
            <input v-model="searchTerm" placeholder="IP / 端口 / 会话片段，例如 10.2.0.12 或 8081" @keyup.enter="runSearch" />
          </label>
          <button type="button" @click="runSearch">检索</button>
        </section>
        <HorizontalBarChart title="检索结果流量" eyebrow="Search Result" :items="searchResultItems" />
        <section class="table-panel">
          <h2>检索结果</h2>
          <table>
            <thead>
              <tr>
                <th>类型</th>
                <th>对象</th>
                <th>流量</th>
                <th>包数</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in searchResults" :key="`${row.kind}-${row.key}`">
                <td>{{ row.kind }}</td>
                <td>{{ row.key }}</td>
                <td>{{ formatBytes(row.bytes) }}</td>
                <td>{{ row.packets.toLocaleString() }}</td>
              </tr>
            </tbody>
          </table>
        </section>
      </template>

      <template v-else-if="currentView === 'history'">
        <section class="toolbar-panel">
          <button type="button" class="command-button" @click="exportWindows">导出窗口 CSV</button>
        </section>
        <section class="command-grid">
          <TrafficHeatmap :points="series" />
          <DashboardChart class="chart-panel" :points="series" />
        </section>
        <section class="table-panel">
          <h2>历史窗口</h2>
          <table>
            <thead>
              <tr>
                <th>时间</th>
                <th>采集源</th>
                <th>网卡</th>
                <th>吞吐</th>
                <th>流量</th>
                <th>包数</th>
                <th>利用率</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in historyWindows" :key="`${row.source_id}-${row.iface}-${row.window_ts}`">
                <td>{{ formatTime(row.window_ts) }}</td>
                <td>{{ row.source_id }}</td>
                <td>{{ row.iface }}</td>
                <td>{{ formatRate(row.bytes, 5) }}</td>
                <td>{{ formatBytes(row.bytes) }}</td>
                <td>{{ row.packets.toLocaleString() }}</td>
                <td>{{ (row.utilization * 100).toFixed(2) }}%</td>
              </tr>
            </tbody>
          </table>
        </section>
      </template>

      <template v-else-if="currentView === 'audit'">
        <section class="metric-grid">
          <article class="metric-card">
            <span>审计事件</span>
            <strong>{{ auditEvents.length.toLocaleString() }}</strong>
            <small>{{ rangeLabel }} / 最近操作记录</small>
          </article>
          <article class="metric-card">
            <span>操作人</span>
            <strong>{{ auditActorItems.length.toLocaleString() }}</strong>
            <small>{{ auditActorItems[0]?.key ?? '-' }}</small>
          </article>
          <article class="metric-card">
            <span>动作类型</span>
            <strong>{{ auditActionItems.length.toLocaleString() }}</strong>
            <small>{{ auditActionItems[0]?.key ?? '-' }}</small>
          </article>
          <article class="metric-card">
            <span>最近操作</span>
            <strong>{{ formatTime(auditEvents[0]?.ts ?? 0) }}</strong>
            <small>{{ auditEvents[0]?.summary ?? '-' }}</small>
          </article>
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="审计动作分布" eyebrow="Audit Action" :items="auditActionItems" />
          <HorizontalBarChart title="操作人分布" eyebrow="Actor" :items="auditActorItems" />
          <HorizontalBarChart title="目标对象分布" eyebrow="Target" :items="auditTargetItems" />
        </section>
        <section class="table-panel audit-table">
          <div class="section-heading">
            <h2>操作审计明细</h2>
            <span>{{ auditEvents.length.toLocaleString() }} 条记录</span>
          </div>
          <div v-if="auditEvents.length === 0" class="empty-state">暂无审计记录</div>
          <table v-else>
            <thead>
              <tr>
                <th>时间</th>
                <th>操作人</th>
                <th>动作</th>
                <th>目标</th>
                <th>摘要</th>
                <th>来源 IP</th>
                <th>详情</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="event in auditEvents" :key="event.id">
                <td>{{ formatTime(event.ts) }}</td>
                <td>{{ event.actor || 'operator' }}</td>
                <td>{{ auditActionText(event.action) }}</td>
                <td :title="event.target">{{ event.target }}</td>
                <td>{{ event.summary }}</td>
                <td>{{ event.client_ip || '-' }}</td>
                <td :title="event.detail_text || event.detail">{{ event.detail_text || event.detail || '-' }}</td>
              </tr>
            </tbody>
          </table>
        </section>
      </template>

      <template v-else-if="currentView === 'config-versions'">
        <section class="metric-grid">
          <article class="metric-card">
            <span>配置版本</span>
            <strong>{{ configVersions.length.toLocaleString() }}</strong>
            <small>最近运行时配置快照</small>
          </article>
          <article class="metric-card">
            <span>配置范围</span>
            <strong>{{ configScopeItems.length.toLocaleString() }}</strong>
            <small>{{ configScopeItems[0]?.key ?? '-' }}</small>
          </article>
          <article class="metric-card">
            <span>变更动作</span>
            <strong>{{ configActionItems.length.toLocaleString() }}</strong>
            <small>{{ configActionItems[0]?.key ?? '-' }}</small>
          </article>
          <article class="metric-card">
            <span>最近快照</span>
            <strong>{{ formatTime(configVersions[0]?.ts ?? 0) }}</strong>
            <small>{{ configVersions[0]?.summary ?? '-' }}</small>
          </article>
        </section>
        <section class="command-grid">
          <HorizontalBarChart title="配置范围分布" eyebrow="Scope" :items="configScopeItems" />
          <HorizontalBarChart title="配置动作分布" eyebrow="Config Action" :items="configActionItems" />
          <HorizontalBarChart title="操作人分布" eyebrow="Actor" :items="configActorItems" />
        </section>
        <section v-if="selectedConfigDiff" class="table-panel config-diff-table">
          <div class="section-heading">
            <h2>配置差异</h2>
            <span>
              {{ selectedConfigDiff.version_id }} / {{ selectedConfigDiff.summary.change_count.toLocaleString() }} 处差异
            </span>
          </div>
          <div class="config-diff-summary">
            <div>
              <span>历史版本</span>
              <strong>{{ formatTime(selectedConfigDiff.summary.source_ts) }}</strong>
            </div>
            <div>
              <span>当前配置</span>
              <strong>{{ formatTime(selectedConfigDiff.summary.current_ts) }}</strong>
            </div>
            <div>
              <span>来源摘要</span>
              <strong>{{ selectedConfigDiff.summary.source || '-' }}</strong>
            </div>
          </div>
          <div v-if="selectedConfigDiff.changes.length === 0" class="empty-state">该版本与当前运行时配置一致</div>
          <table v-else>
            <thead>
              <tr>
                <th>路径</th>
                <th>类型</th>
                <th>历史值</th>
                <th>当前值</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="change in selectedConfigDiff.changes" :key="`${selectedConfigDiff.version_id}-${change.path}`">
                <td>{{ change.path }}</td>
                <td>{{ change.type }}</td>
                <td :title="change.before">{{ change.before || '-' }}</td>
                <td :title="change.after">{{ change.after || '-' }}</td>
              </tr>
            </tbody>
          </table>
        </section>
        <section class="table-panel config-version-table">
          <div class="section-heading">
            <h2>配置快照历史</h2>
            <span>{{ configVersions.length.toLocaleString() }} 条记录</span>
          </div>
          <div v-if="configVersions.length === 0" class="empty-state">暂无配置版本记录</div>
          <table v-else>
            <thead>
              <tr>
                <th>时间</th>
                <th>范围</th>
                <th>目标</th>
                <th>动作</th>
                <th>操作人</th>
                <th>摘要</th>
                <th>来源 IP</th>
                <th>配置快照</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="version in configVersions" :key="version.id">
                <td>{{ formatTime(version.ts) }}</td>
                <td>{{ configScopeText(version.scope) }}</td>
                <td :title="version.target">{{ version.target }}</td>
                <td>{{ auditActionText(version.action) }}</td>
                <td>{{ version.actor || 'operator' }}</td>
                <td>{{ version.summary }}</td>
                <td>{{ version.client_ip || '-' }}</td>
                <td :title="version.config_text || version.config">{{ version.config_text || version.config || '-' }}</td>
                <td class="action-cell">
                  <button
                    class="inline-button"
                    type="button"
                    :disabled="diffingConfigVersion === version.id"
                    @click="loadConfigVersionDiff(version)"
                  >
                    {{ diffingConfigVersion === version.id ? '对比中...' : '对比当前' }}
                  </button>
                  <button
                    class="inline-button"
                    type="button"
                    :disabled="!canWrite || restoringConfigVersion === version.id"
                    @click="restoreConfigVersion(version)"
                  >
                    {{ restoringConfigVersion === version.id ? '恢复中...' : '恢复' }}
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </section>
      </template>

      <template v-else-if="currentView === 'settings'">
        <section class="toolbar-panel">
          <button class="command-button" type="button" :disabled="savingSettings || !canWrite" @click="saveSettings">
            {{ savingSettings ? '保存中...' : '保存系统设置' }}
          </button>
          <button class="inline-button" type="button" @click="testAISettings">测试大模型</button>
          <button class="inline-button" type="button" @click="testWebhookSettings">测试通知</button>
          <button class="inline-button" type="button" @click="exportSettings">导出配置</button>
          <div class="toolbar-summary">
            更新时间 {{ formatTime(systemSettings.updated_at) }} / 敏感字段脱敏展示 / 后台连接项需要重启生效
          </div>
        </section>
        <section class="metric-grid">
          <article class="metric-card">
            <span>AI 模式</span>
            <strong>{{ systemSettings.ai.mode }}</strong>
            <small>{{ systemSettings.ai.provider }} / {{ systemSettings.ai.model }}</small>
          </article>
          <article class="metric-card">
            <span>默认窗口</span>
            <strong>{{ systemSettings.analysis.default_minutes }} 分钟</strong>
            <small>基线 {{ systemSettings.analysis.baseline_minutes }} 分钟</small>
          </article>
          <article class="metric-card">
            <span>登录保护</span>
            <strong>{{ systemSettings.security.auth_enabled ? '已启用' : '未启用' }}</strong>
            <small>会话 {{ systemSettings.security.session_ttl_hours }} 小时</small>
          </article>
          <article class="metric-card">
            <span>通知集成</span>
            <strong>{{ systemSettings.notification.enabled ? '已启用' : '未启用' }}</strong>
            <small>{{ systemSettings.notification.provider }} / {{ severityText(systemSettings.notification.min_severity) }}</small>
          </article>
        </section>
        <section class="tables-grid analysis-grid">
          <section class="table-panel">
            <div class="panel-heading">
              <h2>大模型配置</h2>
              <span>{{ systemSettings.ai.api_key_set ? systemSettings.ai.api_key_masked : '未设置 Key' }}</span>
            </div>
            <div class="asset-editor-grid">
              <label><span>AI 模式</span><select v-model="systemSettings.ai.mode"><option value="disabled">关闭</option><option value="local_mock">本地模板</option><option value="openai">OpenAI 兼容</option></select></label>
              <label><span>Provider</span><input v-model="systemSettings.ai.provider" placeholder="openai / deepseek / qwen / openai_compatible" /></label>
              <label><span>模型</span><input v-model="systemSettings.ai.model" placeholder="gpt-4.1-mini / deepseek-chat" /></label>
              <label><span>Base URL</span><input v-model="systemSettings.ai.base_url" placeholder="https://api.example.com/v1" /></label>
              <label><span>API Key</span><input v-model="systemSettings.ai.api_key" type="password" :placeholder="systemSettings.ai.api_key_set ? systemSettings.ai.api_key_masked : '输入新 API Key'" /></label>
              <label><span>上下文行数</span><input v-model.number="systemSettings.ai.max_context_rows" type="number" min="1" max="200" /></label>
              <label><span>超时秒数</span><input v-model.number="systemSettings.ai.timeout_seconds" type="number" min="1" max="120" /></label>
              <label><span>温度</span><input v-model.number="systemSettings.ai.temperature" type="number" min="0" max="2" step="0.1" /></label>
            </div>
            <label class="check-row"><input v-model="systemSettings.ai.enabled_summaries" type="checkbox" /> 启用页面 AI 摘要</label>
            <p v-if="settingsTestResult" class="muted-text" :class="{ positive: settingsTestResult.ok, negative: !settingsTestResult.ok }">{{ settingsTestResult.message }}</p>
          </section>
          <section class="table-panel">
            <div class="panel-heading">
              <h2>分析配置</h2>
              <span>{{ systemSettings.analysis.bandwidth_mbps.toLocaleString() }} Mbps</span>
            </div>
            <div class="asset-editor-grid">
              <label><span>默认观察窗口</span><input v-model.number="systemSettings.analysis.default_minutes" type="number" min="5" max="10080" /></label>
              <label><span>基线历史跨度</span><input v-model.number="systemSettings.analysis.baseline_minutes" type="number" min="10" max="10080" /></label>
              <label><span>偏离警告倍数</span><input v-model.number="systemSettings.analysis.baseline_deviation_warning" type="number" min="1.1" max="20" step="0.1" /></label>
              <label><span>偏离严重倍数</span><input v-model.number="systemSettings.analysis.baseline_deviation_critical" type="number" min="1.2" max="50" step="0.1" /></label>
              <label><span>新增对象最小字节</span><input v-model.number="systemSettings.analysis.baseline_min_bytes" type="number" min="1" /></label>
              <label><span>链路带宽 Mbps</span><input v-model.number="systemSettings.analysis.bandwidth_mbps" type="number" min="1" /></label>
              <label><span>报表默认窗口</span><input v-model.number="systemSettings.analysis.report_default_minutes" type="number" min="5" max="10080" /></label>
            </div>
          </section>
        </section>
        <section class="tables-grid analysis-grid">
          <section class="table-panel">
            <div class="panel-heading">
              <h2>安全与权限</h2>
              <span>{{ systemSettings.security.admin_password_set ? '管理员密码已设置' : '免登录' }}</span>
            </div>
            <div class="asset-editor-grid">
              <label><span>管理员密码</span><input v-model="systemSettings.security.admin_password" type="password" :placeholder="systemSettings.security.admin_password_set ? '留空保持原密码' : '设置管理员密码'" /></label>
              <label><span>观察员密码</span><input v-model="systemSettings.security.readonly_password" type="password" :placeholder="systemSettings.security.readonly_password_set ? '留空保持原密码' : '设置只读密码'" /></label>
              <label><span>会话时长小时</span><input v-model.number="systemSettings.security.session_ttl_hours" type="number" min="1" max="168" /></label>
            </div>
            <label class="check-row"><input v-model="systemSettings.security.auth_enabled" type="checkbox" /> 启用控制台登录保护</label>
            <label class="check-row"><input v-model="systemSettings.security.readonly_enabled" type="checkbox" /> 启用观察员只读角色</label>
            <label class="check-row"><input v-model="systemSettings.security.require_audit_for_write" type="checkbox" /> 写操作强制记录审计</label>
            <label class="check-row"><input v-model="systemSettings.security.allow_frontend_secrets" type="checkbox" /> 允许前端维护敏感配置</label>
          </section>
          <section class="table-panel">
            <div class="panel-heading">
              <h2>通知集成</h2>
              <span>{{ systemSettings.notification.webhook_token_set ? systemSettings.notification.webhook_token_masked : '无 Token' }}</span>
            </div>
            <div class="asset-editor-grid">
              <label><span>Provider</span><select v-model="systemSettings.notification.provider"><option value="webhook">Webhook</option><option value="feishu">飞书</option><option value="dingtalk">钉钉</option><option value="wechat_work">企业微信</option></select></label>
              <label><span>Webhook URL</span><input v-model="systemSettings.notification.webhook_url" placeholder="https://..." /></label>
              <label><span>Webhook Token</span><input v-model="systemSettings.notification.webhook_token" type="password" :placeholder="systemSettings.notification.webhook_token_set ? systemSettings.notification.webhook_token_masked : '可选 Bearer Token'" /></label>
              <label><span>最低级别</span><select v-model="systemSettings.notification.min_severity"><option value="info">提示</option><option value="warning">警告</option><option value="critical">严重</option></select></label>
            </div>
            <label class="check-row"><input v-model="systemSettings.notification.enabled" type="checkbox" /> 启用通知</label>
            <label class="check-row"><input v-model="systemSettings.notification.notify_on_incident" type="checkbox" /> 事件通知</label>
            <label class="check-row"><input v-model="systemSettings.notification.notify_on_report" type="checkbox" /> 报表通知</label>
            <p v-if="webhookTestResult" class="muted-text" :class="{ positive: webhookTestResult.ok, negative: !webhookTestResult.ok }">{{ webhookTestResult.message }}</p>
          </section>
        </section>
        <section class="tables-grid analysis-grid">
          <section class="table-panel">
            <div class="panel-heading">
              <h2>数据与存储</h2>
              <span>{{ systemSettings.data.export_enabled ? '允许导出' : '禁止导出' }}</span>
            </div>
            <div class="asset-editor-grid">
              <label><span>ClickHouse 保留天数</span><input v-model.number="systemSettings.data.clickhouse_retention_days" type="number" min="1" /></label>
              <label><span>会话保留天数</span><input v-model.number="systemSettings.data.session_retention_days" type="number" min="1" /></label>
              <label><span>审计保留天数</span><input v-model.number="systemSettings.data.audit_retention_days" type="number" min="1" /></label>
              <label><span>配置版本上限</span><input v-model.number="systemSettings.data.config_version_limit" type="number" min="1" /></label>
            </div>
            <label class="check-row"><input v-model="systemSettings.data.export_enabled" type="checkbox" /> 允许报表和配置导出</label>
          </section>
          <section class="table-panel">
            <div class="panel-heading">
              <h2>后台连接</h2>
              <span>{{ systemSettings.backend.requires_restart ? '修改后需重启' : '热更新' }}</span>
            </div>
            <div class="asset-editor-grid">
              <label><span>API 地址</span><input v-model="systemSettings.backend.api_addr" placeholder="0.0.0.0:8080" /></label>
              <label><span>ClickHouse URL</span><input v-model="systemSettings.backend.clickhouse_url" placeholder="http://default:***@clickhouse:8123" /></label>
              <label><span>Redis 地址</span><input v-model="systemSettings.backend.redis_addr" placeholder="redis:6379" /></label>
              <label><span>数据库</span><input v-model="systemSettings.backend.database" placeholder="nexaflow" /></label>
            </div>
          </section>
        </section>
        <section class="tables-grid analysis-grid">
          <section class="table-panel">
            <div class="panel-heading">
              <h2>配置导出</h2>
              <span>{{ settingsExportText ? '已生成' : '未生成' }}</span>
            </div>
            <textarea v-model="settingsExportText" class="asset-note-field" rows="10" readonly placeholder="点击导出配置生成 JSON"></textarea>
          </section>
          <section class="table-panel">
            <div class="panel-heading">
              <h2>配置导入</h2>
              <span>导入后写入审计和配置版本</span>
            </div>
            <textarea v-model="settingsImportText" class="asset-note-field" rows="10" placeholder="粘贴系统设置 JSON"></textarea>
            <button class="command-button" type="button" :disabled="!canWrite || !settingsImportText.trim()" @click="importSettings">导入系统设置</button>
          </section>
        </section>
      </template>

      <template v-else>
        <section class="toolbar-panel capture-control">
          <label>
            <span>采集模式</span>
            <select v-model="selectedMode">
              <option value="live_pcap">网卡采集</option>
              <option value="pcap_replay">PCAP 回放</option>
              <option value="mock">模拟流量</option>
            </select>
          </label>
          <label>
            <span>采集网卡</span>
            <select v-model="selectedIface">
              <option v-for="item in interfaces" :key="item.name" :value="item.name">
                {{ item.name }} / {{ item.state }}
              </option>
            </select>
          </label>
          <label class="filter-field">
            <span>采集过滤</span>
            <input v-model="selectedFilter" placeholder="ip or ip6 / tcp / port 443 / host 1.1.1.1" />
          </label>
          <label class="filter-field">
            <span>PCAP 文件</span>
            <input v-model="selectedPcapFile" placeholder="/var/lib/nexaflow/replay.pcap" />
          </label>
          <label>
            <span>回放倍率</span>
            <input v-model.number="selectedReplaySpeed" type="number" min="0.1" step="0.1" />
          </label>
          <label>
            <span>会话保留量</span>
            <input v-model.number="selectedSessionTopN" type="number" min="20" max="5000" step="50" />
          </label>
          <button type="button" :disabled="switching || !canWrite" @click="applyCaptureConfig">
            {{ switching ? '切换中...' : '应用采集配置' }}
          </button>
        </section>
        <section class="command-grid">
          <HealthGaugePanel :utilization="summary.utilization" :pps="pps" :online="onlineCollectorCount" :total="collectors.length" />
          <TrafficHeatmap :points="series" />
        </section>
        <section class="collector-grid">
          <article class="collector-card">
            <div class="collector-card-header">
              <span class="status-dot" :class="{ offline: systemStatus.database !== 'ok' }"></span>
              <strong>系统状态</strong>
              <b :class="{ warning: systemStatus.database !== 'ok' }">{{ systemStatus.database === 'ok' ? '正常' : '降级' }}</b>
            </div>
            <div class="kv-list">
              <div><span>最近窗口</span><strong>{{ formatTime(systemStatus.latest_window_ts) }}</strong></div>
              <div><span>24 小时窗口</span><strong>{{ systemStatus.windows_24h.toLocaleString() }}</strong></div>
              <div><span>采集源数</span><strong>{{ systemStatus.sources_24h.toLocaleString() }}</strong></div>
              <div><span>网卡数</span><strong>{{ systemStatus.interfaces_24h.toLocaleString() }}</strong></div>
            </div>
          </article>
          <article v-for="collector in collectors" :key="collector.id" class="collector-card">
            <div class="collector-card-header">
              <span class="status-dot" :class="{ offline: collector.status !== 'online' }"></span>
              <strong>{{ collector.id }}</strong>
              <b :class="{ warning: collector.status !== 'online' }">{{ statusText(collector.status) }}</b>
            </div>
            <div class="kv-list">
              <div><span>采集源</span><strong>{{ collector.source_id }}</strong></div>
              <div><span>采集网卡</span><strong>{{ collector.iface ?? '-' }}</strong></div>
              <div><span>采集模式</span><strong>{{ modeText(collector.mode) }}</strong></div>
              <div><span>采集过滤</span><strong>{{ collector.bpf_filter ?? '-' }}</strong></div>
              <div><span>PCAP 文件</span><strong>{{ collector.pcap_file ?? '-' }}</strong></div>
              <div><span>回放倍率</span><strong>{{ collector.replay_speed ?? 1 }}x</strong></div>
              <div><span>会话保留量</span><strong>{{ (collector.session_topn ?? 500).toLocaleString() }} / 窗口</strong></div>
              <div><span>配置更新时间</span><strong>{{ formatTime(collector.updated_at ?? 0) }}</strong></div>
              <div><span>窗口大小</span><strong>5 秒</strong></div>
              <div><span>数据链路</span><strong>Redis / ClickHouse</strong></div>
            </div>
          </article>
        </section>
      </template>
    </section>
    </template>
  </main>
</template>
