<script setup lang="ts">
import {
  Activity,
  AlertTriangle,
  ChartNoAxesCombined,
  CircleGauge,
  Database,
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
  type AssetMetadata,
  type AssetRow,
  type Collector,
  type CollectorConfig,
  type DimensionPoint,
  type IPProfile,
  type MatrixRow,
  type NetworkInterface,
  type ObjectRelations,
  type DirectionPoint,
  type PortProfile,
  type PortPoint,
  type ProtocolPoint,
  type SearchResult,
  type SecurityInsight,
  type ServiceExposure,
  type ServiceMap,
  type SeriesPoint,
  type Summary,
  type SystemStatus,
  type TrafficAnalysis,
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
const interfaces = ref<NetworkInterface[]>([]);
const systemStatus = ref<SystemStatus>({ database: 'unknown', latest_window_ts: 0, windows_24h: 0, sources_24h: 0, interfaces_24h: 0 });
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
const serviceExposure = ref<ServiceExposure[]>([]);
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
const searchTerm = ref('10.2.0.12');
const searchResults = ref<SearchResult[]>([]);
const assets = ref<AssetRow[]>([]);
const assetEditor = ref<AssetMetadata | null>(null);
const assetTagsText = ref('');
const securityInsights = ref<SecurityInsight[]>([]);
const trafficChanges = ref<TrafficChange[]>([]);
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
const degraded = ref(false);
const loading = ref(false);
const switching = ref(false);
const savingAlerts = ref(false);
const savingAsset = ref(false);
const handlingAlert = ref(false);
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
const trendDimension = ref('service');
const trendKey = ref('');
const trendDirection = ref('src');
const whitelistSubject = ref('');
const exposureSearch = ref('');
const exposureRiskFilter = ref('all');
const exposureCategoryFilter = ref('all');
let timer: number | undefined;

const navGroups = [
  {
    title: '监控',
    items: [
      { id: 'dashboard', label: '总览大屏', icon: LayoutDashboard },
      { id: 'realtime', label: '实时监控', icon: MonitorDot },
      { id: 'traffic', label: '流量剖析', icon: ChartNoAxesCombined }
    ]
  },
  {
    title: '分析',
    items: [
      { id: 'analysis', label: '流向分析', icon: Route },
      { id: 'topology', label: '服务拓扑', icon: Network },
      { id: 'topn', label: 'TopN 分析', icon: ListOrdered },
      { id: 'profile', label: '对象画像', icon: Radar },
      { id: 'port', label: '端口画像', icon: CircleGauge }
    ]
  },
  {
    title: '治理',
    items: [
      { id: 'exposure', label: '服务暴露', icon: ServerCog },
      { id: 'assets', label: '资产发现', icon: HardDrive },
      { id: 'security', label: '风险线索', icon: Shield },
      { id: 'alerts', label: '告警中心', icon: AlertTriangle }
    ]
  },
  {
    title: '工具',
    items: [
      { id: 'search', label: '检索分析', icon: Search },
      { id: 'history', label: '历史回放', icon: History },
      { id: 'collectors', label: '采集器', icon: Settings2 }
    ]
  }
];

const viewMeta: Record<string, { title: string; subtitle: string }> = {
  dashboard: { title: '流量总览', subtitle: '近实时流量、采集健康和关键对象排行' },
  realtime: { title: '实时监控', subtitle: '采集窗口、吞吐、包速率和采集器健康状态' },
  traffic: { title: '流量剖析', subtitle: '观察基线、峰值、P95、方向、协议、端口和包长结构' },
  analysis: { title: '流向分析', subtitle: '按主机对、会话、端口和协议拆解实时流量路径' },
  topology: { title: '服务拓扑', subtitle: '基于主机对流量构建节点和链路视图' },
  exposure: { title: '服务暴露', subtitle: '识别目的 IP 上的服务端口、协议、服务类型和风险级别' },
  assets: { title: '资产发现', subtitle: '按活跃 IP 聚合收发流量、角色和最近出现时间' },
  security: { title: '风险线索', subtitle: '从重流量会话、敏感端口和主机扇出中提取排查线索' },
  profile: { title: '对象画像', subtitle: '围绕单个 IP 查看收发流量、关联主机对和活跃会话' },
  port: { title: '端口画像', subtitle: '围绕目的端口查看流量规模和关联会话' },
  topn: { title: 'TopN 分析', subtitle: '按 IP、端口、协议和会话维度定位主要流量对象' },
  alerts: { title: '告警中心', subtitle: '查看阈值、采集健康和异常事件' },
  search: { title: '检索分析', subtitle: '按 IP、端口、主机对或会话关键字检索流量对象' },
  history: { title: '历史回放', subtitle: '回看采集窗口明细，辅助排查短时峰值' },
  collectors: { title: '采集器', subtitle: '查看采集源、运行模式和服务状态' }
};

const pageTitle = computed(() => viewMeta[currentView.value]?.title ?? '流量总览');
const pageSubtitle = computed(() => viewMeta[currentView.value]?.subtitle ?? '近实时流量、采集健康和关键对象排行');
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
      windowsRes,
      alertConfigRes,
      matrixRes,
      serviceMapRes,
      serviceExposureRes,
      protocolSeriesRes,
      portSeriesRes,
      directionSeriesRes,
      assetsRes,
      securityRes,
      trafficAnalysisRes,
      trafficChangesRes
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
      api.windows(minutes, 80),
      api.alertConfig(),
      api.matrix(minutes, 80),
      api.serviceMap(minutes, 80),
      api.serviceExposure(minutes, 120),
      api.protocolTimeseries(minutes),
      api.portTimeseries(minutes, 8),
      api.directionTimeseries(minutes),
      api.assets(minutes, 100),
      api.securityInsights(minutes, 100),
      api.trafficAnalysis(minutes),
      api.trafficChanges(minutes, 30)
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
    historyWindows.value = windowsRes.data;
    alertConfig.value = alertConfigRes.data;
    matrixRows.value = matrixRes.data;
    serviceMap.value = serviceMapRes.data;
    serviceExposure.value = serviceExposureRes.data;
    protocolSeries.value = protocolSeriesRes.data;
    portSeries.value = portSeriesRes.data;
    directionSeries.value = directionSeriesRes.data;
    assets.value = assetsRes.data;
    securityInsights.value = securityRes.data;
    trafficAnalysis.value = trafficAnalysisRes.data;
    trafficChanges.value = trafficChangesRes.data;
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
      windowsRes.degraded ||
      matrixRes.degraded ||
      serviceMapRes.degraded ||
      serviceExposureRes.degraded ||
      protocolSeriesRes.degraded ||
      portSeriesRes.degraded ||
      directionSeriesRes.degraded ||
      assetsRes.degraded ||
      securityRes.degraded ||
      trafficAnalysisRes.degraded ||
      trafficChangesRes.degraded;
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
    collectors.value = [{ id: 'dev-collector-01', source_id: 'dev-source-01', status: 'offline', mode: 'mock', bpf_filter: 'ip or ip6', updated_at: now }];
    interfaces.value = [{ name: 'eth0', state: 'up', type: 'interface' }];
    systemStatus.value = { database: 'degraded', latest_window_ts: now, windows_24h: 0, sources_24h: 0, interfaces_24h: 0 };
    alertConfig.value = { flow_bytes: 20480, flow_share: 0.3, source_packets: 50, link_utilization: 0.8 };
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
      }
    ];
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
    degraded.value = true;
  } finally {
    loading.value = false;
  }
};

onMounted(() => {
  void refresh();
  timer = window.setInterval(refresh, 5000);
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

const formatRate = (bytes: number, seconds = rangeSeconds.value) => `${((bytes * 8) / seconds / 1000 / 1000).toFixed(2)} Mbps`;

const pps = computed(() => Math.round(summary.value.packets / rangeSeconds.value));
const onlineCollectorCount = computed(() => collectors.value.filter((collector) => collector.status === 'online').length);

const profileTotalBytes = computed(() => ipProfile.value.inbound_bytes + ipProfile.value.outbound_bytes);
const profileTotalPackets = computed(() => ipProfile.value.inbound_packets + ipProfile.value.outbound_packets);
const topologyTotalBytes = computed(() => matrixRows.value.reduce((sum, row) => sum + row.bytes, 0));
const topologyNodeCount = computed(() => serviceMap.value.nodes.length);
const topTopologyLink = computed(() => matrixRows.value[0]);
const exposedServiceCount = computed(() => serviceExposure.value.length);
const highRiskServiceCount = computed(() => serviceExposure.value.filter((row) => row.risk === 'critical' || row.risk === 'high').length);
const unknownServiceCount = computed(() => serviceExposure.value.filter((row) => row.risk === 'observe').length);
const exposureTotalBytes = computed(() => serviceExposure.value.reduce((sum, row) => sum + row.bytes, 0));
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
const exposureRiskItems = computed(() => aggregateTopItems(serviceExposure.value, (row) => serviceRiskText(row.risk), (row) => row.bytes, (row) => row.packets));
const exposureCategoryItems = computed(() => aggregateTopItems(serviceExposure.value, (row) => row.category, (row) => row.bytes, (row) => row.packets));
const assetRoleItems = computed(() => aggregateTopItems(assets.value, (row) => row.role, (row) => row.total_bytes, (row) => row.total_packets));
const assetCriticalityItems = computed(() => aggregateTopItems(assets.value, (row) => criticalityText(row.criticality), (row) => row.total_bytes, (row) => row.total_packets));
const insightKindItems = computed(() => aggregateTopItems(securityInsights.value, (row) => insightKindText(row.kind), (row) => row.bytes, (row) => row.packets));
const alertSeverityItems = computed(() => aggregateTopItems(alerts.value, (row) => severityText(row.severity), () => 1, () => 0));
const alertStatusItems = computed(() => aggregateTopItems(alerts.value, (row) => alertStatusText(row.status), () => 1, () => 0));
const searchResultItems = computed(() => aggregateTopItems(searchResults.value, (row) => `${row.kind}: ${row.key}`, (row) => row.bytes, (row) => row.packets));
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

const changeDimensionText = (dimension: string) => {
  const labels: Record<string, string> = {
    src_ip: '源 IP',
    dst_ip: '目的 IP',
    dst_port: '目的端口',
    protocol: '协议'
  };
  return labels[dimension] ?? dimension;
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
    ecn_mark: 'ECN 标记'
  };
  return labels[kind] ?? kind;
};

const alertStatusText = (status: string) => {
  const labels: Record<string, string> = {
    open: '未处理',
    ack: '已确认',
    resolved: '已恢复'
  };
  return labels[status] ?? status;
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

const criticalityText = (value: string) => {
  const labels: Record<string, string> = {
    low: '低',
    normal: '普通',
    high: '高',
    critical: '核心'
  };
  return labels[value] ?? value ?? '普通';
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
  switching.value = true;
  try {
    const config: CollectorConfig = {
      mode: selectedMode.value,
      iface: selectedIface.value,
      source_id: `${selectedMode.value}-${selectedIface.value}`,
      bpf_filter: selectedFilter.value.trim() || 'ip or ip6',
      pcap_file: selectedPcapFile.value.trim() || '/var/lib/nexaflow/replay.pcap',
      replay_speed: selectedReplaySpeed.value || 1
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

const saveAlertConfig = async () => {
  savingAlerts.value = true;
  try {
    const result = await api.updateAlertConfig(alertConfig.value);
    alertConfig.value = result.data;
    await refresh();
  } finally {
    savingAlerts.value = false;
  }
};

const updateAlertStatus = async (alert: AlertEvent, status: string) => {
  handlingAlert.value = true;
  try {
    await api.updateAlertStatus(alert.id, status);
    await refresh();
  } finally {
    handlingAlert.value = false;
  }
};

const silenceSubject = async (subject: string) => {
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

const saveAssetMetadata = async () => {
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

const exportSelectedTopN = () => {
  const rows = [
    ['对象', '流量字节', '包数'],
    ...selectedTopN.value.map((item) => [item.key, String(item.bytes), String(item.packets)])
  ];
  exportCSV(`nexaflow-${activeTopN.value}-${selectedMinutes.value}m.csv`, rows);
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
                      :disabled="handlingAlert || isExposureSilenced(row)"
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
            <button type="button" :disabled="savingAsset" @click="saveAssetMetadata">{{ savingAsset ? '保存中...' : '保存台账' }}</button>
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
                    <button class="inline-button" type="button" @click="editAsset(asset)">编辑</button>
                    <button class="inline-button" type="button" @click="profileIP = asset.ip; currentView = 'profile'; loadProfile()">画像</button>
                  </div>
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
                  <button class="inline-button" type="button" :disabled="handlingAlert" @click="silenceSubject(item.subject)">忽略</button>
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
          <button type="button" :disabled="savingAlerts" @click="saveAlertConfig">
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
            <button type="button" :disabled="handlingAlert || !whitelistSubject.trim()" @click="addWhitelistSubject">加入白名单</button>
          </div>
          <div class="whitelist-list">
            <button
              v-for="subject in alertConfig.silenced_subjects ?? []"
              :key="subject"
              type="button"
              class="silence-chip"
              :disabled="handlingAlert"
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
                  <button class="inline-button" type="button" :disabled="handlingAlert || alert.status === 'ack'" @click="updateAlertStatus(alert, 'ack')">确认</button>
                  <button class="inline-button" type="button" :disabled="handlingAlert || alert.status === 'resolved'" @click="updateAlertStatus(alert, 'resolved')">恢复</button>
                  <button class="inline-button" type="button" :disabled="handlingAlert" @click="silenceSubject(alert.subject)">忽略</button>
                </td>
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
          <button type="button" :disabled="switching" @click="applyCaptureConfig">
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
              <div><span>配置更新时间</span><strong>{{ formatTime(collector.updated_at ?? 0) }}</strong></div>
              <div><span>窗口大小</span><strong>5 秒</strong></div>
              <div><span>数据链路</span><strong>Redis / ClickHouse</strong></div>
            </div>
          </article>
        </section>
      </template>
    </section>
  </main>
</template>
