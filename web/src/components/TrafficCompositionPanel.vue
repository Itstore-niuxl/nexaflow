<script setup lang="ts">
import * as echarts from 'echarts';
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import type { TopItem } from '../services/api';

const props = defineProps<{ protocols: TopItem[]; ports: TopItem[]; directions: TopItem[]; packetSizes: TopItem[] }>();
const el = ref<HTMLDivElement | null>(null);
let chart: echarts.ECharts | undefined;

const formatBytes = (value: number) => {
  if (value >= 1024 ** 3) return `${(value / 1024 ** 3).toFixed(2)} GB`;
  if (value >= 1024 ** 2) return `${(value / 1024 ** 2).toFixed(2)} MB`;
  if (value >= 1024) return `${(value / 1024).toFixed(2)} KB`;
  return `${value.toFixed(0)} B`;
};

const totalDirectionBytes = computed(() => Math.max(props.directions.reduce((sum, row) => sum + row.bytes, 0), 1));
const dominantPacketSize = computed(() => props.packetSizes[0]?.key ?? '-');
const dominantProtocol = computed(() => props.protocols[0]?.key ?? '-');
const portRows = computed(() => props.ports.slice(0, 5));
const maxPortBytes = computed(() => Math.max(...portRows.value.map((row) => row.bytes), 1));
const rowWidth = (value: number) => `${Math.max(8, Math.round((value / maxPortBytes.value) * 100))}%`;
const directionWidth = (value: number) => `${Math.max(8, Math.round((value / totalDirectionBytes.value) * 100))}%`;

const render = () => {
  if (!chart || !el.value) return;
  const protocolData = (props.protocols.length ? props.protocols : [{ key: '无数据', bytes: 1, packets: 0 }]).slice(0, 5);
  chart.setOption({
    color: ['#2563eb', '#38bdf8', '#818cf8', '#f59e0b', '#ef4444'],
    tooltip: {
      trigger: 'item',
      formatter: (params: any) => `${params.name}<br/>${formatBytes(params.value)}`
    },
    series: [
      {
        type: 'pie',
        radius: ['54%', '78%'],
        center: ['50%', '52%'],
        avoidLabelOverlap: true,
        label: {
          color: '#42526a',
          formatter: '{b}'
        },
        labelLine: { lineStyle: { color: '#c7d1dd' } },
        data: protocolData.map((item) => ({ name: item.key, value: item.bytes }))
      }
    ]
  });
};

const resize = () => chart?.resize();

onMounted(() => {
  if (!el.value) return;
  chart = echarts.init(el.value);
  render();
  window.addEventListener('resize', resize);
});

onUnmounted(() => {
  window.removeEventListener('resize', resize);
  chart?.dispose();
});

watch(() => [props.protocols, props.ports, props.directions, props.packetSizes], render, { deep: true });
</script>

<template>
  <section class="composition-panel">
    <div class="panel-title">
      <div>
        <span>Traffic Mix</span>
        <h2>流量结构</h2>
      </div>
      <strong>{{ dominantProtocol }}</strong>
    </div>
    <div class="composition-grid">
      <div ref="el" class="composition-chart"></div>
      <div class="composition-side">
        <div class="mini-stat">
          <span>主导包长</span>
          <strong>{{ dominantPacketSize }}</strong>
        </div>
        <div class="bar-list">
          <div v-for="row in portRows" :key="row.key" class="bar-row">
            <div>
              <span>{{ row.key }}</span>
              <b>{{ formatBytes(row.bytes) }}</b>
            </div>
            <i><em :style="{ width: rowWidth(row.bytes) }"></em></i>
          </div>
        </div>
        <div class="direction-list">
          <div v-for="row in directions.slice(0, 4)" :key="row.key">
            <span>{{ row.key }}</span>
            <i><em :style="{ width: directionWidth(row.bytes) }"></em></i>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.composition-panel {
  min-height: 360px;
  display: grid;
  align-content: start;
  gap: 12px;
  padding: 16px;
  border: 1px solid #dce3eb;
  border-radius: 8px;
  background: #ffffff;
  box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
}

.panel-title {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 12px;
}

.panel-title span {
  color: #67768a;
  font-size: 12px;
  font-weight: 760;
}

.panel-title h2 {
  margin-top: 4px;
}

.panel-title strong {
  color: #2563eb;
  font-size: 17px;
  text-transform: uppercase;
}

.composition-grid {
  display: grid;
  grid-template-columns: minmax(190px, 0.95fr) minmax(0, 1fr);
  gap: 14px;
}

.composition-chart {
  height: 230px;
  min-height: 230px;
}

.composition-side {
  display: grid;
  gap: 12px;
}

.mini-stat {
  padding: 12px;
  border: 1px solid #dce3eb;
  border-radius: 8px;
  background: #f8fafc;
}

.mini-stat span,
.bar-row span,
.direction-list span {
  color: #67768a;
  font-size: 12px;
  font-weight: 700;
}

.mini-stat strong {
  display: block;
  margin-top: 5px;
  color: #172033;
  font-size: 20px;
}

.bar-list,
.direction-list {
  display: grid;
  gap: 10px;
}

.bar-row div {
  display: flex;
  justify-content: space-between;
  gap: 10px;
}

.bar-row b {
  color: #172033;
  font-size: 12px;
}

.bar-row i,
.direction-list i {
  display: block;
  height: 7px;
  overflow: hidden;
  border-radius: 999px;
  background: #e5eaf0;
}

.bar-row em,
.direction-list em {
  display: block;
  height: 100%;
  border-radius: inherit;
  background: linear-gradient(90deg, #1d4ed8, #38bdf8);
}

.direction-list div {
  display: grid;
  gap: 6px;
}

@media (max-width: 760px) {
  .composition-grid {
    grid-template-columns: 1fr;
  }
}
</style>
