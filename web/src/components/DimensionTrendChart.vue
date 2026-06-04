<script setup lang="ts">
import * as echarts from 'echarts';
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import type { DimensionPoint } from '../services/api';

const props = defineProps<{ title: string; points: DimensionPoint[] }>();
const el = ref<HTMLDivElement | null>(null);
let chart: echarts.ECharts | undefined;

const keys = computed(() => Array.from(new Set(props.points.map((point) => point.key))).slice(0, 8));

const formatBytes = (value: number) => {
  if (value >= 1024 ** 3) return `${(value / 1024 ** 3).toFixed(2)} GB`;
  if (value >= 1024 ** 2) return `${(value / 1024 ** 2).toFixed(2)} MB`;
  if (value >= 1024) return `${(value / 1024).toFixed(2)} KB`;
  return `${value.toFixed(0)} B`;
};

const render = () => {
  if (!chart || !el.value) return;
  const times = Array.from(new Set(props.points.map((point) => point.ts))).sort((a, b) => a - b);
  chart.setOption({
    color: ['#2563eb', '#38bdf8', '#818cf8', '#f59e0b', '#ef4444', '#14b8a6', '#64748b', '#a855f7'],
    grid: { left: 52, right: 22, top: 38, bottom: 42 },
    tooltip: {
      trigger: 'axis',
      formatter: (params: any) => {
        const lines = [`${params[0]?.axisValue ?? ''}`];
        for (const item of params) {
          lines.push(`${item.marker}${item.seriesName}: ${formatBytes(item.value)}`);
        }
        return lines.join('<br/>');
      }
    },
    legend: { top: 0, right: 6, textStyle: { color: '#475569' } },
    xAxis: {
      type: 'category',
      data: times.map((ts) => new Date(ts * 1000).toLocaleTimeString()),
      axisLine: { lineStyle: { color: '#c7d1dd' } },
      axisLabel: { color: '#64748b' }
    },
    yAxis: {
      type: 'value',
      axisLabel: { color: '#64748b', formatter: (value: number) => formatBytes(value) },
      splitLine: { lineStyle: { color: '#e2e8f0' } }
    },
    series: keys.value.map((key) => {
      const byTs = new Map(props.points.filter((point) => point.key === key).map((point) => [point.ts, point.bytes]));
      return {
        name: key,
        type: 'line',
        smooth: true,
        symbol: 'circle',
        symbolSize: 5,
        lineStyle: { width: 2.5 },
        areaStyle: { opacity: keys.value.length === 1 ? 0.14 : 0 },
        data: times.map((ts) => byTs.get(ts) ?? 0)
      };
    })
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

watch(() => props.points, render, { deep: true });
</script>

<template>
  <section class="dimension-trend-card">
    <div class="chart-card-title">
      <span>Drilldown Trend</span>
      <h2>{{ title }}</h2>
    </div>
    <div ref="el" class="dimension-chart"></div>
  </section>
</template>

<style scoped>
.dimension-trend-card {
  min-height: 330px;
  display: grid;
  align-content: start;
  gap: 10px;
  padding: 16px;
  border: 1px solid #dbe7f3;
  border-radius: 8px;
  background: linear-gradient(180deg, #ffffff, #f8fbff);
  box-shadow: 0 12px 28px rgba(30, 64, 175, 0.07);
}

.chart-card-title span {
  color: #2563eb;
  font-size: 12px;
  font-weight: 800;
}

.chart-card-title h2 {
  margin-top: 4px;
}

.dimension-chart {
  height: 270px;
  min-height: 270px;
}
</style>
