<script setup lang="ts">
import * as echarts from 'echarts';
import { onMounted, onUnmounted, ref, watch } from 'vue';
import type { SeriesPoint } from '../services/api';

const props = defineProps<{ points: SeriesPoint[] }>();
const el = ref<HTMLDivElement | null>(null);
let chart: echarts.ECharts | undefined;

const rows = ['吞吐', '包数'];

const render = () => {
  if (!chart || !el.value) return;
  const points = props.points.slice(-36);
  const maxBytes = Math.max(...points.map((point) => point.bytes), 1);
  const maxPackets = Math.max(...points.map((point) => point.packets), 1);
  const data = points.flatMap((point, index) => [
    [index, 0, Number(((point.bytes / maxBytes) * 100).toFixed(2))],
    [index, 1, Number(((point.packets / maxPackets) * 100).toFixed(2))]
  ]);
  chart.setOption({
    tooltip: {
      position: 'top',
      formatter: (params: any) => `${rows[params.value[1]]}<br/>强度 ${params.value[2]}%`
    },
    grid: { left: 42, right: 12, top: 18, bottom: 34 },
    xAxis: {
      type: 'category',
      data: points.map((point) => new Date(point.ts * 1000).toLocaleTimeString()),
      axisLabel: { color: '#67768a', interval: Math.max(0, Math.floor(points.length / 6)) },
      axisLine: { lineStyle: { color: '#c7d1dd' } }
    },
    yAxis: {
      type: 'category',
      data: rows,
      axisLabel: { color: '#42526a' },
      axisLine: { show: false },
      axisTick: { show: false }
    },
    visualMap: {
      min: 0,
      max: 100,
      show: false,
      inRange: { color: ['#eef2f7', '#bfdbfe', '#2563eb', '#f59e0b'] }
    },
    series: [
      {
        type: 'heatmap',
        data,
        itemStyle: { borderColor: '#ffffff', borderWidth: 2, borderRadius: 4 }
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

watch(() => props.points, render, { deep: true });
</script>

<template>
  <section class="heatmap-panel">
    <div class="panel-title">
      <div>
        <span>Window Heatmap</span>
        <h2>实时强度热力</h2>
      </div>
    </div>
    <div ref="el" class="heatmap-chart"></div>
  </section>
</template>

<style scoped>
.heatmap-panel {
  min-height: 250px;
  display: grid;
  align-content: start;
  gap: 10px;
  padding: 16px;
  border: 1px solid #dce3eb;
  border-radius: 8px;
  background: #ffffff;
  box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
}

.panel-title span {
  color: #67768a;
  font-size: 12px;
  font-weight: 760;
}

.panel-title h2 {
  margin-top: 4px;
}

.heatmap-chart {
  height: 190px;
  min-height: 190px;
}
</style>
