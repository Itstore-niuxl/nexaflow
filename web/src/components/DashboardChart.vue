<script setup lang="ts">
import * as echarts from 'echarts';
import { onMounted, onUnmounted, ref, watch } from 'vue';
import type { SeriesPoint } from '../services/api';

const props = defineProps<{ points: SeriesPoint[] }>();
const el = ref<HTMLDivElement | null>(null);
let chart: echarts.ECharts | undefined;

const render = () => {
  if (!chart || !el.value) return;
  chart.setOption({
    backgroundColor: 'transparent',
    grid: { left: 48, right: 18, top: 24, bottom: 36 },
    tooltip: { trigger: 'axis' },
    xAxis: {
      type: 'category',
      data: props.points.map((point) => new Date(point.ts * 1000).toLocaleTimeString()),
      axisLine: { lineStyle: { color: '#c7d1dd' } },
      axisLabel: { color: '#67768a' }
    },
    yAxis: {
      type: 'value',
      axisLabel: { color: '#67768a' },
      splitLine: { lineStyle: { color: '#e5eaf0' } }
    },
    series: [
      {
        name: 'Mbps',
        type: 'line',
        smooth: true,
        symbol: 'none',
        lineStyle: { width: 3, color: '#2563eb' },
        areaStyle: { color: 'rgba(37, 99, 235, 0.14)' },
        data: props.points.map((point) => Number(((point.bytes * 8) / 60 / 1000 / 1000).toFixed(2)))
      }
    ]
  });
};

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

const resize = () => chart?.resize();
</script>

<template>
  <section>
    <h2>流量趋势</h2>
    <div ref="el" class="chart"></div>
  </section>
</template>
