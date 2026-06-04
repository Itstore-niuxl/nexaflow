<script setup lang="ts">
import * as echarts from 'echarts';
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import type { MatrixRow } from '../services/api';

const props = defineProps<{ rows: MatrixRow[] }>();
const el = ref<HTMLDivElement | null>(null);
let chart: echarts.ECharts | undefined;

const srcList = computed(() => Array.from(new Set(props.rows.slice(0, 30).map((row) => row.src))).slice(0, 8));
const dstList = computed(() => Array.from(new Set(props.rows.slice(0, 30).map((row) => row.dst))).slice(0, 8));

const formatBytes = (value: number) => {
  if (value >= 1024 ** 3) return `${(value / 1024 ** 3).toFixed(2)} GB`;
  if (value >= 1024 ** 2) return `${(value / 1024 ** 2).toFixed(2)} MB`;
  if (value >= 1024) return `${(value / 1024).toFixed(2)} KB`;
  return `${value.toFixed(0)} B`;
};

const render = () => {
  if (!chart || !el.value) return;
  const srcs = srcList.value.length ? srcList.value : ['源端'];
  const dsts = dstList.value.length ? dstList.value : ['目的端'];
  const maxBytes = Math.max(...props.rows.map((row) => row.bytes), 1);
  const data = props.rows
    .slice(0, 30)
    .map((row) => [srcs.indexOf(row.src), dsts.indexOf(row.dst), row.bytes, row.packets, row.src, row.dst])
    .filter((row) => Number(row[0]) >= 0 && Number(row[1]) >= 0);

  chart.setOption({
    tooltip: {
      formatter: (params: any) => `${params.value[4]} -> ${params.value[5]}<br/>${formatBytes(params.value[2])}<br/>${params.value[3].toLocaleString()} 包`
    },
    grid: { left: 96, right: 24, top: 24, bottom: 74 },
    xAxis: {
      type: 'category',
      data: srcs,
      axisLabel: { color: '#475569', rotate: 35 },
      splitLine: { show: true, lineStyle: { color: '#e2e8f0' } }
    },
    yAxis: {
      type: 'category',
      data: dsts,
      axisLabel: { color: '#475569' },
      splitLine: { show: true, lineStyle: { color: '#e2e8f0' } }
    },
    series: [
      {
        type: 'scatter',
        data,
        symbolSize: (value: any) => 10 + Math.sqrt(value[2] / maxBytes) * 34,
        itemStyle: {
          color: '#2563eb',
          opacity: 0.72,
          shadowBlur: 14,
          shadowColor: 'rgba(37, 99, 235, 0.28)'
        }
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

watch(() => props.rows, render, { deep: true });
</script>

<template>
  <section class="matrix-card">
    <div class="chart-card-title">
      <span>Flow Matrix</span>
      <h2>主机关系矩阵</h2>
    </div>
    <div ref="el" class="matrix-chart"></div>
  </section>
</template>

<style scoped>
.matrix-card {
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

.matrix-chart {
  height: 270px;
  min-height: 270px;
}
</style>
