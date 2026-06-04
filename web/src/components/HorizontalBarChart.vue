<script setup lang="ts">
import * as echarts from 'echarts';
import { onMounted, onUnmounted, ref, watch } from 'vue';
import type { TopItem } from '../services/api';

const props = withDefaults(
  defineProps<{
    title: string;
    eyebrow?: string;
    items: TopItem[];
    unit?: 'bytes' | 'count';
  }>(),
  { eyebrow: 'Ranking', unit: 'bytes' }
);

const el = ref<HTMLDivElement | null>(null);
let chart: echarts.ECharts | undefined;

const formatBytes = (value: number) => {
  if (value >= 1024 ** 3) return `${(value / 1024 ** 3).toFixed(2)} GB`;
  if (value >= 1024 ** 2) return `${(value / 1024 ** 2).toFixed(2)} MB`;
  if (value >= 1024) return `${(value / 1024).toFixed(2)} KB`;
  return `${value.toFixed(0)} B`;
};

const formatValue = (value: number) => (props.unit === 'count' ? value.toLocaleString() : formatBytes(value));

const render = () => {
  if (!chart || !el.value) return;
  const rows = (props.items.length ? props.items : [{ key: '暂无数据', bytes: 0, packets: 0 }]).slice(0, 8).reverse();
  chart.setOption({
    color: ['#2563eb'],
    grid: { left: 96, right: 28, top: 12, bottom: 12 },
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      formatter: (params: any) => `${params[0].name}<br/>${formatValue(params[0].value)}`
    },
    xAxis: {
      type: 'value',
      axisLabel: { color: '#64748b' },
      splitLine: { lineStyle: { color: '#e2e8f0' } }
    },
    yAxis: {
      type: 'category',
      data: rows.map((row) => row.key),
      axisLabel: {
        color: '#334155',
        width: 86,
        overflow: 'truncate'
      },
      axisLine: { show: false },
      axisTick: { show: false }
    },
    series: [
      {
        type: 'bar',
        data: rows.map((row) => row.bytes),
        barWidth: 12,
        itemStyle: {
          borderRadius: [0, 8, 8, 0],
          color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [
            { offset: 0, color: '#1d4ed8' },
            { offset: 1, color: '#38bdf8' }
          ])
        },
        label: {
          show: true,
          position: 'right',
          color: '#1e293b',
          formatter: (params: any) => formatValue(params.value)
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

watch(() => [props.items, props.unit, props.title], render, { deep: true });
</script>

<template>
  <section class="chart-card">
    <div class="chart-card-title">
      <span>{{ eyebrow }}</span>
      <h2>{{ title }}</h2>
    </div>
    <div ref="el" class="bar-chart"></div>
  </section>
</template>

<style scoped>
.chart-card {
  min-height: 286px;
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

.bar-chart {
  height: 226px;
  min-height: 226px;
}
</style>
