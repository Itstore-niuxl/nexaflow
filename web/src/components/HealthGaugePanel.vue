<script setup lang="ts">
import * as echarts from 'echarts';
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';

const props = defineProps<{ utilization: number; pps: number; online: number; total: number }>();
const el = ref<HTMLDivElement | null>(null);
let chart: echarts.ECharts | undefined;

const collectorRatio = computed(() => (props.total > 0 ? props.online / props.total : 0));
const score = computed(() => {
  const linkScore = Math.max(0, 1 - props.utilization);
  return Math.round(((linkScore * 0.55 + collectorRatio.value * 0.45) * 100));
});

const render = () => {
  if (!chart || !el.value) return;
  chart.setOption({
    series: [
      {
        type: 'gauge',
        startAngle: 210,
        endAngle: -30,
        min: 0,
        max: 100,
        radius: '92%',
        progress: {
          show: true,
          width: 14,
          itemStyle: { color: '#2563eb' }
        },
        axisLine: {
          lineStyle: { width: 14, color: [[1, '#e2e8f0']] }
        },
        pointer: { show: false },
        axisTick: { show: false },
        splitLine: { show: false },
        axisLabel: { show: false },
        anchor: { show: false },
        detail: {
          valueAnimation: true,
          formatter: '{value}',
          color: '#172033',
          fontSize: 34,
          fontWeight: 800,
          offsetCenter: [0, '8%']
        },
        title: {
          show: true,
          offsetCenter: [0, '42%'],
          color: '#64748b',
          fontSize: 12
        },
        data: [{ value: score.value, name: '健康评分' }]
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

watch(() => [props.utilization, props.pps, props.online, props.total], render);
</script>

<template>
  <section class="health-panel">
    <div class="chart-card-title">
      <span>Health Gauge</span>
      <h2>采集健康</h2>
    </div>
    <div class="health-grid">
      <div ref="el" class="health-gauge"></div>
      <div class="health-kpis">
        <div>
          <span>链路利用率</span>
          <strong>{{ (utilization * 100).toFixed(2) }}%</strong>
        </div>
        <div>
          <span>实时 PPS</span>
          <strong>{{ pps.toLocaleString() }}</strong>
        </div>
        <div>
          <span>采集器在线</span>
          <strong>{{ online }} / {{ total }}</strong>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.health-panel {
  min-height: 286px;
  display: grid;
  align-content: start;
  gap: 10px;
  padding: 16px;
  border: 1px solid #dbe7f3;
  border-radius: 8px;
  background:
    radial-gradient(circle at 18% 24%, rgba(59, 130, 246, 0.14), transparent 34%),
    linear-gradient(180deg, #ffffff, #f8fbff);
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

.health-grid {
  display: grid;
  grid-template-columns: 190px minmax(0, 1fr);
  gap: 14px;
  align-items: center;
}

.health-gauge {
  height: 198px;
  min-height: 198px;
}

.health-kpis {
  display: grid;
  gap: 10px;
}

.health-kpis div {
  display: grid;
  gap: 4px;
  padding: 12px;
  border: 1px solid #dbe7f3;
  border-radius: 8px;
  background: rgba(255, 255, 255, 0.72);
}

.health-kpis span {
  color: #64748b;
  font-size: 12px;
  font-weight: 700;
}

.health-kpis strong {
  color: #172033;
  font-size: 18px;
}

@media (max-width: 760px) {
  .health-grid {
    grid-template-columns: 1fr;
  }
}
</style>
