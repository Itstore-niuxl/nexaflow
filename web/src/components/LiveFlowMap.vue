<script setup lang="ts">
import { computed } from 'vue';
import type { MatrixRow, ServiceNode } from '../services/api';

const props = defineProps<{ nodes: ServiceNode[]; links: MatrixRow[] }>();

const palette = ['#38bdf8', '#2563eb', '#60a5fa', '#818cf8', '#0ea5e9', '#93c5fd'];

const formatBytes = (value: number) => {
  if (value >= 1024 ** 3) return `${(value / 1024 ** 3).toFixed(2)} GB`;
  if (value >= 1024 ** 2) return `${(value / 1024 ** 2).toFixed(2)} MB`;
  if (value >= 1024) return `${(value / 1024).toFixed(2)} KB`;
  return `${value.toFixed(0)} B`;
};

const displayLinks = computed(() => {
  const rows = props.links.slice(0, 6);
  if (rows.length) return rows;
  const fallbackNodes = props.nodes.slice(0, 4);
  return fallbackNodes.slice(1).map((node, index) => ({
    src: fallbackNodes[0]?.ip ?? 'source',
    dst: node.ip,
    bytes: node.bytes,
    packets: node.packets + index
  }));
});

const maxBytes = computed(() => Math.max(...displayLinks.value.map((link) => link.bytes), 1));

const linkRows = computed(() =>
  displayLinks.value.map((link, index) => {
    const y = 34 + index * 44;
    const intensity = Math.max(0.28, link.bytes / maxBytes.value);
    return {
      ...link,
      id: `${link.src}-${link.dst}-${index}`,
      color: palette[index % palette.length],
      width: 1.5 + intensity * 3.5,
      y,
      delay: `${index * 0.35}s`,
      opacity: 0.35 + intensity * 0.55
    };
  })
);

const totalBytes = computed(() => displayLinks.value.reduce((sum, link) => sum + link.bytes, 0));
</script>

<template>
  <section class="flow-map-panel">
    <div class="panel-title">
      <div>
        <span>Live Network Map</span>
        <h2>实时流向拓扑</h2>
      </div>
      <strong>{{ formatBytes(totalBytes) }}</strong>
    </div>

    <div class="flow-stage">
      <div class="flow-node left-node">
        <span>源端</span>
        <strong>{{ linkRows.length }}</strong>
      </div>
      <svg viewBox="0 0 720 300" role="img" aria-label="实时流向拓扑">
        <defs>
          <filter id="flowGlow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="2.5" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        <g v-for="row in linkRows" :key="row.id">
          <path
            :d="`M 72 ${row.y} C 230 ${row.y - 28}, 430 ${row.y + 28}, 648 ${row.y}`"
            fill="none"
            :stroke="row.color"
            :stroke-width="row.width"
            :opacity="row.opacity"
            stroke-linecap="round"
          />
          <circle r="5" :fill="row.color" filter="url(#flowGlow)" class="flow-pulse" :style="{ animationDelay: row.delay }">
            <animateMotion dur="3s" repeatCount="indefinite" :begin="row.delay" :path="`M 72 ${row.y} C 230 ${row.y - 28}, 430 ${row.y + 28}, 648 ${row.y}`" />
          </circle>
          <text x="80" :y="row.y - 9">{{ row.src }}</text>
          <text x="648" :y="row.y - 9" text-anchor="end">{{ row.dst }}</text>
          <text x="360" :y="row.y + 19" text-anchor="middle" class="flow-value">{{ formatBytes(row.bytes) }} / {{ row.packets.toLocaleString() }} 包</text>
        </g>
      </svg>
      <div class="flow-node right-node">
        <span>目的端</span>
        <strong>{{ props.nodes.length || linkRows.length }}</strong>
      </div>
    </div>
  </section>
</template>

<style scoped>
.flow-map-panel {
  min-height: 360px;
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
  gap: 12px;
  overflow: hidden;
  border: 1px solid #22324a;
  border-radius: 8px;
  background:
    linear-gradient(135deg, rgba(37, 99, 235, 0.22), transparent 42%),
    linear-gradient(180deg, #0f1b33, #172033);
  color: #e5edf7;
  box-shadow: 0 12px 34px rgba(15, 23, 42, 0.18);
}

.panel-title {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 12px;
  padding: 16px 16px 0;
}

.panel-title span {
  color: #93c5fd;
  font-size: 12px;
  font-weight: 760;
}

.panel-title h2 {
  margin-top: 4px;
  color: #ffffff;
}

.panel-title strong {
  color: #93c5fd;
  font-size: 18px;
}

.flow-stage {
  position: relative;
  min-height: 286px;
}

svg {
  width: 100%;
  height: 100%;
  min-height: 286px;
}

text {
  fill: #c9d6e6;
  font-size: 12px;
}

.flow-value {
  fill: #91a2ba;
  font-size: 11px;
}

.flow-node {
  position: absolute;
  z-index: 1;
  width: 76px;
  height: 76px;
  display: grid;
  place-items: center;
  align-content: center;
  gap: 3px;
  border: 1px solid rgba(147, 197, 253, 0.42);
  border-radius: 999px;
  background: rgba(15, 23, 42, 0.74);
  box-shadow: 0 0 36px rgba(37, 99, 235, 0.24);
}

.flow-node span {
  color: #93c5fd;
  font-size: 12px;
}

.flow-node strong {
  color: #ffffff;
  font-size: 22px;
}

.left-node {
  left: 14px;
  top: 50%;
  transform: translateY(-50%);
}

.right-node {
  right: 14px;
  top: 50%;
  transform: translateY(-50%);
}

.flow-pulse {
  animation: pulse 1.6s ease-in-out infinite;
}

@keyframes pulse {
  0%,
  100% {
    opacity: 0.38;
  }
  50% {
    opacity: 1;
  }
}

@media (max-width: 760px) {
  .flow-map-panel {
    min-height: 300px;
  }

  .flow-stage,
  svg {
    min-height: 236px;
  }

  .flow-node {
    width: 58px;
    height: 58px;
  }

  .flow-node strong {
    font-size: 18px;
  }

  text {
    font-size: 10px;
  }

  .flow-value {
    font-size: 9px;
  }
}
</style>
