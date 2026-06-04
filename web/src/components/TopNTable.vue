<script setup lang="ts">
import type { TopItem } from '../services/api';

defineProps<{ title: string; items: TopItem[] }>();

const formatBytes = (value: number) => {
  if (value >= 1024 ** 3) return `${(value / 1024 ** 3).toFixed(2)} GB`;
  if (value >= 1024 ** 2) return `${(value / 1024 ** 2).toFixed(2)} MB`;
  if (value >= 1024) return `${(value / 1024).toFixed(2)} KB`;
  return `${value.toFixed(0)} B`;
};
</script>

<template>
  <section class="table-panel topn-table-panel" :class="{ 'wide-key-table': title.includes('会话') || title.includes('主机对') }">
    <h2>{{ title }}</h2>
    <table>
      <thead>
        <tr>
          <th>对象</th>
          <th>流量</th>
          <th>包数</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="item in items" :key="item.key">
          <td :title="item.key">{{ item.key }}</td>
          <td>{{ formatBytes(item.bytes) }}</td>
          <td>{{ item.packets.toLocaleString() }}</td>
        </tr>
      </tbody>
    </table>
  </section>
</template>
