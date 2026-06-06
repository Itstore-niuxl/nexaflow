import { defineComponent } from 'vue';
import { createRouter, createWebHistory } from 'vue-router';

const EmptyRoute = defineComponent({
  name: 'EmptyRoute',
  setup: () => () => null
});

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'dashboard', component: EmptyRoute },
    { path: '/:view', name: 'view', component: EmptyRoute }
  ]
});
