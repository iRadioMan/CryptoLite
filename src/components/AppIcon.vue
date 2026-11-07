<script setup lang="ts">
import { ICON_PATHS, type IconName } from './icons';
const props = withDefaults(defineProps<{ name: IconName; size?: number }>(), { size: 18 });
</script>

<template>
  <svg :width="props.size" :height="props.size" viewBox="0 0 24 24" fill="none" stroke="currentColor"
       stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">
    <path v-for="d in ICON_PATHS[props.name]" :key="d" :d="d" />
  </svg>
</template>
