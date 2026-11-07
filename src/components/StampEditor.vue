<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, shallowRef, watch } from 'vue';
import { useI18n } from 'vue-i18n';
import { getDocument, GlobalWorkerOptions, type PDFDocumentProxy, type PDFPageProxy } from 'pdfjs-dist';
import workerUrl from 'pdfjs-dist/build/pdf.worker.min.mjs?url';
import type { StampRect } from '../signing';
import AppIcon from './AppIcon.vue';

GlobalWorkerOptions.workerSrc = workerUrl;

const props = defineProps<{
  /** PDF в Base64 (без data-префикса). */
  pdfBase64: string;
  rects: StampRect[];
  /** Подписанты в порядке наложения: первая свободная область отдаётся следующему. */
  signerIds: string[];
  signerLabels: Record<string, string>;
}>();

const emit = defineEmits<{
  (event: 'update:rects', value: StampRect[]): void;
}>();

const { t } = useI18n();
const canvas = ref<HTMLCanvasElement | null>(null);
const pdf = shallowRef<PDFDocumentProxy | null>(null);
const pageProxy = shallowRef<PDFPageProxy | null>(null);
const pageCount = ref(0);
const activePage = ref(0);
const loading = ref(false);
const error = ref('');
/** Размер отрисованной страницы в CSS-пикселях. */
const viewWidth = ref(0);
const viewHeight = ref(0);
/** Сколько CSS-пикселей приходится на 1 pt PDF. */
const cssScale = ref(1);
const draft = ref<{ x0: number; y0: number; x1: number; y1: number } | null>(null);
let renderTask: { cancel: () => void } | null = null;

const nextSigner = computed(() => {
  const placed = new Set(props.rects.map((rect) => rect.certificateId));
  return props.signerIds.find((id) => !placed.has(id)) ?? '';
});
const pageRects = computed(() => props.rects.filter((rect) => rect.page === activePage.value));
const mmPerPixel = computed(() => (25.4 / 72) / cssScale.value);

function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

async function load() {
  if (!props.pdfBase64 || !canvas.value) return;
  loading.value = true;
  error.value = '';
  try {
    const loaded = await getDocument({ data: base64ToBytes(props.pdfBase64) }).promise;
    await pdf.value?.cleanup();
    pdf.value = loaded;
    pageCount.value = loaded.numPages;
    if (activePage.value >= loaded.numPages) activePage.value = 0;
    await render();
  } catch (caught) {
    error.value = t('stampEditor.pdfError', { error: String(caught) });
  } finally {
    loading.value = false;
  }
}

async function render() {
  const loaded = pdf.value;
  const element = canvas.value;
  if (!loaded || !element) return;
  renderTask?.cancel();
  const target = await loaded.getPage(activePage.value + 1);
  pageProxy.value = target;
  const unscaled = target.getViewport({ scale: 1 });
  const scale = Math.min(1.5, 760 / unscaled.width);
  cssScale.value = scale;
  const viewport = target.getViewport({ scale });
  viewWidth.value = viewport.width;
  viewHeight.value = viewport.height;
  const ratio = Math.min(window.devicePixelRatio || 1, 2);
  element.width = Math.floor(viewport.width * ratio);
  element.height = Math.floor(viewport.height * ratio);
  element.style.width = `${viewport.width}px`;
  element.style.height = `${viewport.height}px`;
  const context = element.getContext('2d');
  if (!context) return;

  renderTask = target.render({
    canvasContext: context,
    viewport,
    transform: ratio !== 1 ? [ratio, 0, 0, ratio, 0, 0] : undefined,
  } as never) as unknown as { cancel: () => void; promise: Promise<void> };
}

function point(event: MouseEvent) {
  const element = canvas.value;
  if (!element) return { x: 0, y: 0 };
  const bounds = element.getBoundingClientRect();
  return { x: event.clientX - bounds.left, y: event.clientY - bounds.top };
}

function onPointerDown(event: MouseEvent) {
  if (event.button !== 0) return;
  const start = point(event);
  draft.value = { x0: start.x, y0: start.y, x1: start.x, y1: start.y };
}

function onPointerMove(event: MouseEvent) {
  if (!draft.value) return;
  const current = point(event);
  draft.value = { ...draft.value, x1: current.x, y1: current.y };
}

function onPointerUp(event: MouseEvent) {
  const current = draft.value;
  draft.value = null;
  if (!current) return;
  const end = point(event);
  const left = Math.min(current.x0, end.x);
  const top = Math.min(current.y0, end.y);
  const width = Math.abs(end.x - current.x0);
  const height = Math.abs(end.y - current.y0);
  if (width < 16 || height < 10 || !nextSigner.value) return;
  const rect: StampRect = {
    page: activePage.value,
    leftMm: left * mmPerPixel.value,
    topMm: top * mmPerPixel.value,
    widthMm: width * mmPerPixel.value,
    heightMm: height * mmPerPixel.value,
    certificateId: nextSigner.value,
  };
  // Один подписант — ровно одна область, и только пока у него её нет.
  if (props.rects.some((item) => item.certificateId === nextSigner.value)) return;
  emit('update:rects', [...props.rects, rect]);
}

/// Сколько областей уже стоит у подписанта (для подсказки в разметке).
function placedCount(certificateId: string) {
  return props.rects.filter((rect) => rect.certificateId === certificateId).length;
}

function removeRect(target: StampRect) {
  emit('update:rects', props.rects.filter((rect) => rect !== target));
}

function clearPage() {
  emit('update:rects', props.rects.filter((rect) => rect.page !== activePage.value));
}

function changePage(delta: number) {
  const next = Math.min(Math.max(activePage.value + delta, 0), pageCount.value - 1);
  if (next === activePage.value) return;
  activePage.value = next;
  void render();
}

function zoneStyle(rect: StampRect) {
  const factor = 1 / mmPerPixel.value;
  return {
    left: `${rect.leftMm * factor}px`,
    top: `${rect.topMm * factor}px`,
    width: `${rect.widthMm * factor}px`,
    height: `${rect.heightMm * factor}px`,
  };
}

watch(() => props.pdfBase64, () => void load());
onMounted(() => void load());
onBeforeUnmount(() => {
  renderTask?.cancel();
  void pdf.value?.cleanup();
});
</script>

<template>
  <div class="stamp-editor">
    <header class="stamp-toolbar">
      <div class="stamp-pager">
        <button class="outline-button" :disabled="activePage === 0" :aria-label="t('stampEditor.prevPage')" @click="changePage(-1)"><AppIcon name="chevron-left" :size="16" /></button>
        <span>{{ t('stampEditor.page', { current: activePage + 1, total: pageCount || 1 }) }}</span>
        <button class="outline-button" :disabled="activePage + 1 >= pageCount" :aria-label="t('stampEditor.nextPage')" @click="changePage(1)"><AppIcon name="chevron-right" :size="16" /></button>
      </div>
      <p class="stamp-hint">
        {{ nextSigner ? t('stampEditor.hint', { signer: signerLabels[nextSigner] ?? nextSigner }) : t('stampEditor.allPlaced') }}
      </p>
      <span v-if="nextSigner" class="stamp-counter">
        {{ t('stampEditor.placedCount', { placed: placedCount(nextSigner), max: 1 }) }}
      </span>
      <button class="outline-button" :disabled="!pageRects.length" @click="clearPage">
        {{ t('stampEditor.clearPage') }}
      </button>
    </header>

    <div class="stamp-stage">
      <div v-if="loading" class="stamp-message">{{ t('stampEditor.loading') }}</div>
      <div v-else-if="error" class="stamp-message error">{{ error }}</div>
      <div v-show="!error" class="stamp-canvas" :style="{ width: `${viewWidth}px`, height: `${viewHeight}px` }">
        <canvas
          ref="canvas"
          class="stamp-canvas-surface"
          @mousedown.prevent="onPointerDown"
          @mousemove="onPointerMove"
          @mouseup="onPointerUp"
          @mouseleave="draft = null"
        ></canvas>
        <div
          v-for="(rect, index) in pageRects"
          :key="`${rect.certificateId}-${index}`"
          class="stamp-zone"
          :style="zoneStyle(rect)"
        >
          <span class="stamp-zone-label">{{ signerLabels[rect.certificateId] ?? rect.certificateId }}</span>
          <button class="stamp-zone-remove" :title="t('stampEditor.remove')" :aria-label="t('stampEditor.remove')" @mousedown.stop @click.stop="removeRect(rect)"><AppIcon name="x" :size="14" /></button>
        </div>
        <div
          v-if="draft"
          class="stamp-zone draft"
          :style="{
            left: `${Math.min(draft.x0, draft.x1)}px`,
            top: `${Math.min(draft.y0, draft.y1)}px`,
            width: `${Math.abs(draft.x1 - draft.x0)}px`,
            height: `${Math.abs(draft.y1 - draft.y0)}px`,
          }"
        ></div>
      </div>
    </div>

    <footer class="stamp-summary">
      <span :class="{ warning: rects.length !== signerIds.length }">
        {{ t('stampEditor.count', { page: pageRects.length, total: rects.length }) }}
      </span>
      <span>{{ t('stampEditor.required', { required: signerIds.length }) }}</span>
    </footer>
  </div>
</template>
