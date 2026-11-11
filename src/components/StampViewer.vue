<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, shallowRef, watch } from 'vue';
import { useI18n } from 'vue-i18n';
import { getDocument, GlobalWorkerOptions, type PDFDocumentProxy } from 'pdfjs-dist';
import workerUrl from 'pdfjs-dist/build/pdf.worker.min.mjs?url';
import AppIcon from './AppIcon.vue';

GlobalWorkerOptions.workerSrc = workerUrl;

type SignerInfo = {
  subject: string;
  issuer: string;
  expiresAt: string;
  chainTrusted: boolean;
  chainMessage: string;
  revocationStatus: string;
  revocationMessage: string;
};

type SignatureInfo = {
  fieldName: string;
  page: number | null;
  leftMm: number | null;
  topMm: number | null;
  widthMm: number | null;
  heightMm: number | null;
  subFilter: string;
  signedAt: string;
  coversDocument: boolean;
  valid: boolean;
  message: string;
  signers: SignerInfo[];
};

const props = defineProps<{
  /** PDF в Base64 (без data-префикса). */
  pdfBase64: string;
  signatures: SignatureInfo[];
}>();

const { t } = useI18n();
const canvas = ref<HTMLCanvasElement | null>(null);
const pdf = shallowRef<PDFDocumentProxy | null>(null);
const pageCount = ref(0);
const activePage = ref(0);
const loading = ref(false);
const error = ref('');
const viewWidth = ref(0);
const viewHeight = ref(0);
const cssScale = ref(1);
const selected = ref<number | null>(null);
let renderTask: { cancel: () => void } | null = null;
let renderToken = 0;

/** CSS-пикселей на 1 мм видимой стороны страницы. */
const mmPerPixel = computed(() => 25.4 / 72 / cssScale.value);
/** Штампы текущей страницы вместе с их индексом в общем списке подписей. */
const pageSignatures = computed(() =>
  props.signatures
    .map((signature, index) => ({ signature, index }))
    .filter(({ signature }) =>
      signature.page === activePage.value
      && signature.leftMm !== null
      && signature.topMm !== null
      && signature.widthMm !== null
      && signature.heightMm !== null));
/** Подписи без отметки на странице: до них нельзя добраться кликом по штампу. */
const hiddenSignatures = computed(() =>
  props.signatures
    .map((signature, index) => ({ signature, index }))
    .filter(({ signature }) =>
      signature.page === null
      || signature.leftMm === null
      || signature.topMm === null
      || signature.widthMm === null
      || signature.heightMm === null));
const selectedSignature = computed(() =>
  selected.value === null ? null : props.signatures[selected.value] ?? null);

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
  selected.value = null;
  try {
    const loaded = await getDocument({ data: base64ToBytes(props.pdfBase64) }).promise;
    await pdf.value?.cleanup();
    pdf.value = loaded;
    pageCount.value = loaded.numPages;
    if (activePage.value >= loaded.numPages) activePage.value = 0;
    await render();
  } catch (caught) {
    error.value = t('stampViewer.pdfError', { error: String(caught) });
  } finally {
    loading.value = false;
  }
}

async function render() {
  const loaded = pdf.value;
  const element = canvas.value;
  if (!loaded || !element) return;
  const token = ++renderToken;
  renderTask?.cancel();
  const target = await loaded.getPage(activePage.value + 1);
  if (token !== renderToken) return;
  const rotation = ((target.rotate % 360) + 360) % 360;
  const unscaled = target.getViewport({ scale: 1, rotation });
  const scale = Math.min(1.5, 760 / unscaled.width);
  cssScale.value = scale;
  const viewport = target.getViewport({ scale, rotation });
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

function changePage(delta: number) {
  const next = Math.min(Math.max(activePage.value + delta, 0), pageCount.value - 1);
  if (next === activePage.value) return;
  activePage.value = next;
  selected.value = null;
  void render();
}

function zoneStyle(signature: SignatureInfo) {
  const factor = 1 / mmPerPixel.value;
  return {
    left: `${(signature.leftMm ?? 0) * factor}px`,
    top: `${(signature.topMm ?? 0) * factor}px`,
    width: `${(signature.widthMm ?? 0) * factor}px`,
    height: `${(signature.heightMm ?? 0) * factor}px`,
  };
}

function signatureTitle(signature: SignatureInfo) {
  return signature.signers[0]?.subject || signature.fieldName;
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
        <button class="outline-button" :disabled="activePage === 0" :aria-label="t('stampViewer.prevPage')" @click="changePage(-1)"><AppIcon name="chevron-left" :size="16" /></button>
        <span>{{ t('stampViewer.page', { current: activePage + 1, total: pageCount || 1 }) }}</span>
        <button class="outline-button" :disabled="activePage + 1 >= pageCount" :aria-label="t('stampViewer.nextPage')" @click="changePage(1)"><AppIcon name="chevron-right" :size="16" /></button>
      </div>
      <p class="stamp-hint">{{ t('stampViewer.hint') }}</p>
    </header>

    <div class="stamp-stage">
      <div v-if="loading" class="stamp-message">{{ t('stampViewer.loading') }}</div>
      <div v-else-if="error" class="stamp-message error">{{ error }}</div>
      <div v-show="!error" class="stamp-canvas" :style="{ width: `${viewWidth}px`, height: `${viewHeight}px` }">
        <canvas ref="canvas" class="stamp-canvas-surface viewer" @click="selected = null"></canvas>
        <button
          v-for="item in pageSignatures"
          :key="item.index"
          type="button"
          class="stamp-zone signature"
          :class="{ valid: item.signature.valid, invalid: !item.signature.valid, selected: selected === item.index }"
          :style="zoneStyle(item.signature)"
          :title="signatureTitle(item.signature)"
          @click.stop="selected = item.index"
        >
          <span class="stamp-zone-label">{{ signatureTitle(item.signature) }}</span>
        </button>
      </div>
    </div>

    <section v-if="selectedSignature" class="signature-details">
      <header class="signature-details-head">
        <span class="signature-state" :class="selectedSignature.valid ? 'valid' : 'invalid'">
          <AppIcon :name="selectedSignature.valid ? 'check' : 'alert'" :size="14" />
          {{ selectedSignature.valid ? t('stampViewer.statusValid') : t('stampViewer.statusInvalid') }}
        </span>
        <b>{{ signatureTitle(selectedSignature) }}</b>
      </header>
      <p class="signature-message">{{ selectedSignature.message }}</p>
      <dl class="signature-meta">
        <div><dt>{{ t('stampViewer.field') }}</dt><dd>{{ selectedSignature.fieldName }}</dd></div>
        <div v-if="selectedSignature.signedAt"><dt>{{ t('stampViewer.signedAt') }}</dt><dd>{{ selectedSignature.signedAt }}</dd></div>
        <div v-if="selectedSignature.subFilter"><dt>{{ t('stampViewer.subFilter') }}</dt><dd>{{ selectedSignature.subFilter }}</dd></div>
      </dl>
      <article v-for="(signer, index) in selectedSignature.signers" :key="index" class="signature-signer">
        <b>{{ signer.subject }}</b>
        <small>{{ t('verifyPage.issuer') }}{{ signer.issuer }}</small>
        <small>{{ t('verifyPage.validUntil') }}{{ signer.expiresAt }}</small>
        <small class="chain-status" :class="signer.chainTrusted ? 'trusted' : 'untrusted'">{{ signer.chainMessage }}</small>
        <small class="chain-status" :class="signer.revocationStatus === 'good' ? 'trusted' : signer.revocationStatus === 'revoked' ? 'untrusted' : 'unknown'">{{ signer.revocationMessage }}</small>
      </article>
      <p v-if="!selectedSignature.coversDocument" class="signature-note">{{ t('stampViewer.partialCoverage') }}</p>
    </section>

    <footer v-if="hiddenSignatures.length" class="stamp-summary stamp-viewer-list">
      <span>{{ t('stampViewer.withoutStamp') }}</span>
      <button
        v-for="item in hiddenSignatures"
        :key="item.index"
        type="button"
        class="outline-button"
        @click="selected = item.index"
      >{{ item.signature.fieldName }}</button>
    </footer>
  </div>
</template>
