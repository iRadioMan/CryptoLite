<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { useI18n } from 'vue-i18n';
import { open } from '@tauri-apps/plugin-dialog';
import { invoke } from '@tauri-apps/api/core';
import { getCurrentWebview } from '@tauri-apps/api/webview';

type CspStatus = { available: boolean; cadesAvailable: boolean; signingAvailable: boolean; providerType?: number | null; version?: string | null; message: string };
type AppSettings = { language: string; theme: string; animations: boolean; defaultStandard: string; defaultEncoding: string; defaultDetached: boolean; defaultSignatureExtension: string; defaultCertificateIds: string[]; defaultOutputDirectory: string; saveLastSigningSettings: boolean; tspServer: string };
type CertInfo = { id: string; subject: string; issuer: string; expiresAt: string; expired: boolean; hasPrivateKey: boolean; source: string };
type Doc = { path: string; name: string; selected: boolean };
type SignBatchItemResult = { inputPath: string; outputPath: string; success: boolean; error: string | null };
type VerifyResult = { valid: boolean; signaturePath: string; contentPath: string | null; signers: { subject: string; issuer: string; expiresAt: string; chainTrusted: boolean; chainMessage: string }[]; message: string };
type CryptoResult = { outputPath: string; bytesWritten: number };
const { t, locale } = useI18n();
const systemLanguage = navigator.language.toLowerCase().startsWith('ru') ? 'ru' : 'en';
const page = ref('sign');
const documents = ref<Doc[]>([]);
const status = ref<CspStatus>({ available: false, cadesAvailable: false, signingAvailable: false, message: t('checkingCsp') });
const appSettings = ref<AppSettings>({ language: 'system', theme: 'system', animations: true, defaultStandard: 'cms', defaultEncoding: 'der', defaultDetached: true, defaultSignatureExtension: 'sig', defaultCertificateIds: [], defaultOutputDirectory: '', saveLastSigningSettings: true, tspServer: '' });
const settingsLoaded = ref(false);
const settingsSaveState = ref<'saving' | 'saved' | ''>('');
const settingsError = ref('');
const showAlert = ref(false);
const standard = ref('cms');
const encoding = ref('der');
const signatureType = ref('detached');
const fileType = ref('sig');
const certificateNames = ref<string[]>([]);
const certificates = ref<CertInfo[]>([]);
const selectedCertIds = ref<string[]>([]);
const certFilter = ref('');
const certPickerOpen = ref(false);
const certPickerMode = ref<'signing' | 'defaults' | 'encryption'>('signing');
const pickerDraftCertIds = ref<string[]>([]);
const certsLoading = ref(false);
const certsError = ref('');
const signingInProgress = ref(false);
const signingMessage = ref('');
const signReportOpen = ref(false);
const signReportItems = ref<SignBatchItemResult[]>([]);
const verifySignaturePath = ref('');
const verifyContentPath = ref('');
const verifyDetached = ref(true);
const verifyBase64 = ref(false);
const verifyProgress = ref(false);
const verifyResult = ref<VerifyResult | null>(null);
const dragHover = ref(false);
const cryptoMode = ref<'encrypt' | 'decrypt'>('encrypt');
const cryptoFiles = ref<Doc[]>([]);
const cryptoEncoding = ref('der');
const cryptoRecipientIds = ref<string[]>([]);
const cryptoProgress = ref(false);
const cryptoMessage = ref('');
const cryptoReportOpen = ref(false);
const cryptoReportItems = ref<{ inputPath: string; outputPath: string; success: boolean; error: string | null }[]>([]);
const cryptoOutputDir = ref('');
let unlistenDrop: (() => void) | undefined;
let unlistenSystemTheme: (() => void) | undefined;
const outputDir = ref('');
const isDark = ref(localStorage.getItem('cryptolite.theme') === 'dark');
let settingsSaveQueue: Promise<unknown> = Promise.resolve();
const selectedCount = computed(() => documents.value.filter((document) => document.selected).length);
const selectedCertificates = computed(() => selectedCertIds.value.map((id) => certificates.value.find((certificate) => certificate.id === id)).filter((certificate): certificate is CertInfo => !!certificate && !certificate.expired));
const defaultCertificateNames = computed(() => certificates.value.filter((certificate) => appSettings.value.defaultCertificateIds.includes(certificate.id) && !certificate.expired).map((certificate) => certificate.subject));
const canSign = computed(() => {
  if (!status.value.available || !selectedCount.value || signingInProgress.value) return false;
  if (!selectedCertificates.value.length) return false;
  if (standard.value === 'cades-bes') return status.value.cadesAvailable && selectedCertIds.value.length === 1;
  if (standard.value === 'cms') return status.value.signingAvailable;
  return false;
});
const signSuccessCount = computed(() => signReportItems.value.filter((item) => item.success).length);
const signErrorCount = computed(() => signReportItems.value.length - signSuccessCount.value);
const filteredCertificates = computed(() => certificates.value.filter((certificate) => certificate.subject.toLocaleLowerCase().includes(certFilter.value.toLocaleLowerCase())));
const cryptoSelectedCount = computed(() => cryptoFiles.value.filter((document) => document.selected).length);
const cryptoRecipientNames = computed(() => certificates.value.filter((certificate) => cryptoRecipientIds.value.includes(certificate.id) && !certificate.expired).map((certificate) => certificate.subject));
const canEncrypt = computed(() => status.value.available && cryptoMode.value === 'encrypt' && cryptoSelectedCount.value > 0 && cryptoRecipientIds.value.length > 0 && !cryptoProgress.value);
const canDecrypt = computed(() => status.value.available && cryptoMode.value === 'decrypt' && cryptoSelectedCount.value > 0 && !cryptoProgress.value);
const cryptoSuccessCount = computed(() => cryptoReportItems.value.filter((item) => item.success).length);
const cryptoErrorCount = computed(() => cryptoReportItems.value.length - cryptoSuccessCount.value);

onMounted(async () => {
  document.documentElement.classList.toggle('dark', isDark.value);
  const colorScheme = window.matchMedia('(prefers-color-scheme: dark)');
  const onSystemThemeChange = () => {
    if (appSettings.value.theme === 'system') {
      isDark.value = colorScheme.matches;
      document.documentElement.classList.toggle('dark', colorScheme.matches);
    }
  };
  colorScheme.addEventListener('change', onSystemThemeChange);
  unlistenSystemTheme = () => colorScheme.removeEventListener('change', onSystemThemeChange);
  try {
    unlistenDrop = await getCurrentWebview().onDragDropEvent((event) => {
      if (event.payload.type === 'enter') dragHover.value = true;
      else if (event.payload.type === 'leave') dragHover.value = false;
      else if (event.payload.type === 'drop') {
        dragHover.value = false;
        handleDroppedPaths(event.payload.paths);
      }
    });
  } catch (error) {
    console.warn('Не удалось подключить обработчик drag-and-drop', error);
  }
  try { status.value = await invoke<CspStatus>('csp_status'); }
  catch (error) { status.value = { available: false, cadesAvailable: false, signingAvailable: false, message: String(error) }; }
  await initializeSettings();
  if (!status.value.available) showAlert.value = true;
});
onUnmounted(() => { unlistenDrop?.(); unlistenSystemTheme?.(); });

watch(appSettings, () => {
  if (!settingsLoaded.value) return;
  applySettings();
  scheduleSettingsSave();
}, { deep: true });
watch([standard, encoding, signatureType, fileType, outputDir], () => {
  if (!settingsLoaded.value) return;
  if (appSettings.value.saveLastSigningSettings) {
    appSettings.value.defaultStandard = standard.value;
    appSettings.value.defaultEncoding = encoding.value;
    appSettings.value.defaultDetached = signatureType.value === 'detached';
    appSettings.value.defaultSignatureExtension = fileType.value;
    appSettings.value.defaultOutputDirectory = outputDir.value;
  } else scheduleSettingsSave();
});
watch(selectedCertIds, () => {
  if (!settingsLoaded.value) return;
  if (appSettings.value.saveLastSigningSettings) {
    if (!sameStringList(appSettings.value.defaultCertificateIds, selectedCertIds.value)) {
      appSettings.value.defaultCertificateIds = [...selectedCertIds.value];
    }
  }
  else scheduleSettingsSave();
}, { deep: true });

function sameStringList(left: string[], right: string[]) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

async function initializeSettings() {
  try {
    const loaded = await invoke<AppSettings>('load_settings');
    appSettings.value = { ...appSettings.value, ...loaded };
    settingsLoaded.value = true;
    applySettings();
    await refreshSettingsCertificates();
  } catch (error) {
    settingsError.value = t('settings.loadErrorDetail', { error: String(error) });
    settingsLoaded.value = true;
    applySettings();
  }
}
function applySettings() {
  standard.value = appSettings.value.defaultStandard;
  encoding.value = appSettings.value.defaultEncoding;
  signatureType.value = appSettings.value.defaultDetached ? 'detached' : 'attached';
  fileType.value = appSettings.value.defaultSignatureExtension;
  outputDir.value = appSettings.value.defaultOutputDirectory;
  selectedCertIds.value = [...appSettings.value.defaultCertificateIds];
  certificateNames.value = certificates.value.filter((certificate) => selectedCertIds.value.includes(certificate.id) && !certificate.expired).map((certificate) => certificate.subject);
  const language = appSettings.value.language === 'system' ? systemLanguage : appSettings.value.language;
  locale.value = language;
  document.documentElement.lang = language;
  localStorage.setItem('cryptolite.language', language);
  const dark = appSettings.value.theme === 'dark' || (appSettings.value.theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
  isDark.value = dark;
  document.documentElement.classList.toggle('dark', dark);
  document.documentElement.classList.toggle('motion-off', !appSettings.value.animations);
  localStorage.setItem('cryptolite.theme', dark ? 'dark' : 'light');
}
function scheduleSettingsSave() {
  settingsSaveState.value = 'saving';
  const snapshot = snapshotSettings();
  settingsSaveQueue = settingsSaveQueue.catch(() => undefined).then(() => invoke('save_settings', { settings: snapshot }));
  settingsSaveQueue.then(() => { settingsSaveState.value = 'saved'; settingsError.value = ''; }).catch((error) => { settingsError.value = t('settings.saveErrorDetail', { error: String(error) }); });
}
function snapshotSettings(): AppSettings {
  const settings = appSettings.value;
  return { ...settings, defaultCertificateIds: [...settings.defaultCertificateIds] };
}
async function refreshSettingsCertificates() {
  certsLoading.value = true;
  certsError.value = '';
  try {
    certificates.value = await invoke<CertInfo[]>('list_certs');
    appSettings.value.defaultCertificateIds = appSettings.value.defaultCertificateIds.filter((id) => certificates.value.some((certificate) => certificate.id === id && !certificate.expired));
    certificateNames.value = certificates.value.filter((certificate) => selectedCertIds.value.includes(certificate.id) && !certificate.expired).map((certificate) => certificate.subject);
  }
  catch (error) { certsError.value = String(error); }
  finally { certsLoading.value = false; }
}

function addFiles(paths: string[]) {
  for (const path of paths) {
    if (!documents.value.some((doc) => doc.path === path)) {
      const name = path.split(/[\\/]/).pop() || path;
      documents.value.push({ path, name, selected: true });
    }
  }
}
async function chooseFiles() {
  const result = await open({ multiple: true, title: t('add') });
  if (result) addFiles(Array.isArray(result) ? result : [result]);
}
async function chooseOutput() {
  const result = await open({ directory: true, title: t('output') });
  if (result && typeof result === 'string') outputDir.value = result;
}
async function chooseVerifySignature() {
  const result = await open({ multiple: false, title: t('verifyPage.chooseSignatureTitle') });
  if (typeof result === 'string') { verifySignaturePath.value = result; verifyResult.value = null; }
}
async function chooseVerifyContent() {
  const result = await open({ multiple: false, title: t('verifyPage.chooseContentTitle') });
  if (typeof result === 'string') { verifyContentPath.value = result; verifyResult.value = null; }
}
async function runVerify() {
  if (!verifySignaturePath.value || (verifyDetached.value && !verifyContentPath.value) || verifyProgress.value) return;
  verifyProgress.value = true;
  verifyResult.value = null;
  try {
    verifyResult.value = await invoke<VerifyResult>('verify_signature', { request: {
      signaturePath: verifySignaturePath.value,
      contentPath: verifyContentPath.value || null,
      detached: verifyDetached.value,
      base64: verifyBase64.value,
    } });
  } catch (error) {
    verifyResult.value = { valid: false, signaturePath: verifySignaturePath.value, contentPath: verifyContentPath.value || null, signers: [], message: String(error) };
  } finally { verifyProgress.value = false; }
}
function handleDroppedPaths(paths: string[]) {
  if (page.value === 'sign') {
    addFiles(paths);
  } else if (page.value === 'encrypt') {
    addCryptoFiles(paths);
  } else if (page.value === 'verify' && paths.length) {
    const signatures = paths.filter((path) => /\.(sig|p7s)$/i.test(path));
    const signature = signatures[0] || paths[0];
    const content = paths.find((path) => path !== signature);
    verifySignaturePath.value = signature;
    if (content) {
      verifyContentPath.value = content;
      verifyDetached.value = true;
    }
    verifyResult.value = null;
  }
}
function changeLanguage(language: string) { appSettings.value.language = language; }
function toggleTheme() {
  appSettings.value.theme = isDark.value ? 'light' : 'dark';
}
async function openCertificatePicker(mode: 'signing' | 'defaults' = 'signing') {
  certPickerMode.value = mode;
  pickerDraftCertIds.value = [...(mode === 'defaults' ? appSettings.value.defaultCertificateIds : selectedCertIds.value)];
  certPickerOpen.value = true;
  certFilter.value = '';
  certsError.value = '';
  certsLoading.value = true;
  try {
    certificates.value = await invoke<CertInfo[]>('list_certs');
    pickerDraftCertIds.value = pickerDraftCertIds.value.filter((id) => certificates.value.some((certificate) => certificate.id === id && !certificate.expired));
    certificateNames.value = certificates.value.filter((certificate) => selectedCertIds.value.includes(certificate.id)).map((certificate) => certificate.subject);
  }
  catch (error) { certsError.value = String(error); }
  finally { certsLoading.value = false; }
}
function confirmCertificates() {
  const activeIds = pickerDraftCertIds.value.filter((id) => certificates.value.some((certificate) => certificate.id === id && !certificate.expired));
  if (certPickerMode.value === 'defaults') appSettings.value.defaultCertificateIds = activeIds;
  else if (certPickerMode.value === 'encryption') cryptoRecipientIds.value = activeIds;
  else selectedCertIds.value = activeIds;
  if (certPickerMode.value === 'signing') certificateNames.value = certificates.value.filter((certificate) => selectedCertIds.value.includes(certificate.id) && !certificate.expired).map((certificate) => certificate.subject);
  certPickerOpen.value = false;
}
async function signSelectedDocument() {
  const selected = documents.value.filter((document) => document.selected);
  if (!canSign.value || !selected.length || !selectedCertIds.value.length) return;
  const requests = selected.map((document) => {
    const separator = Math.max(document.path.lastIndexOf('/'), document.path.lastIndexOf('\\'));
    const folder = outputDir.value || document.path.slice(0, separator);
    const slash = document.path.includes('\\') ? '\\' : '/';
    return { inputPath: document.path, outputPath: `${folder ? `${folder}${slash}` : ''}${document.name}.${fileType.value}` };
  });
  signingInProgress.value = true;
  signingMessage.value = '';
  try {
    signReportItems.value = await invoke<SignBatchItemResult[]>('sign_files', {
      requests: requests.map(({ inputPath, outputPath }) => ({
        standard: standard.value,
        inputPath,
        outputPath,
        certificateIds: [...selectedCertIds.value],
        detached: signatureType.value === 'detached',
        base64: encoding.value === 'base64',
      })),
    });
    signReportOpen.value = true;
  } catch (error) {
    signingMessage.value = String(error);
  } finally {
    signingInProgress.value = false;
  }
}
function addCryptoFiles(paths: string[]) {
  for (const path of paths) {
    if (!cryptoFiles.value.some((doc) => doc.path === path)) {
      const name = path.split(/[\\/]/).pop() || path;
      cryptoFiles.value.push({ path, name, selected: true });
    }
  }
}
async function chooseCryptoFiles() {
  const result = await open({ multiple: true, title: cryptoMode.value === 'encrypt' ? t('encryptPage.chooseFilesTitle') : t('encryptPage.chooseDecryptTitle') });
  if (result) addCryptoFiles(Array.isArray(result) ? result : [result]);
}
async function chooseCryptoOutput() {
  const result = await open({ directory: true, title: t('encryptPage.saveFolderTitle') });
  if (result && typeof result === 'string') cryptoOutputDir.value = result;
}
function openRecipientPicker() {
  pickerDraftCertIds.value = [...cryptoRecipientIds.value];
  certPickerMode.value = 'encryption';
  certPickerOpen.value = true;
  certFilter.value = '';
  certsError.value = '';
  certsLoading.value = true;
  invoke<CertInfo[]>('list_certs')
    .then((certs) => {
      certificates.value = certs;
      pickerDraftCertIds.value = pickerDraftCertIds.value.filter((id) => certs.some((certificate) => certificate.id === id && !certificate.expired));
    })
    .catch((error) => { certsError.value = String(error); })
    .finally(() => { certsLoading.value = false; });
}
async function runCrypto() {
  const selected = cryptoFiles.value.filter((document) => document.selected);
  if (cryptoProgress.value || !selected.length) return;
  if (cryptoMode.value === 'encrypt' && !cryptoRecipientIds.value.length) return;
  cryptoProgress.value = true;
  cryptoMessage.value = '';
  cryptoReportItems.value = [];
  for (const document of selected) {
    const separator = Math.max(document.path.lastIndexOf('/'), document.path.lastIndexOf('\\'));
    const folder = cryptoOutputDir.value || document.path.slice(0, separator);
    const slash = document.path.includes('\\') ? '\\' : '/';
    const baseName = document.name;
    const outputPath = cryptoMode.value === 'encrypt'
      ? `${folder ? `${folder}${slash}` : ''}${baseName}.enc`
      : stripEncryptedExtension(baseName, folder, slash);
    try {
      if (cryptoMode.value === 'encrypt') {
        const result = await invoke<CryptoResult>('encrypt_file', { request: {
          inputPath: document.path,
          outputPath,
          certificateIds: cryptoRecipientIds.value,
          base64: cryptoEncoding.value === 'base64',
        } });
        cryptoReportItems.value.push({ inputPath: document.path, outputPath: result.outputPath, success: true, error: null });
      } else {
        const result = await invoke<CryptoResult>('decrypt_file', { request: {
          inputPath: document.path,
          outputPath,
          base64: cryptoEncoding.value === 'base64',
        } });
        cryptoReportItems.value.push({ inputPath: document.path, outputPath: result.outputPath, success: true, error: null });
      }
    } catch (error) {
      cryptoReportItems.value.push({ inputPath: document.path, outputPath, success: false, error: String(error) });
    }
  }
  cryptoProgress.value = false;
  cryptoReportOpen.value = true;
}
function stripEncryptedExtension(name: string, folder: string, slash: string): string {
  const lowered = name.toLowerCase();
  const base = lowered.endsWith('.p7m') || lowered.endsWith('.p7e') || lowered.endsWith('.enc')
    ? name.slice(0, -4)
    : name;
  return `${folder ? `${folder}${slash}` : ''}${base}.dec`;
}
</script>

<template>
  <div class="app-shell" :class="{'drag-hover':dragHover}">
    <div v-if="dragHover" class="drop-overlay"><span>＋</span><b>{{ page==='verify'?t('dropOverlay.verify'):page==='encrypt'?t('dropOverlay.encrypt'):t('dropOverlay.sign') }}</b></div>
    <aside class="sidebar">
      <div class="brand"><div class="brand-mark">К</div><div><div class="brand-name">КриптоЛайт</div><div class="brand-caption">{{ t('subtitle') }}</div></div></div>
      <div class="menu-label">{{ t('workspace') }}</div>
      <nav class="nav-list">
        <button v-for="item in ['sign','encrypt','verify']" :key="item" class="nav-item" :class="{active:page===item}" @click="page=item"><span class="nav-icon">{{ item==='sign'?'✳':item==='encrypt'?'◇':'✓' }}</span>{{ t(`nav.${item}`) }}<span v-if="page===item" class="active-dot"></span></button>
      </nav>
      <div class="menu-label secondary-label">{{ t('preferences') }}</div>
      <nav class="nav-list">
        <button v-for="item in ['settings','about']" :key="item" class="nav-item" :class="{active:page===item}" @click="page=item"><span class="nav-icon">{{ item==='settings'?'⚙':'ⓘ' }}</span>{{ t(`nav.${item}`) }}</button>
      </nav>
      <div class="sidebar-bottom"><div class="csp-card"><span class="status-dot" :class="{connected:status.available}"></span><div><b>{{ status.available ? t('cspFound') : t('disconnected') }}</b><small>{{ status.available ? status.message : 'CryptoLite 0.1.0' }}</small></div><span class="refresh">↻</span></div></div>
    </aside>

    <main class="main-area">
      <header class="topbar"><div class="breadcrumb">КриптоЛайт <span>/</span> <b>{{ t(`nav.${page}`) }}</b></div><div class="top-actions"><button class="language-button" @click="changeLanguage(locale==='ru'?'en':'ru')">{{ locale==='ru'?'RU':'EN' }} <span>⌄</span></button><button class="icon-button" @click="toggleTheme">☼</button></div></header>

      <section v-if="page==='sign'" class="content-view">
        <div class="page-heading"><div><div class="eyebrow">{{ t('signPage.eyebrow') }}</div><h1>{{ t('nav.sign') }}</h1><p>{{ t('signPage.description') }}</p></div><div class="heading-badge"><span class="status-dot" :class="{connected:status.available}"></span> {{ status.available ? t('cspFound') : t('disconnected') }}</div></div>
        <section class="settings-card"><div class="card-heading"><div><h2>{{ t('signPage.paramsTitle') }}</h2><p>{{ t('signPage.paramsHelp') }}</p></div><span class="step-number">01 <span>/ 02</span></span></div>
          <div class="form-grid"><label class="field"><span>{{ t('standard') }}</span><select v-model="standard"><option value="cades-bes" :disabled="!status.cadesAvailable">CAdES-BES{{ status.cadesAvailable?'':t('signPage.sdkMissing') }}</option><option value="cades-t" disabled>{{ t('signPage.cadesTNote') }}</option><option value="cms">CMS / PKCS#7</option></select></label><label class="field"><span>{{ t('encoding') }}</span><select v-model="encoding"><option value="der">{{ t('signPage.derBinary') }}</option><option value="base64">Base64</option></select></label><label class="field"><span>{{ t('signatureType') }}</span><select v-model="signatureType"><option value="detached">{{ t('detached') }}</option><option value="attached">{{ t('attached') }}</option></select></label><label class="field"><span>{{ t('fileType') }}</span><select v-model="fileType"><option value="sig">.sig</option><option value="p7s">.p7s</option></select></label></div>
          <div class="field-row"><label class="field wide-field"><span>{{ t('certificates') }}</span><button class="picker-button" @click="openCertificatePicker('signing')"><span class="picker-leading">♙</span><span class="picker-copy"><b>{{ certificateNames.length ? certificateNames.join(', ') : t('signPage.selectCerts') }}</b><small>{{ t('signPage.windowsPersonalStore') }}</small></span><span class="picker-trailing">⌄</span></button></label><label class="field wide-field"><span>{{ t('output') }}</span><button class="picker-button" @click="chooseOutput"><span class="picker-leading">▱</span><span class="picker-copy"><b>{{ outputDir || t('signPage.sourceFolder') }}</b><small>{{ t('signPage.changeForList') }}</small></span><span class="picker-trailing">↗</span></button></label></div>
        </section>

        <section class="documents-card"><div class="card-heading doc-heading"><div><div class="title-line"><h2>{{ t('signPage.docsTitle') }}</h2><span class="count-chip">{{ documents.length }}</span></div><p>{{ t('signPage.docsHelp') }}</p></div><button class="outline-button" @click="chooseFiles"><span>＋</span> {{ t('add') }}</button></div>
          <div v-if="!documents.length" class="drop-zone" @click="chooseFiles"><div class="upload-icon"><span>↑</span></div><b>{{ t('drop') }}</b><p>{{ t('dropHint') }}</p><button class="browse-button">{{ t('signPage.chooseFiles') }} <span>↗</span></button><small>{{ t('signPage.supportedFormats') }}</small></div>
          <div v-else class="document-list"><article v-for="(doc,index) in documents" :key="doc.path" class="document-row"><input v-model="doc.selected" type="checkbox"/><div class="file-icon">{{ doc.name.split('.').pop()?.slice(0,3).toUpperCase() }}</div><div class="file-info"><b>{{ doc.name }}</b><small>{{ doc.path }}</small></div><span class="file-ready">{{ t('signPage.readyToSign') }}</span><button class="remove-button" @click="documents.splice(index,1)">×</button></article><button class="add-more" @click="chooseFiles">{{ t('signPage.addMoreDocs') }}</button></div>
          <div class="documents-footer"><span>{{ t('signPage.selectedOf') }} <b>{{ selectedCount }}</b> {{ t('signPage.ofDocs') }} {{ documents.length }} {{ t('signPage.documents') }}</span><span class="supported"><i></i> {{ t('signPage.filesStayLocal') }}</span></div>
        </section>
        <footer class="action-bar"><div class="action-note"><span class="lock-icon">♙</span><span><b>{{ t('signPage.signProtected') }}</b><small>{{ t('signPage.privateKeyStays') }}</small><small v-if="signingMessage" class="signing-message">{{ signingMessage }}</small><small v-else-if="standard==='cades-t'" class="signing-message">{{ t('signPage.cadesTLater') }}</small><small v-else-if="standard==='cades-bes'&&!status.cadesAvailable" class="signing-message">{{ t('signPage.cadesSdkRequired') }}</small></span></div><button class="sign-button" :disabled="!canSign" :title="!status.available?t('unavailable'):standard==='cades-t'?t('signPage.cadesNotConnected'):standard==='cades-bes'&&!status.cadesAvailable?t('signPage.cadesSdkTitle'):selectedCount===0?t('signPage.chooseDocs'):selectedCertIds.length===0?t('signPage.chooseCerts'):standard==='cades-bes'&&selectedCertIds.length>1?t('signPage.cadesSingleCert'):''" @click="signSelectedDocument"><span>✳</span> {{ signingInProgress ? t('signPage.signingInProgress') : t('sign') }} <span class="button-arrow">→</span></button></footer>
      </section>

      <section v-else-if="page==='verify'" class="content-view verify-view">
        <div class="page-heading"><div><div class="eyebrow">CMS / PKCS#7</div><h1>{{ t('nav.verify') }}</h1><p>{{ t('verifyPage.description') }}</p></div><div class="heading-badge"><span class="status-dot" :class="{connected:status.available}"></span> {{ status.available ? t('cspFound') : t('disconnected') }}</div></div>
        <section class="settings-card verify-card"><div class="card-heading"><div><h2>{{ t('verifyPage.filesTitle') }}</h2><p>{{ t('verifyPage.filesHelp') }}</p></div><span class="step-number">01 <span>/ 01</span></span></div>
          <div class="verify-fields"><label class="field"><span>{{ t('verifyPage.signatureKind') }}</span><select v-model="verifyDetached" @change="verifyResult=null"><option :value="true">{{ t('detached') }}</option><option :value="false">{{ t('attached') }}</option></select></label><label class="field"><span>{{ t('verifyPage.encoding') }}</span><select v-model="verifyBase64"><option :value="false">{{ t('verifyPage.derBinary') }}</option><option :value="true">{{ t('verifyPage.base64Pem') }}</option></select></label></div>
          <div class="verify-file-field"><span>{{ t('verifyPage.signatureFile') }}</span><button class="picker-button" @click="chooseVerifySignature"><span class="picker-leading">✳</span><span class="picker-copy"><b>{{ verifySignaturePath || t('verifyPage.chooseSignature') }}</b><small>{{ t('verifyPage.cmsSupported') }}</small></span><span class="picker-trailing">↗</span></button></div>
          <div v-if="verifyDetached" class="verify-file-field"><span>{{ t('verifyPage.sourceDoc') }}</span><button class="picker-button" @click="chooseVerifyContent"><span class="picker-leading">▱</span><span class="picker-copy"><b>{{ verifyContentPath || t('verifyPage.chooseOriginal') }}</b><small>{{ t('verifyPage.contentCompared') }}</small></span><span class="picker-trailing">↗</span></button></div>
        </section>
        <section v-if="verifyResult" class="verify-result" :class="verifyResult.valid?'valid':'invalid'"><header><span class="verify-result-icon">{{ verifyResult.valid?'✓':'!' }}</span><div><h2>{{ verifyResult.valid?t('verifyPage.valid'):t('verifyPage.invalid') }}</h2><p>{{ verifyResult.message }}</p></div></header><div v-if="verifyResult.signers.length" class="verify-signer-list"><article v-for="(signer,index) in verifyResult.signers" :key="index" class="verify-signer"><b>{{ signer.subject || t('verifyPage.signer') }}</b><small>{{ t('verifyPage.issuer') }}{{ signer.issuer }}</small><small>{{ t('verifyPage.validUntil') }}{{ signer.expiresAt }}</small><small class="chain-status" :class="signer.chainTrusted?'trusted':'untrusted'">{{ signer.chainMessage }}</small></article></div></section>
        <footer class="action-bar verify-action"><div class="action-note"><span class="lock-icon">✓</span><span><b>{{ t('verifyPage.checkLocal') }}</b><small>{{ t('verifyPage.checkLocalHelp') }}</small></span></div><button class="sign-button" :disabled="!status.available || !verifySignaturePath || (verifyDetached && !verifyContentPath) || verifyProgress" @click="runVerify">{{ verifyProgress?t('verifyPage.checking'):t('verifyPage.runVerify') }} <span class="button-arrow">→</span></button></footer>
      </section>

      <section v-else-if="page==='encrypt'" class="content-view encrypt-view">
        <div class="page-heading"><div><div class="eyebrow">CMS / PKCS#7 · ENVELOPEDDATA</div><h1>{{ t('nav.encrypt') }}</h1><p>{{ t('encryptPage.description') }}</p></div><div class="heading-badge"><span class="status-dot" :class="{connected:status.available}"></span> {{ status.available ? t('cspFound') : t('disconnected') }}</div></div>
        <section class="settings-card"><div class="card-heading"><div><h2>{{ t('encryptPage.modeTitle') }}</h2><p>{{ t('encryptPage.modeHelp') }}</p></div><span class="step-number">01 <span>/ 02</span></span></div>
          <div class="form-grid"><label class="field"><span>{{ t('encryptPage.operation') }}</span><select v-model="cryptoMode"><option value="encrypt">{{ t('encryptPage.encrypt') }}</option><option value="decrypt">{{ t('encryptPage.decrypt') }}</option></select></label><label class="field"><span>{{ t('encryptPage.encoding') }}</span><select v-model="cryptoEncoding"><option value="der">{{ t('encryptPage.derBinary') }}</option><option value="base64">Base64</option></select></label><label class="field wide-field"><span>{{ t('encryptPage.saveFolder') }}</span><button class="picker-button" @click="chooseCryptoOutput"><span class="picker-leading">▱</span><span class="picker-copy"><b>{{ cryptoOutputDir || t('encryptPage.sourceFolder') }}</b><small>{{ t('encryptPage.changeForList') }}</small></span><span class="picker-trailing">↗</span></button></label></div>
          <div v-if="cryptoMode==='encrypt'" class="field-row"><label class="field wide-field"><span>{{ t('encryptPage.recipients') }}</span><button class="picker-button" @click="openRecipientPicker"><span class="picker-leading">♙</span><span class="picker-copy"><b>{{ cryptoRecipientNames.length ? cryptoRecipientNames.join(', ') : t('encryptPage.chooseRecipients') }}</b><small>{{ t('encryptPage.recipientsHelp') }}</small></span><span class="picker-trailing">⌄</span></button></label></div>
        </section>

        <section class="documents-card"><div class="card-heading doc-heading"><div><div class="title-line"><h2>{{ cryptoMode==='encrypt'?t('encryptPage.filesEncrypt'):t('encryptPage.filesDecrypt') }}</h2><span class="count-chip">{{ cryptoFiles.length }}</span></div><p>{{ t('encryptPage.filesHelp') }}</p></div><button class="outline-button" @click="chooseCryptoFiles"><span>＋</span> {{ t('add') }}</button></div>
          <div v-if="!cryptoFiles.length" class="drop-zone" @click="chooseCryptoFiles"><div class="upload-icon"><span>◇</span></div><b>{{ cryptoMode==='encrypt'?t('encryptPage.dropEncrypt'):t('encryptPage.dropDecrypt') }}</b><p>{{ t('encryptPage.orChoose') }}</p><button class="browse-button">{{ t('encryptPage.chooseFiles') }} <span>↗</span></button><small v-if="cryptoMode==='encrypt'">{{ t('encryptPage.encryptToEnc') }}</small><small v-else>{{ t('encryptPage.decryptSupported') }}</small></div>
          <div v-else class="document-list"><article v-for="(doc,index) in cryptoFiles" :key="doc.path" class="document-row"><input v-model="doc.selected" type="checkbox"/><div class="file-icon">{{ doc.name.split('.').pop()?.slice(0,3).toUpperCase() }}</div><div class="file-info"><b>{{ doc.name }}</b><small>{{ doc.path }}</small></div><span class="file-ready">{{ cryptoMode==='encrypt'?t('encryptPage.readyEncrypt'):t('encryptPage.readyDecrypt') }}</span><button class="remove-button" @click="cryptoFiles.splice(index,1)">×</button></article><button class="add-more" @click="chooseCryptoFiles">{{ t('encryptPage.addMore') }}</button></div>
          <div class="documents-footer"><span>{{ t('encryptPage.selectedOf') }} <b>{{ cryptoSelectedCount }}</b> {{ t('encryptPage.ofFiles') }} {{ cryptoFiles.length }} {{ t('encryptPage.files') }}</span><span class="supported"><i></i> {{ t('encryptPage.filesStayLocal') }}</span></div>
        </section>
        <footer class="action-bar"><div class="action-note"><span class="lock-icon">◇</span><span><b>{{ t('encryptPage.dataProtection') }}</b><small>{{ t('encryptPage.dataProtectionHelp') }}</small><small v-if="cryptoMessage" class="signing-message">{{ cryptoMessage }}</small></span></div><button class="sign-button" :disabled="cryptoMode==='encrypt'? !canEncrypt : !canDecrypt" :title="!status.available?t('unavailable'):cryptoMode==='encrypt'&&cryptoSelectedCount===0?t('encryptPage.chooseFilesBtn'):cryptoMode==='encrypt'&&!cryptoRecipientIds.length?t('encryptPage.chooseRecipientsBtn'):''" @click="runCrypto"><span>◇</span> {{ cryptoProgress ? (cryptoMode==='encrypt'?t('encryptPage.encrypting'):t('encryptPage.decrypting')) : (cryptoMode==='encrypt'?t('encryptPage.encrypt'):t('encryptPage.decrypt')) }} <span class="button-arrow">→</span></button></footer>
      </section>

      <section v-else-if="page==='settings'" class="content-view settings-view">
        <div class="page-heading"><div><div class="eyebrow">CRYPTOLITE · PREFERENCES</div><h1>{{ t('nav.settings') }}</h1><p>{{ t('settings.intro') }}</p></div><div class="settings-save-state" :class="{ error: settingsError }">{{ settingsError || (settingsSaveState ? t(`settings.${settingsSaveState}`) : t('settings.autoSave')) }}</div></div>
        <section class="settings-card"><div class="card-heading"><div><h2>{{ t('settings.appearance') }}</h2><p>{{ t('settings.appearanceHelp') }}</p></div></div><div class="form-grid settings-grid"><label class="field"><span>{{ t('settings.language') }}</span><select v-model="appSettings.language"><option value="system">{{ t('settings.systemLanguage') }} ({{ systemLanguage==='ru'?'Русский':'English' }})</option><option value="ru">Русский</option><option value="en">English</option></select></label><label class="field"><span>{{ t('settings.theme') }}</span><select v-model="appSettings.theme"><option value="system">{{ t('settings.systemTheme') }}</option><option value="light">{{ t('settings.lightTheme') }}</option><option value="dark">{{ t('settings.darkTheme') }}</option></select></label><label class="settings-toggle"><input v-model="appSettings.animations" type="checkbox"/><span><b>{{ t('settings.animations') }}</b><small>{{ t('settings.animationsHelp') }}</small></span></label></div></section>
        <section class="settings-card"><div class="card-heading"><div><h2>{{ t('settings.signingDefaults') }}</h2><p>{{ t('settings.signingHelp') }}</p></div></div><div class="form-grid settings-grid"><label class="field"><span>{{ t('standard') }}</span><select v-model="appSettings.defaultStandard"><option value="cms">CMS / PKCS#7</option><option value="cades-bes">CAdES-BES</option><option value="cades-t">CAdES-T</option></select></label><label class="field"><span>{{ t('encoding') }}</span><select v-model="appSettings.defaultEncoding"><option value="der">DER · бинарная</option><option value="base64">Base64</option></select></label><label class="field"><span>{{ t('signatureType') }}</span><select v-model="appSettings.defaultDetached"><option :value="true">{{ t('detached') }}</option><option :value="false">{{ t('attached') }}</option></select></label><label class="field"><span>{{ t('settings.extension') }}</span><select v-model="appSettings.defaultSignatureExtension"><option value="sig">.sig</option><option value="p7s">.p7s</option></select></label><label class="field settings-output"><span>{{ t('settings.outputFolder') }}</span><input v-model="appSettings.defaultOutputDirectory" :placeholder="t('settings.outputPlaceholder')"/></label></div><label class="settings-toggle remember-toggle"><input v-model="appSettings.saveLastSigningSettings" type="checkbox"/><span><b>{{ t('settings.remember') }}</b><small>{{ t('settings.rememberHelp') }}</small></span></label></section>
        <section class="settings-card"><div class="card-heading"><div><h2>{{ t('settings.defaultCerts') }}</h2><p>{{ t('settings.certsHelp') }}</p></div></div><div class="default-cert-picker"><div class="default-cert-summary"><template v-if="defaultCertificateNames.length"><b v-for="name in defaultCertificateNames" :key="name">{{ name }}</b></template><span v-else>{{ t('settings.noDefaultCert') }}</span></div><button class="outline-button" @click="openCertificatePicker('defaults')">{{ t('settings.chooseCert') }}</button></div></section>
        <section class="settings-card"><div class="card-heading"><div><h2>{{ t('settings.tsp') }}</h2><p>{{ t('settings.tspHelp') }}</p></div></div><label class="field"><span>{{ t('settings.tspServer') }}</span><input v-model="appSettings.tspServer" type="url" placeholder="https://tsa.example.ru/"/></label></section>
      </section>

      <section v-else-if="page==='about'" class="content-view about-view">
        <div class="page-heading"><div><div class="eyebrow">CRYPTOLITE · PROJECT</div><h1>{{ t('nav.about') }}</h1><p>{{ t('about.intro') }}</p></div></div>
        <section class="about-hero"><div class="brand-mark about-mark">К</div><div><h2>КриптоЛайт</h2><p>{{ t('about.description') }}</p><span>{{ t('about.version') }} 0.1.0</span></div></section>
        <div class="about-grid"><section class="settings-card"><div class="card-heading"><div><h2>{{ t('about.provider') }}</h2><p>{{ status.available ? status.message : t('about.providerMissing') }}</p></div></div><dl class="about-details"><div><dt>{{ t('cspFound') }}</dt><dd>{{ status.available ? (status.version || `${t('about.providerType')} ${status.providerType ?? '—'}`) : t('about.providerMissing') }}</dd></div><div><dt>{{ t('about.cades') }}</dt><dd>{{ status.cadesAvailable ? t('about.available') : t('about.missing') }}</dd></div></dl></section><section class="settings-card"><div class="card-heading"><div><h2>{{ t('about.technologies') }}</h2><p>{{ t('about.technologiesHelp') }}</p></div></div><ul class="technology-list"><li>Rust · Tauri 2</li><li>Vue 3 · TypeScript</li><li>Tailwind CSS · Vue I18n</li><li>{{ t('about.crypto') }}</li></ul></section></div>
        <section class="settings-card about-license"><div class="card-heading"><div><h2>{{ t('about.licenseTitle') }}</h2><p>{{ t('about.licenseIntro') }}</p></div></div><p>{{ t('about.disclaimer') }}</p><span class="license-name">{{ t('about.licenseLink') }}</span></section>
      </section>

      <section v-else class="placeholder-view"><div class="placeholder-icon">◇</div><div class="eyebrow">CRYPTOLITE · 0.1.0</div><h1>{{ t(`nav.${page}`) }}</h1><p>{{ t('placeholder.description') }}</p><button class="outline-button" @click="page='sign'">{{ t('placeholder.goSign') }}</button></section>
    </main>
    <div v-if="showAlert" class="modal-backdrop"><section class="alert-modal"><div class="alert-icon">!</div><h2>{{ t('dialogTitle') }}</h2><p>{{ t('unavailable') }}</p><div class="alert-detail">{{ status.message }}</div><button @click="showAlert=false">{{ t('dismiss') }}</button></section></div>
    <div v-if="certPickerOpen" class="modal-backdrop" @click.self="certPickerOpen=false"><section class="certificate-modal"><header class="certificate-header"><div><div class="eyebrow">CRYPTOPRO CSP</div><h2>{{ certPickerMode==='encryption'?t('certPicker.recipients'):t('certPicker.signing') }}</h2><p>{{ t('certPicker.listRefresh') }}</p></div><button class="modal-close" @click="certPickerOpen=false">×</button></header><label class="certificate-search"><span>⌕</span><input v-model="certFilter" :placeholder="t('certPicker.filterPlaceholder')"/></label><div v-if="certsLoading" class="certificate-empty">{{ t('certPicker.loading') }}</div><div v-else-if="certsError" class="certificate-empty error">{{ certsError }}</div><div v-else-if="!filteredCertificates.length" class="certificate-empty"><div class="empty-certificate-icon">♙</div><b>{{ certificates.length ? t('certPicker.notFound') : t('certPicker.storeEmpty') }}</b><p>{{ certificates.length ? t('certPicker.changeFilter') : t('certPicker.storeEmptyHint') }}</p></div><div v-else class="certificate-list"><label v-for="certificate in filteredCertificates" :key="certificate.id" class="certificate-row" :class="{ expired: certificate.expired }"><input v-model="pickerDraftCertIds" type="checkbox" :value="certificate.id" :disabled="certificate.expired"/><div class="certificate-avatar">♙</div><div class="certificate-info"><b>{{ certificate.subject }}</b><span>{{ t('certPicker.issuer') }}{{ certificate.issuer }}</span><small>{{ certificate.expired ? t('certPicker.expired') : t('certPicker.validUntil') }} {{ certificate.expiresAt }} · {{ certificate.hasPrivateKey ? t('certPicker.keyLinked') : t('certPicker.keyNotLinked') }}</small></div><span class="certificate-source">{{ certificate.expired ? t('certPicker.invalid') : certificate.source }}</span></label></div><footer class="certificate-footer"><span>{{ t('certPicker.selected') }}{{ pickerDraftCertIds.length }}</span><div><button class="outline-button" @click="pickerDraftCertIds=[]">{{ t('certPicker.reset') }}</button><button class="outline-button" @click="certPickerOpen=false">{{ t('certPicker.cancel') }}</button><button class="sign-button" @click="confirmCertificates">{{ t('certPicker.select') }}</button></div></footer></section></div>
    <div v-if="signReportOpen" class="modal-backdrop" @click.self="signReportOpen=false"><section class="sign-report-modal"><header class="certificate-header"><div><div class="eyebrow">CRYPTOLITE · CMS / PKCS#7</div><h2>{{ t('signReport.title') }}</h2><p>{{ t('signReport.help') }}</p></div><button class="modal-close" @click="signReportOpen=false">×</button></header><div class="sign-report-summary"><div class="sign-report-count success"><b>{{ signSuccessCount }}</b><span>{{ t('signReport.success') }}</span></div><div class="sign-report-count error"><b>{{ signErrorCount }}</b><span>{{ t('signReport.error') }}</span></div></div><div class="sign-report-list"><article v-for="item in signReportItems" :key="item.inputPath" class="sign-report-row" :class="item.success?'success':'error'"><span class="report-status">{{ item.success?'✓':'!' }}</span><div class="sign-report-details"><b>{{ item.inputPath.split(/[\\/]/).pop() }}</b><small>{{ item.success ? item.outputPath : item.error }}</small></div></article></div><footer class="certificate-footer"><span>{{ signReportItems.length }} {{ t('signReport.documentsCount') }}</span><button class="sign-button" @click="signReportOpen=false">{{ t('signReport.done') }}</button></footer></section></div>
    <div v-if="cryptoReportOpen" class="modal-backdrop" @click.self="cryptoReportOpen=false"><section class="sign-report-modal"><header class="certificate-header"><div><div class="eyebrow">CRYPTOLITE · CMS ENVELOPEDDATA</div><h2>{{ cryptoMode==='encrypt'?t('cryptoReport.encryptTitle'):t('cryptoReport.decryptTitle') }}</h2><p>{{ t('cryptoReport.help') }}</p></div><button class="modal-close" @click="cryptoReportOpen=false">×</button></header><div class="sign-report-summary"><div class="sign-report-count success"><b>{{ cryptoSuccessCount }}</b><span>{{ t('cryptoReport.success') }}</span></div><div class="sign-report-count error"><b>{{ cryptoErrorCount }}</b><span>{{ t('cryptoReport.error') }}</span></div></div><div class="sign-report-list"><article v-for="item in cryptoReportItems" :key="item.inputPath" class="sign-report-row" :class="item.success?'success':'error'"><span class="report-status">{{ item.success?'✓':'!' }}</span><div class="sign-report-details"><b>{{ item.inputPath.split(/[\\/]/).pop() }}</b><small>{{ item.success ? item.outputPath : item.error }}</small></div></article></div><footer class="certificate-footer"><span>{{ cryptoReportItems.length }} {{ t('cryptoReport.filesCount') }}</span><button class="sign-button" @click="cryptoReportOpen=false">{{ t('cryptoReport.done') }}</button></footer></section></div>
  </div>
</template>

