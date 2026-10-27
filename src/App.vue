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
const { t, locale } = useI18n();
const systemLanguage = navigator.language.toLowerCase().startsWith('ru') ? 'ru' : 'en';
const page = ref('sign');
const documents = ref<Doc[]>([]);
const status = ref<CspStatus>({ available: false, cadesAvailable: false, signingAvailable: false, message: 'Проверка КриптоПро CSP…' });
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
const certPickerMode = ref<'signing' | 'defaults'>('signing');
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
let unlistenDrop: (() => void) | undefined;
let unlistenSystemTheme: (() => void) | undefined;
const outputDir = ref('');
const isDark = ref(localStorage.getItem('cryptolite.theme') === 'dark');
let settingsSaveQueue: Promise<unknown> = Promise.resolve();
const selectedCount = computed(() => documents.value.filter((document) => document.selected).length);
const selectedCertificate = computed(() => certificates.value.find((certificate) => certificate.id === selectedCertIds.value[0]));
const defaultCertificateNames = computed(() => certificates.value.filter((certificate) => appSettings.value.defaultCertificateIds.includes(certificate.id) && !certificate.expired).map((certificate) => certificate.subject));
const canSign = computed(() => status.value.available && (standard.value === 'cms' ? status.value.signingAvailable : standard.value === 'cades-bes' ? status.value.cadesAvailable : false) && selectedCount.value > 0 && selectedCertIds.value.length === 1 && !!selectedCertificate.value && !selectedCertificate.value.expired && !signingInProgress.value);
const signSuccessCount = computed(() => signReportItems.value.filter((item) => item.success).length);
const signErrorCount = computed(() => signReportItems.value.length - signSuccessCount.value);
const filteredCertificates = computed(() => certificates.value.filter((certificate) => certificate.subject.toLocaleLowerCase().includes(certFilter.value.toLocaleLowerCase())));

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
    settingsError.value = `Не удалось загрузить настройки: ${String(error)}`;
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
  settingsSaveQueue.then(() => { settingsSaveState.value = 'saved'; settingsError.value = ''; }).catch((error) => { settingsError.value = `Не удалось сохранить настройки: ${String(error)}`; });
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
  const result = await open({ multiple: false, title: 'Выберите файл подписи' });
  if (typeof result === 'string') { verifySignaturePath.value = result; verifyResult.value = null; }
}
async function chooseVerifyContent() {
  const result = await open({ multiple: false, title: 'Выберите исходный документ' });
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
  else selectedCertIds.value = activeIds;
  if (certPickerMode.value === 'signing') certificateNames.value = certificates.value.filter((certificate) => selectedCertIds.value.includes(certificate.id) && !certificate.expired).map((certificate) => certificate.subject);
  certPickerOpen.value = false;
}
async function signSelectedDocument() {
  const selected = documents.value.filter((document) => document.selected);
  if (!canSign.value || !selected.length || selectedCertIds.value.length !== 1) return;
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
        certificateId: selectedCertIds.value[0],
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
</script>

<template>
  <div class="app-shell" :class="{'drag-hover':dragHover}">
    <div v-if="dragHover" class="drop-overlay"><span>＋</span><b>{{ page==='verify'?'Отпустите подпись и исходный документ':'Отпустите файлы для добавления' }}</b></div>
    <aside class="sidebar">
      <div class="brand"><div class="brand-mark">К</div><div><div class="brand-name">КриптоЛайт</div><div class="brand-caption">{{ t('subtitle') }}</div></div></div>
      <div class="menu-label">WORKSPACE</div>
      <nav class="nav-list">
        <button v-for="item in ['sign','encrypt','verify']" :key="item" class="nav-item" :class="{active:page===item}" @click="page=item"><span class="nav-icon">{{ item==='sign'?'✳':item==='encrypt'?'◇':'✓' }}</span>{{ t(`nav.${item}`) }}<span v-if="page===item" class="active-dot"></span></button>
      </nav>
      <div class="menu-label secondary-label">PREFERENCES</div>
      <nav class="nav-list">
        <button v-for="item in ['settings','about']" :key="item" class="nav-item" :class="{active:page===item}" @click="page=item"><span class="nav-icon">{{ item==='settings'?'⚙':'ⓘ' }}</span>{{ t(`nav.${item}`) }}</button>
      </nav>
      <div class="sidebar-bottom"><div class="csp-card"><span class="status-dot" :class="{connected:status.available}"></span><div><b>{{ status.available ? t('cspFound') : t('disconnected') }}</b><small>{{ status.available ? status.message : 'CryptoLite 0.1.0' }}</small></div><span class="refresh">↻</span></div><div class="profile"><div class="avatar">К</div><div class="profile-text"><b>Локальный профиль</b><small>Безопасная обработка</small></div></div></div>
    </aside>

    <main class="main-area">
      <header class="topbar"><div class="breadcrumb">КриптоЛайт <span>/</span> <b>{{ t(`nav.${page}`) }}</b></div><div class="top-actions"><div class="secure-label"><span>◈</span> Локальная обработка</div><button class="language-button" @click="changeLanguage(locale==='ru'?'en':'ru')">{{ locale==='ru'?'RU':'EN' }} <span>⌄</span></button><button class="icon-button" @click="toggleTheme">☼</button></div></header>

      <section v-if="page==='sign'" class="content-view">
        <div class="page-heading"><div><div class="eyebrow">DOCUMENT WORKFLOW</div><h1>{{ t('nav.sign') }}</h1><p>Создайте электронную подпись для одного или нескольких документов.</p></div><div class="heading-badge"><span class="status-dot" :class="{connected:status.available}"></span> {{ status.available ? t('cspFound') : t('disconnected') }}</div></div>
        <section class="settings-card"><div class="card-heading"><div><h2>Параметры подписи</h2><p>Выберите формат и сертификаты для подписания.</p></div><span class="step-number">01 <span>/ 02</span></span></div>
          <div class="form-grid"><label class="field"><span>{{ t('standard') }}</span><select v-model="standard"><option value="cades-bes" :disabled="!status.cadesAvailable">CAdES-BES{{ status.cadesAvailable?'':' · SDK не найден' }}</option><option value="cades-t" disabled>CAdES-T · задайте TSP позже</option><option value="cms">CMS / PKCS#7</option></select></label><label class="field"><span>{{ t('encoding') }}</span><select v-model="encoding"><option value="der">DER · бинарный</option><option value="base64">Base64</option></select></label><label class="field"><span>{{ t('signatureType') }}</span><select v-model="signatureType"><option value="detached">{{ t('detached') }}</option><option value="attached">{{ t('attached') }}</option></select></label><label class="field"><span>{{ t('fileType') }}</span><select v-model="fileType"><option value="sig">.sig</option><option value="p7s">.p7s</option></select></label></div>
          <div class="field-row"><label class="field wide-field"><span>{{ t('certificates') }}</span><button class="picker-button" @click="openCertificatePicker('signing')"><span class="picker-leading">♙</span><span class="picker-copy"><b>{{ certificateNames.length ? certificateNames.join(', ') : 'Выберите сертификаты' }}</b><small>Windows · Личное хранилище</small></span><span class="picker-trailing">⌄</span></button></label><label class="field wide-field"><span>{{ t('output') }}</span><button class="picker-button" @click="chooseOutput"><span class="picker-leading">▱</span><span class="picker-copy"><b>{{ outputDir || 'Папка исходного документа' }}</b><small>Можно изменить для этого списка</small></span><span class="picker-trailing">↗</span></button></label></div>
        </section>

        <section class="documents-card"><div class="card-heading doc-heading"><div><div class="title-line"><h2>Документы</h2><span class="count-chip">{{ documents.length }}</span></div><p>Добавьте файлы и отметьте те, которые нужно подписать.</p></div><button class="outline-button" @click="chooseFiles"><span>＋</span> {{ t('add') }}</button></div>
          <div v-if="!documents.length" class="drop-zone" @click="chooseFiles"><div class="upload-icon"><span>↑</span></div><b>{{ t('drop') }}</b><p>{{ t('dropHint') }}</p><button class="browse-button">Выбрать файлы <span>↗</span></button><small>PDF, DOCX, XLSX и другие форматы</small></div>
          <div v-else class="document-list"><article v-for="(doc,index) in documents" :key="doc.path" class="document-row"><input v-model="doc.selected" type="checkbox"/><div class="file-icon">{{ doc.name.split('.').pop()?.slice(0,3).toUpperCase() }}</div><div class="file-info"><b>{{ doc.name }}</b><small>{{ doc.path }}</small></div><span class="file-ready">Готов к подписанию</span><button class="remove-button" @click="documents.splice(index,1)">×</button></article><button class="add-more" @click="chooseFiles">＋ Добавить ещё документы</button></div>
          <div class="documents-footer"><span>Выбрано <b>{{ selectedCount }}</b> из {{ documents.length }} документов</span><span class="supported"><i></i> Файлы остаются на вашем устройстве</span></div>
        </section>
        <footer class="action-bar"><div class="action-note"><span class="lock-icon">♙</span><span><b>Подпись защищена</b><small>Закрытый ключ остаётся в КриптоПро CSP</small><small v-if="signingMessage" class="signing-message">{{ signingMessage }}</small><small v-else-if="standard==='cades-t'" class="signing-message">CAdES-T подключим после настройки TSP.</small><small v-else-if="standard==='cades-bes'&&!status.cadesAvailable" class="signing-message">Для CAdES-BES требуется установленный КриптоПро ЭЦП SDK.</small></span></div><button class="sign-button" :disabled="!canSign" :title="!status.available?t('unavailable'):standard==='cades-t'?'CAdES-T пока не подключён':standard==='cades-bes'&&!status.cadesAvailable?'Требуется КриптоПро ЭЦП SDK':selectedCount===0?'Выберите документы':selectedCertIds.length!==1?'Выберите один сертификат':''" @click="signSelectedDocument"><span>✳</span> {{ signingInProgress ? 'Подписание…' : t('sign') }} <span class="button-arrow">→</span></button></footer>
      </section>

      <section v-else-if="page==='verify'" class="content-view verify-view">
        <div class="page-heading"><div><div class="eyebrow">CMS / PKCS#7</div><h1>{{ t('nav.verify') }}</h1><p>Проверьте подпись и при необходимости укажите исходный документ.</p></div><div class="heading-badge"><span class="status-dot" :class="{connected:status.available}"></span> {{ status.available ? t('cspFound') : t('disconnected') }}</div></div>
        <section class="settings-card verify-card"><div class="card-heading"><div><h2>Файлы для проверки</h2><p>Для отсоединённой подписи нужен оригинал документа.</p></div><span class="step-number">01 <span>/ 01</span></span></div>
          <div class="verify-fields"><label class="field"><span>Вид подписи</span><select v-model="verifyDetached" @change="verifyResult=null"><option :value="true">Отсоединённая</option><option :value="false">Присоединённая</option></select></label><label class="field"><span>Кодировка</span><select v-model="verifyBase64"><option :value="false">DER · бинарная</option><option :value="true">Base64 / PEM</option></select></label></div>
          <div class="verify-file-field"><span>Файл подписи (.sig / .p7s)</span><button class="picker-button" @click="chooseVerifySignature"><span class="picker-leading">✳</span><span class="picker-copy"><b>{{ verifySignaturePath || 'Выберите файл подписи' }}</b><small>Поддерживаются CMS / PKCS#7 DER и Base64</small></span><span class="picker-trailing">↗</span></button></div>
          <div v-if="verifyDetached" class="verify-file-field"><span>Исходный документ</span><button class="picker-button" @click="chooseVerifyContent"><span class="picker-leading">▱</span><span class="picker-copy"><b>{{ verifyContentPath || 'Выберите оригинал документа' }}</b><small>Содержимое будет сверено с отсоединённой подписью</small></span><span class="picker-trailing">↗</span></button></div>
        </section>
        <section v-if="verifyResult" class="verify-result" :class="verifyResult.valid?'valid':'invalid'"><header><span class="verify-result-icon">{{ verifyResult.valid?'✓':'!' }}</span><div><h2>{{ verifyResult.valid?'Подпись действительна':'Подпись не подтверждена' }}</h2><p>{{ verifyResult.message }}</p></div></header><div v-if="verifyResult.signers.length" class="verify-signer-list"><article v-for="(signer,index) in verifyResult.signers" :key="index" class="verify-signer"><b>{{ signer.subject || 'Подписант' }}</b><small>Издатель: {{ signer.issuer }}</small><small>Сертификат действителен до {{ signer.expiresAt }}</small><small class="chain-status" :class="signer.chainTrusted?'trusted':'untrusted'">{{ signer.chainMessage }}</small></article></div></section>
        <footer class="action-bar verify-action"><div class="action-note"><span class="lock-icon">✓</span><span><b>Проверка выполняется локально</b><small>Проверяется криптографическая целостность подписи; доверие к цепочке сертификата оценивается отдельно.</small></span></div><button class="sign-button" :disabled="!status.available || !verifySignaturePath || (verifyDetached && !verifyContentPath) || verifyProgress" @click="runVerify">{{ verifyProgress?'Проверка…':'Проверить подпись' }} <span class="button-arrow">→</span></button></footer>
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

      <section v-else class="placeholder-view"><div class="placeholder-icon">◇</div><div class="eyebrow">CRYPTOLITE · 0.1.0</div><h1>{{ t(`nav.${page}`) }}</h1><p>Раздел будет реализован на следующем этапе.</p><button class="outline-button" @click="page='sign'">Перейти к подписанию →</button></section>
    </main>
    <div v-if="showAlert" class="modal-backdrop"><section class="alert-modal"><div class="alert-icon">!</div><h2>{{ t('dialogTitle') }}</h2><p>{{ t('unavailable') }}</p><div class="alert-detail">{{ status.message }}</div><button @click="showAlert=false">{{ t('dismiss') }}</button></section></div>
    <div v-if="certPickerOpen" class="modal-backdrop" @click.self="certPickerOpen=false"><section class="certificate-modal"><header class="certificate-header"><div><div class="eyebrow">CRYPTOPRO CSP</div><h2>Сертификаты подписи</h2><p>Список обновляется при каждом открытии окна.</p></div><button class="modal-close" @click="certPickerOpen=false">×</button></header><label class="certificate-search"><span>⌕</span><input v-model="certFilter" placeholder="Фильтр по имени владельца"/></label><div v-if="certsLoading" class="certificate-empty">Загрузка сертификатов…</div><div v-else-if="certsError" class="certificate-empty error">{{ certsError }}</div><div v-else-if="!filteredCertificates.length" class="certificate-empty"><div class="empty-certificate-icon">♙</div><b>{{ certificates.length ? 'Сертификаты не найдены' : 'Личное хранилище пусто' }}</b><p>{{ certificates.length ? 'Измените фильтр и попробуйте снова.' : 'Проверьте, что сертификат установлен в хранилище Windows «Личные» текущего пользователя.' }}</p></div><div v-else class="certificate-list"><label v-for="certificate in filteredCertificates" :key="certificate.id" class="certificate-row" :class="{ expired: certificate.expired }"><input v-model="pickerDraftCertIds" type="checkbox" :value="certificate.id" :disabled="certificate.expired"/><div class="certificate-avatar">♙</div><div class="certificate-info"><b>{{ certificate.subject }}</b><span>Издатель: {{ certificate.issuer }}</span><small>{{ certificate.expired ? 'Истёк срок действия' : 'Действителен до' }} {{ certificate.expiresAt }} · {{ certificate.hasPrivateKey ? 'связь с закрытым ключом настроена' : 'связь с закрытым ключом не найдена' }}</small></div><span class="certificate-source">{{ certificate.expired ? 'Недействителен' : certificate.source }}</span></label></div><footer class="certificate-footer"><span>Выбрано: {{ pickerDraftCertIds.length }}</span><div><button class="outline-button" @click="certPickerOpen=false">Отмена</button><button class="sign-button" @click="confirmCertificates">Выбрать</button></div></footer></section></div>
    <div v-if="signReportOpen" class="modal-backdrop" @click.self="signReportOpen=false"><section class="sign-report-modal"><header class="certificate-header"><div><div class="eyebrow">CRYPTOLITE · CMS / PKCS#7</div><h2>Подписание завершено</h2><p>Обработка выбранных документов окончена.</p></div><button class="modal-close" @click="signReportOpen=false">×</button></header><div class="sign-report-summary"><div class="sign-report-count success"><b>{{ signSuccessCount }}</b><span>Успешно</span></div><div class="sign-report-count error"><b>{{ signErrorCount }}</b><span>С ошибкой</span></div></div><div class="sign-report-list"><article v-for="item in signReportItems" :key="item.inputPath" class="sign-report-row" :class="item.success?'success':'error'"><span class="report-status">{{ item.success?'✓':'!' }}</span><div class="sign-report-details"><b>{{ item.inputPath.split(/[\\/]/).pop() }}</b><small>{{ item.success ? item.outputPath : item.error }}</small></div></article></div><footer class="certificate-footer"><span>{{ signReportItems.length }} документов</span><button class="sign-button" @click="signReportOpen=false">Готово</button></footer></section></div>
  </div>
</template>

