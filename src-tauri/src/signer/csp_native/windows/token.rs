#![allow(unsafe_code)]

//! Обнаружение Рутокенов и чтение сертификатов из их контейнеров.
//!
//! Считыватели и контейнеры перечисляются через CryptoPro CSP (`PP_ENUMREADERS`,
//! `PP_ENUMCONTAINERS`), но открываются только контейнеры обнаруженных токенов:
//! в личном хранилище пользователя есть сертификаты с контейнерами на отсутствующих
//! FAT12-дисках, и открытие такого контейнера показывает системный запрос «вставьте диск».
//!
//! Чтение сертификата из контейнера (`KP_CERTIFICATE`) и открытие контейнера идут
//! с `CRYPT_SILENT`: PIN спрашивается только при подписи, а не при перечислении.

use super::ffi;
use crate::tr;
use std::collections::HashMap;
use std::ffi::c_void;
use std::ptr;
use std::sync::{LazyLock, Mutex};

use windows::Win32::Globalization::{MultiByteToWideChar, CP_ACP, MULTI_BYTE_TO_WIDE_CHAR_FLAGS};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Security::Cryptography::{
    CertCloseStore, CertCreateCertificateContext, CertEnumCertificatesInStore,
    CertGetCertificateContextProperty, CertSetCertificateContextProperty, CryptAcquireContextW,
    CryptDestroyKey, CryptGetKeyParam, CryptGetProvParam, CryptGetUserKey, CryptReleaseContext,
    CERT_CONTEXT, CERT_KEY_PROV_INFO_PROP_ID, CRYPT_KEY_PROV_INFO, HCERTSTORE, X509_ASN_ENCODING,
};

/// `PP_ENUMCONTAINERS`: перечисление контейнеров провайдера.
const PP_ENUMCONTAINERS: u32 = 2;
/// `PP_NAME`: имя провайдера, нужно для `CryptAcquireContextW` по контейнеру.
const PP_NAME: u32 = 4;
/// `PP_USER_CERTSTORE`: хранилище сертификатов, привязанных к контейнерам.
const PP_USER_CERTSTORE: u32 = 42;
/// `PP_ENUMREADERS` (CryptoPro): перечисление считывателей и носителей.
const PP_ENUMREADERS: u32 = 114;

/// `KP_CERTIFICATE`: сертификат открытого ключа контейнера.
const KP_CERTIFICATE: u32 = 26;

const CRYPT_FIRST: u32 = 0x0000_0001;
const CRYPT_NEXT: u32 = 0x0000_0002;
/// `CRYPT_FQCN`: полное имя контейнера (`\\.\<считыватель>\<контейнер>`).
const CRYPT_FQCN: u32 = 0x0000_0010;
const CRYPT_MEDIA: u32 = 0x0000_0020;
const CRYPT_AVAILABLE: u32 = 0x0000_0040;
/// `CRYPT_SILENT`: CSP не показывает диалоги (в том числе ввод PIN) при открытии.
const CRYPT_SILENT: u32 = 0x0000_0040;

const ERROR_NO_MORE_ITEMS: u32 = 259;
const ERROR_MORE_DATA: u32 = 234;

/// Порядок типов провайдера — как в `probe`: 2012-256, 2012-512, 2001.
const PROVIDER_TYPES: [u32; 3] = [80, 81, 75];

/// Начальный размер буфера для параметров провайдера.
///
/// Длина, которую возвращает `CryptGetProvParam` для перечислимых параметров,
/// равна размеру переданного буфера, а не длине строки, поэтому строки разбираются
/// по завершающему нулю, а не по `pdwDataLen`.
const PARAM_BUFFER: usize = 2048;

/// Обнаруженный физический токен.
#[derive(Debug, Clone)]
pub(super) struct DetectedToken {
    /// Имя считывателя — префикс полного имени контейнера.
    pub reader: String,
    /// Короткая модель без префикса производителя: `Lite`, `ECP`.
    pub model: String,
    /// Идентификатор носителя: `rutoken_lt_...`.
    pub media_id: String,
}

/// Контейнер токена и провайдеры, через которые его видно.
#[derive(Debug, Clone)]
pub(super) struct TokenContainer {
    pub name: String,
    pub providers: Vec<(String, u32)>,
}

/// Всё, что нужно, чтобы получить контекст сертификата с закрытым ключом на токене.
///
/// Виден в пределах `csp_native`: те же данные нужны CAdESCOM, чтобы открыть
/// закрытый ключ контейнера.
#[derive(Debug, Clone)]
pub(in crate::signer::csp_native) struct TokenCertificateDetails {
    pub der: Vec<u8>,
    pub container: String,
    pub provider_name: String,
    pub provider_type: u32,
    pub key_spec: u32,
}

impl TokenCertificateDetails {
    /// Контекст сертификата со свойством `CERT_KEY_PROV_INFO_PROP_ID`.
    ///
    /// До создания контекста контейнер проверяется `CRYPT_SILENT`: если токен отключён,
    /// вызывающий получает ошибку и успевает откатиться на `CurrentUser\MY`.
    pub(super) fn to_context(&self) -> Result<ffi::CertificateContext, crate::signer::SignerError> {
        let container = wide(&self.container);
        let provider = wide(&self.provider_name);
        let mut handle = 0usize;
        let available = unsafe {
            CryptAcquireContextW(
                &mut handle,
                container.as_ptr(),
                provider.as_ptr(),
                self.provider_type,
                CRYPT_SILENT,
            )
        };
        if available == 0 {
            let code = unsafe { GetLastError() };
            return Err(crate::signer::SignerError::Signing(tr!(
                "контейнер ключа на токене недоступен (код Windows 0x{code:08X})",
                "the key container on the token is not available (Windows code 0x{code:08X})"
            )));
        }
        unsafe { CryptReleaseContext(handle, 0) };

        let encoded_length = u32::try_from(self.der.len()).map_err(|_| {
            crate::signer::SignerError::Signing(tr!(
                "сертификат токена слишком велик для CryptoAPI",
                "the token certificate is too large for CryptoAPI"
            ))
        })?;
        let context = unsafe {
            CertCreateCertificateContext(X509_ASN_ENCODING, self.der.as_ptr(), encoded_length)
        };
        if context.is_null() {
            let code = unsafe { GetLastError() };
            return Err(crate::signer::SignerError::Signing(tr!(
                "не удалось разобрать сертификат токена (код Windows 0x{code:08X})",
                "could not parse the token certificate (Windows code 0x{code:08X})"
            )));
        }
        let key_info = CRYPT_KEY_PROV_INFO {
            pwszContainerName: container.as_ptr() as *mut u16,
            pwszProvName: provider.as_ptr() as *mut u16,
            dwProvType: self.provider_type,
            dwFlags: 0,
            cProvParam: 0,
            rgProvParam: ptr::null_mut(),
            dwKeySpec: self.key_spec,
        };
        let applied = unsafe {
            CertSetCertificateContextProperty(
                context,
                CERT_KEY_PROV_INFO_PROP_ID,
                0,
                &key_info as *const CRYPT_KEY_PROV_INFO as *const c_void,
            )
        };
        if applied == 0 {
            let code = unsafe { GetLastError() };
            drop(ffi::CertificateContext::new(context));
            return Err(crate::signer::SignerError::Signing(tr!(
                "не удалось привязать сертификат токена к контейнеру (код Windows 0x{code:08X})",
                "could not bind the token certificate to its container (Windows code 0x{code:08X})"
            )));
        }
        Ok(ffi::CertificateContext::from_token(context, self.clone()))
    }
}

/// Реестр деталей контейнеров по идентификатору сертификата.
///
/// Ключ — стабильный `CertInfo.id` (издатель + серийный номер). Значение — все
/// найденные варианты: один сертификат может лежать на нескольких токенах.
static TOKEN_DETAILS: LazyLock<Mutex<HashMap<String, Vec<TokenCertificateDetails>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Полностью заменяет реестр: вызывается после каждого перечисления сертификатов.
pub(super) fn replace_token_details(map: HashMap<String, Vec<TokenCertificateDetails>>) {
    let mut details = TOKEN_DETAILS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    *details = map;
}

/// Детали контейнеров для сертификата из последнего перечисления.
pub(super) fn details_for_certificate(id: &str) -> Vec<TokenCertificateDetails> {
    let details = TOKEN_DETAILS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    details.get(id).cloned().unwrap_or_default()
}

/// Детали контейнера по идентификатору сертификата без предварительного перечисления.
///
/// Нужен, когда подпись запускается по сохранённому идентификатору раньше, чем
/// открывался список сертификатов. Сканируются только контейнеры обнаруженных токенов.
pub(super) fn find_details_by_id(id: &str) -> Option<TokenCertificateDetails> {
    if let Some(details) = details_for_certificate(id).into_iter().next() {
        return Some(details);
    }
    let tokens = detect_tokens().ok()?;
    let collected = collect_token_certificates(&tokens);
    let mut map: HashMap<String, Vec<TokenCertificateDetails>> = HashMap::new();
    let mut found = None;
    for (info, details) in collected {
        if let Some(details) = details {
            if info.id == id && found.is_none() {
                found = Some(details.clone());
            }
            map.entry(info.id).or_default().push(details);
        }
    }
    replace_token_details(map);
    found
}

/// Обнаруживает подключённые Рутокены по перечислению считывателей CryptoPro CSP.
pub(super) fn detect_tokens() -> Result<Vec<DetectedToken>, crate::signer::SignerError> {
    let mut tokens: Vec<DetectedToken> = Vec::new();
    let mut last_error = 0u32;
    let mut opened = 0usize;
    for provider_type in PROVIDER_TYPES {
        let provider = match ffi::acquire_provider(provider_type) {
            Ok(provider) => provider,
            Err(code) => {
                last_error = code;
                continue;
            }
        };
        opened += 1;
        let mut flags = CRYPT_FIRST | CRYPT_MEDIA | CRYPT_AVAILABLE;
        loop {
            let buffer = match provider_param(provider.handle(), PP_ENUMREADERS, flags) {
                Ok(buffer) => buffer,
                Err(code) => {
                    if code != ERROR_NO_MORE_ITEMS {
                        tracing::warn!(
                            provider_type,
                            code = format!("0x{code:08X}"),
                            "PP_ENUMREADERS failed"
                        );
                    }
                    break;
                }
            };
            flags = CRYPT_NEXT | CRYPT_MEDIA | CRYPT_AVAILABLE;
            let Some((description, reader, media)) = parse_reader_entry(&buffer) else {
                continue;
            };
            if !is_token_media(&media) {
                continue;
            }
            let model = normalize_model(&description, &reader);
            match tokens
                .iter_mut()
                .find(|token| token.media_id.eq_ignore_ascii_case(&media))
            {
                Some(existing) => {
                    if model_score(&description) > model_score(&existing.model) {
                        existing.reader = reader;
                        existing.model = model;
                    }
                }
                None => tokens.push(DetectedToken {
                    reader,
                    model,
                    media_id: media,
                }),
            }
        }
    }
    if opened == 0 {
        return Err(crate::signer::SignerError::CspNotFound(tr!(
            "ни один провайдер КриптоПро CSP не открылся (код Windows 0x{last_error:08X})",
            "no CryptoPro CSP provider could be opened (Windows code 0x{last_error:08X})"
        )));
    }
    tokens.sort_by(|left, right| left.reader.cmp(&right.reader));
    Ok(tokens)
}

/// Приоритет описания носителя: `Rutoken Lite`/`Rutoken ECP` информативнее
/// `Rutoken PKCS#11`, который CSP показывает для того же носителя.
fn model_score(description: &str) -> u8 {
    let lower = description.to_ascii_lowercase();
    if lower.contains("pkcs#11") {
        0
    } else if lower.contains("rutoken") {
        2
    } else {
        1
    }
}

/// Разбирает ответ `PP_ENUMREADERS`: описание носителя, считыватель, media id.
///
/// Ответ — три ANSI-строки через `\0`; дальше идёт `DWORD` флагов и выравнивание,
/// поэтому берутся только первые три строки.
fn parse_reader_entry(buffer: &[u8]) -> Option<(String, String, String)> {
    let fields = nul_fields(buffer);
    let description = decode_ansi(fields.first().copied()?);
    let reader = decode_ansi(fields.get(1).copied()?);
    let media = decode_ansi(fields.get(2).copied()?);
    if media.is_empty() {
        return None;
    }
    Some((description, reader, media))
}

/// Строки до первого пустого поля: остаток буфера — нулевое заполнение.
fn nul_fields(buffer: &[u8]) -> Vec<&[u8]> {
    buffer
        .split(|byte| *byte == 0)
        .take_while(|field| !field.is_empty())
        .collect()
}

/// Носитель принадлежит Рутокену: `rutoken_lt_...`, `rutoken_ecp_...`.
///
/// Пустые считыватели (`NO_MEDIA`), реестр (`NO_UNIQUE`), жёсткие диски (`FAT12_*`)
/// и JaCarta этим фильтром отбрасываются.
fn is_token_media(media: &str) -> bool {
    media.to_ascii_lowercase().starts_with("rutoken_")
}

/// Короткая модель токена: `Rutoken Lite` → `Lite`, `Aktiv Rutoken lite 0` → `Lite`.
fn normalize_model(description: &str, reader: &str) -> String {
    let raw = if description.trim().is_empty() {
        reader
    } else {
        description
    };
    let mut value = raw.trim().to_owned();
    loop {
        let lower = value.to_ascii_lowercase();
        let prefix = if lower.starts_with("aktiv ") {
            "aktiv ".len()
        } else if lower.starts_with("rutoken ") {
            "rutoken ".len()
        } else {
            break;
        };
        value = value[prefix..].to_owned();
    }
    let trimmed = value.trim_end();
    let cleaned = trimmed
        .rsplit_once(' ')
        .filter(|(_, tail)| !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()))
        .map(|(head, _)| head.trim_end())
        .unwrap_or(trimmed);
    let cleaned = if cleaned.is_empty() { trimmed } else { cleaned };
    let mut characters = cleaned.chars();
    match characters.next() {
        Some(first) => first.to_uppercase().chain(characters).collect(),
        None => String::new(),
    }
}

/// Строка источника для сертификата, прочитанного из контейнера токена.
pub(super) fn token_source(model: &str) -> String {
    let model = model.trim();
    if model.is_empty() {
        tr!(
            "Windows · Личное хранилище (Рутокен)",
            "Windows · Personal store (Rutoken)"
        )
    } else {
        tr!(
            "Windows · Личное хранилище (Рутокен {model})",
            "Windows · Personal store (Rutoken {model})"
        )
    }
}

/// Токен, которому принадлежит контейнер закрытого ключа.
pub(super) fn match_token<'a>(
    container: &str,
    tokens: &'a [DetectedToken],
) -> Option<&'a DetectedToken> {
    tokens
        .iter()
        .find(|token| container_belongs_to(container, token))
}

/// Контейнер относится к токену: полное имя начинается с `\\.\<считыватель>\`
/// либо содержит media id.
fn container_belongs_to(container: &str, token: &DetectedToken) -> bool {
    let container = container.to_ascii_lowercase();
    let reader_prefix = format!("\\\\.\\{}", token.reader.to_ascii_lowercase());
    container.starts_with(&reader_prefix)
        || container.contains(&token.media_id.to_ascii_lowercase())
}

/// Контейнеры токена, сгруппированные по имени, со всеми провайдерами, которые их видят.
pub(super) fn enum_token_containers(token: &DetectedToken) -> Vec<TokenContainer> {
    let mut containers: Vec<TokenContainer> = Vec::new();
    for provider_type in PROVIDER_TYPES {
        let provider = match ffi::acquire_provider(provider_type) {
            Ok(provider) => provider,
            Err(code) => {
                tracing::warn!(
                    provider_type,
                    code = format!("0x{code:08X}"),
                    "provider for container enumeration is unavailable"
                );
                continue;
            }
        };
        let provider_name = provider_param(provider.handle(), PP_NAME, 0)
            .ok()
            .and_then(|buffer| nul_fields(&buffer).first().map(|field| decode_ansi(field)))
            .unwrap_or_default();
        if provider_name.is_empty() {
            continue;
        }
        let mut flags = CRYPT_FIRST | CRYPT_FQCN;
        loop {
            let buffer = match provider_param(provider.handle(), PP_ENUMCONTAINERS, flags) {
                Ok(buffer) => buffer,
                Err(code) => {
                    if code != ERROR_NO_MORE_ITEMS {
                        tracing::warn!(
                            provider_type,
                            code = format!("0x{code:08X}"),
                            "PP_ENUMCONTAINERS failed"
                        );
                    }
                    break;
                }
            };
            flags = CRYPT_NEXT | CRYPT_FQCN;
            let Some(name) = nul_fields(&buffer).first().copied().map(decode_ansi) else {
                continue;
            };
            if name.is_empty() || !container_belongs_to(&name, token) {
                continue;
            }
            match containers.iter_mut().find(|entry| entry.name == name) {
                Some(entry) => entry.providers.push((provider_name.clone(), provider_type)),
                None => containers.push(TokenContainer {
                    name,
                    providers: vec![(provider_name.clone(), provider_type)],
                }),
            }
        }
    }
    containers
}

/// Читает сертификат открытого ключа контейнера.
///
/// Контейнер открывается `CRYPT_SILENT`, поэтому PIN не запрашивается. Порядок
/// спецификаций ключа тот же, что при подписи: `AT_SIGNATURE`, затем `AT_KEYEXCHANGE`.
fn read_container_certificate(container: &TokenContainer) -> Option<TokenCertificateDetails> {
    for (provider_name, provider_type) in &container.providers {
        let provider = match open_container(&container.name, provider_name, *provider_type) {
            Ok(provider) => provider,
            Err(code) => {
                tracing::warn!(
                    container = %container.name,
                    provider_type,
                    code = format!("0x{code:08X}"),
                    "token container is not available"
                );
                continue;
            }
        };
        let key_spec = match ffi::signing_key_spec(provider.handle()) {
            Ok(key_spec) => key_spec,
            Err(error) => {
                tracing::warn!(container = %container.name, %error, "token container has no key");
                continue;
            }
        };
        let mut key = 0usize;
        let got_key = unsafe { CryptGetUserKey(provider.handle(), key_spec, &mut key) };
        if got_key == 0 {
            tracing::warn!(container = %container.name, "CryptGetUserKey failed");
            continue;
        }
        let der = key_certificate(key);
        unsafe { CryptDestroyKey(key) };
        let Some(der) = der else {
            tracing::warn!(container = %container.name, "container has no KP_CERTIFICATE");
            continue;
        };
        return Some(TokenCertificateDetails {
            der,
            container: container.name.clone(),
            provider_name: provider_name.clone(),
            provider_type: *provider_type,
            key_spec,
        });
    }
    None
}

/// `KP_CERTIFICATE` ключа: размер, затем DER.
fn key_certificate(key: usize) -> Option<Vec<u8>> {
    let mut length = 0u32;
    let sized = unsafe { CryptGetKeyParam(key, KP_CERTIFICATE, ptr::null_mut(), &mut length, 0) };
    if sized == 0 || length == 0 {
        return None;
    }
    let mut der = vec![0u8; length as usize];
    let read = unsafe { CryptGetKeyParam(key, KP_CERTIFICATE, der.as_mut_ptr(), &mut length, 0) };
    if read == 0 || length == 0 {
        return None;
    }
    der.truncate(length as usize);
    Some(der)
}

/// Сертификаты всех контейнеров обнаруженных токенов.
///
/// Возвращает пару «сертификат для списка» и детали контейнера (если их удалось
/// получить) для последующей подписи. Дубликаты по `id` отбрасываются: первый
/// найденный контейнер выигрывает.
pub(super) fn collect_token_certificates(
    tokens: &[DetectedToken],
) -> Vec<(crate::signer::CertInfo, Option<TokenCertificateDetails>)> {
    let mut collected: Vec<(crate::signer::CertInfo, Option<TokenCertificateDetails>)> = Vec::new();
    for token in tokens {
        let source = token_source(&token.model);
        let containers = enum_token_containers(token);
        let mut found = 0usize;
        for container in &containers {
            let Some(details) = read_container_certificate(container) else {
                continue;
            };
            let context = match details.to_context() {
                Ok(context) => context,
                Err(error) => {
                    tracing::warn!(container = %container.name, %error, "token certificate is unusable");
                    continue;
                }
            };
            let Some(info) = (unsafe { ffi::read_certificate(context.as_ptr(), &source) }) else {
                continue;
            };
            if collected.iter().any(|(existing, _)| existing.id == info.id) {
                continue;
            }
            found += 1;
            collected.push((info, Some(details)));
        }
        if found == 0 {
            collected.extend(collect_from_user_certstore(token));
        }
    }
    collected
}

/// Fallback: хранилище сертификатов, привязанных к контейнерам токена.
///
/// Используется, только если `KP_CERTIFICATE` не дал ни одного сертификата.
/// Открывается первый доступный контейнер токена, отсутствующие диски не затрагиваются.
fn collect_from_user_certstore(
    token: &DetectedToken,
) -> Vec<(crate::signer::CertInfo, Option<TokenCertificateDetails>)> {
    let source = token_source(&token.model);
    let mut collected: Vec<(crate::signer::CertInfo, Option<TokenCertificateDetails>)> = Vec::new();
    let containers = enum_token_containers(token);
    for container in &containers {
        for (provider_name, provider_type) in &container.providers {
            let provider = match open_container(&container.name, provider_name, *provider_type) {
                Ok(provider) => provider,
                Err(_) => continue,
            };
            let Some(store) = user_certstore(provider.handle()) else {
                continue;
            };
            let mut previous: *const CERT_CONTEXT = ptr::null();
            loop {
                // CertEnumCertificatesInStore освобождает предыдущий контекст.
                let current = unsafe { CertEnumCertificatesInStore(store, previous) };
                if current.is_null() {
                    break;
                }
                previous = current;
                let Some(info) = (unsafe { ffi::read_certificate(current, &source) }) else {
                    continue;
                };
                if collected.iter().any(|(existing, _)| existing.id == info.id) {
                    continue;
                }
                let details = unsafe { certificate_details(current, &container.name) };
                collected.push((info, details));
            }
            unsafe { CertCloseStore(store, 0) };
            if !collected.is_empty() {
                return collected;
            }
        }
    }
    collected
}

/// Сведения о контейнере из сертификата в хранилище пользователя.
unsafe fn certificate_details(
    context: *const CERT_CONTEXT,
    container: &str,
) -> Option<TokenCertificateDetails> {
    let mut length = 0u32;
    let sized = CertGetCertificateContextProperty(
        context,
        CERT_KEY_PROV_INFO_PROP_ID,
        ptr::null_mut(),
        &mut length,
    );
    if sized == 0 || length == 0 {
        return None;
    }
    let mut bytes = vec![0u8; length as usize];
    let read = CertGetCertificateContextProperty(
        context,
        CERT_KEY_PROV_INFO_PROP_ID,
        bytes.as_mut_ptr() as *mut c_void,
        &mut length,
    );
    if read == 0 {
        return None;
    }
    let key_info = bytes.as_ptr() as *const CRYPT_KEY_PROV_INFO;
    let provider_name = wide_string((*key_info).pwszProvName)?;
    let container_name = wide_string((*key_info).pwszContainerName)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| container.to_owned());
    let context_ref = context.as_ref()?;
    if context_ref.cbCertEncoded == 0 || context_ref.pbCertEncoded.is_null() {
        return None;
    }
    let der = std::slice::from_raw_parts(
        context_ref.pbCertEncoded,
        context_ref.cbCertEncoded as usize,
    )
    .to_vec();
    Some(TokenCertificateDetails {
        der,
        container: container_name,
        provider_name,
        provider_type: (*key_info).dwProvType,
        key_spec: (*key_info).dwKeySpec,
    })
}

/// `PP_USER_CERTSTORE` открытого контейнера.
fn user_certstore(provider: usize) -> Option<HCERTSTORE> {
    let mut store: HCERTSTORE = ptr::null_mut();
    let mut length = std::mem::size_of::<HCERTSTORE>() as u32;
    let read = unsafe {
        CryptGetProvParam(
            provider,
            PP_USER_CERTSTORE,
            &mut store as *mut HCERTSTORE as *mut u8,
            &mut length,
            0,
        )
    };
    if read == 0 || store.is_null() {
        None
    } else {
        Some(store)
    }
}

/// Хранилища сертификатов всех обнаруженных токенов — для расшифрования.
///
/// На каждый токен открывается первый доступный контейнер; ошибки отдельных
/// токенов пропускаются.
pub(super) fn open_all_token_stores() -> Vec<ffi::CertificateStore> {
    let mut stores = Vec::new();
    let tokens = match detect_tokens() {
        Ok(tokens) => tokens,
        Err(error) => {
            tracing::warn!(%error, "token detection failed");
            return stores;
        }
    };
    for token in &tokens {
        let containers = enum_token_containers(token);
        let mut opened = false;
        for container in &containers {
            if opened {
                break;
            }
            for (provider_name, provider_type) in &container.providers {
                let Ok(provider) = open_container(&container.name, provider_name, *provider_type)
                else {
                    continue;
                };
                if let Some(store) = user_certstore(provider.handle()) {
                    stores.push(ffi::CertificateStore::from_handle(store));
                    opened = true;
                    break;
                }
            }
        }
        if !opened {
            tracing::warn!(reader = %token.reader, "token has no certificate store");
        }
    }
    stores
}

fn open_container(
    container: &str,
    provider_name: &str,
    provider_type: u32,
) -> Result<ffi::ProviderContext, u32> {
    let container = wide(container);
    let provider = wide(provider_name);
    let mut handle = 0usize;
    let acquired = unsafe {
        CryptAcquireContextW(
            &mut handle,
            container.as_ptr(),
            provider.as_ptr(),
            provider_type,
            CRYPT_SILENT,
        )
    };
    if acquired == 0 {
        Err(unsafe { GetLastError() })
    } else {
        Ok(ffi::ProviderContext::from_handle(handle))
    }
}

/// Читает параметр провайдера в буфер.
///
/// `pdwDataLen` у перечислимых параметров возвращается равным размеру буфера,
/// поэтому успешный вызов отдаёт весь буфер, а строки разбираются по `\0`.
fn provider_param(provider: usize, param: u32, flags: u32) -> Result<Vec<u8>, u32> {
    let mut capacity = PARAM_BUFFER;
    loop {
        let mut buffer = vec![0u8; capacity];
        let mut length = capacity as u32;
        let read =
            unsafe { CryptGetProvParam(provider, param, buffer.as_mut_ptr(), &mut length, flags) };
        if read != 0 {
            return Ok(buffer);
        }
        let code = unsafe { GetLastError() };
        let needed = length as usize;
        if code == ERROR_MORE_DATA && needed > capacity {
            capacity = needed;
            continue;
        }
        return Err(code);
    }
}

/// ANSI-строка CSP (кодовая страница ANSI) в Unicode.
fn decode_ansi(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let flags = MULTI_BYTE_TO_WIDE_CHAR_FLAGS(0);
    let needed = unsafe { MultiByteToWideChar(CP_ACP, flags, bytes, None) };
    if needed <= 0 {
        return String::new();
    }
    let mut wide_buffer = vec![0u16; needed as usize];
    let written = unsafe { MultiByteToWideChar(CP_ACP, flags, bytes, Some(&mut wide_buffer)) };
    if written <= 0 {
        return String::new();
    }
    String::from_utf16_lossy(&wide_buffer[..written as usize])
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// NUL-терминированная UTF-16 строка из структуры CryptoAPI.
unsafe fn wide_string(pointer: *const u16) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    let mut length = 0usize;
    while *pointer.add(length) != 0 {
        length += 1;
    }
    Some(String::from_utf16_lossy(std::slice::from_raw_parts(
        pointer, length,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(reader: &str, media: &str) -> DetectedToken {
        DetectedToken {
            reader: reader.to_owned(),
            model: normalize_model("", reader),
            media_id: media.to_owned(),
        }
    }

    #[test]
    fn reader_entry_is_description_reader_media() {
        let buffer = b"Rutoken Lite\0Aktiv Rutoken lite 0\0rutoken_lt_2cdc8558\0\x03\0\0\0";
        let (description, reader, media) = parse_reader_entry(buffer).expect("entry parsed");
        assert_eq!(description, "Rutoken Lite");
        assert_eq!(reader, "Aktiv Rutoken lite 0");
        assert_eq!(media, "rutoken_lt_2cdc8558");
    }

    #[test]
    fn reader_entries_without_token_media_are_skipped() {
        for buffer in [
            &b"\xd0\xe5\xe5\xf1\xf2\xf0\0REGISTRY\0NO_UNIQUE\0\x03\0\0\0"[..],
            &b"\xc4\xe8\xf1\xea Z\0FAT12_Z\0NO_MEDIA\0"[..],
            &b"JaCarta\0JaCarta Reader 0\0jcart_1\0"[..],
        ] {
            let (_, _, media) = parse_reader_entry(buffer).expect("entry parsed");
            assert!(
                !is_token_media(&media),
                "media {media} must be filtered out"
            );
        }
        let (_, reader, media) =
            parse_reader_entry(b"Rutoken ECP\0Aktiv Rutoken ECP 0\0rutoken_ecp_41\0")
                .expect("entry");
        assert_eq!(reader, "Aktiv Rutoken ECP 0");
        assert_eq!(media, "rutoken_ecp_41");
        assert!(is_token_media(&media));
    }

    #[test]
    fn model_is_shortened_to_the_device_name() {
        assert_eq!(
            normalize_model("Rutoken Lite", "Aktiv Rutoken lite 0"),
            "Lite"
        );
        assert_eq!(normalize_model("Aktiv Rutoken lite 0", ""), "Lite");
        assert_eq!(normalize_model("Rutoken ECP", "Aktiv Rutoken ECP 0"), "ECP");
        assert_eq!(normalize_model("Rutoken PKCS#11", ""), "PKCS#11");
        assert_eq!(normalize_model("", "Aktiv Rutoken lite 0"), "Lite");
        assert_eq!(normalize_model("", ""), "");
    }

    #[test]
    fn container_matches_its_token() {
        let lite = token("Aktiv Rutoken lite 0", "rutoken_lt_2cdc8558");
        assert!(container_belongs_to(
            "\\\\.\\Aktiv Rutoken lite 0\\1022202864452 831094549 - copy",
            &lite
        ));
        assert!(!container_belongs_to(
            "FAT12\\EE75EC20_файлы\\10222028.021\\17CE",
            &lite
        ));
        assert!(!container_belongs_to(
            "\\\\.\\Aktiv Rutoken ECP 0\\key",
            &lite
        ));
    }

    #[test]
    fn registry_keeps_variants_of_every_token() {
        let details = |container: &str| TokenCertificateDetails {
            der: vec![0x30, 0x00],
            container: container.to_owned(),
            provider_name: "prov".to_owned(),
            provider_type: 80,
            key_spec: 1,
        };
        let mut map: HashMap<String, Vec<TokenCertificateDetails>> = HashMap::new();
        map.insert(
            "issuer:01".to_owned(),
            vec![
                details("\\\\.\\Aktiv Rutoken lite 0\\a"),
                details("\\\\.\\Aktiv Rutoken ECP 0\\b"),
            ],
        );
        replace_token_details(map);
        let found = details_for_certificate("issuer:01");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].container, "\\\\.\\Aktiv Rutoken lite 0\\a");
        assert!(details_for_certificate("issuer:02").is_empty());
        replace_token_details(HashMap::new());
    }
}
