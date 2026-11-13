#![allow(unsafe_code)]

//! Обнаружение Рутокенов и чтение сертификатов из их контейнеров через КриптоПро CSP.
//!
//! На Linux считыватели и контейнеры перечисляются одним способом — `PP_ENUMCONTAINERS`
//! с флагом `CRYPT_FQCN`: полное имя контейнера — `\\.\<считыватель>\<контейнер>`,
//! поэтому считыватель восстанавливается из префикса, а не из `PP_ENUMREADERS`.
//!
//! Контейнеры открываются с `CRYPT_SILENT`: PIN спрашивается только при подписи,
//! а не при перечислении. Сертификат читается ключевым параметром `KP_CERTIFICATE`.

use super::api;
use crate::tr;
use std::collections::HashMap;
use std::ptr;
use std::sync::{LazyLock, Mutex};

/// Порядок типов провайдера — как в `probe`: 2012-256, 2012-512, 2001.
const PROVIDER_TYPES: [u32; 3] = [80, 81, 75];

/// Обнаруженный физический токен.
#[derive(Debug, Clone)]
pub(super) struct DetectedToken {
    /// Имя считывателя — префикс полного имени контейнера.
    pub reader: String,
    /// Короткая модель без префикса производителя: `Lite`, `ECP`.
    pub model: String,
    /// Контейнеры токена и провайдеры, через которые они видны.
    pub containers: Vec<TokenContainer>,
}

/// Контейнер токена.
#[derive(Debug, Clone)]
pub(super) struct TokenContainer {
    /// Полное имя контейнера (`CRYPT_FQCN`).
    pub name: String,
    /// Имя провайдера для `CryptAcquireContextA`.
    pub provider_name: String,
    pub provider_type: u32,
}

/// Всё, что нужно, чтобы открыть закрытый ключ сертификата с токена.
#[derive(Debug, Clone)]
pub(super) struct TokenDetails {
    pub der: Vec<u8>,
    pub container: String,
    pub provider_name: String,
    pub provider_type: u32,
    pub key_spec: u32,
}

/// Реестр деталей контейнеров по идентификатору сертификата.
///
/// Ключ — стабильный `CertInfo.id` (издатель + серийный номер). Значение — все
/// найденные варианты: один сертификат может лежать на нескольких токенах.
static TOKEN_DETAILS: LazyLock<Mutex<HashMap<String, Vec<TokenDetails>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Полностью заменяет реестр: вызывается после каждого перечисления сертификатов.
pub(super) fn replace_token_details(map: HashMap<String, Vec<TokenDetails>>) {
    let mut details = TOKEN_DETAILS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    *details = map;
}

/// Детали контейнеров для сертификата из последнего перечисления.
pub(super) fn details_for_certificate(id: &str) -> Vec<TokenDetails> {
    let details = TOKEN_DETAILS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    details.get(id).cloned().unwrap_or_default()
}

/// Детали контейнера по идентификатору сертификата без предварительного перечисления.
///
/// Нужен, когда подпись запускается по сохранённому идентификатору раньше, чем
/// открывался список сертификатов.
pub(super) fn find_details_by_id(id: &str) -> Option<TokenDetails> {
    if let Some(details) = details_for_certificate(id).into_iter().next() {
        return Some(details);
    }
    let tokens = detect_tokens().ok()?;
    let collected = collect_token_certificates(&tokens);
    let mut map: HashMap<String, Vec<TokenDetails>> = HashMap::new();
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

/// Обнаруживает подключённые Рутокены по перечислению контейнеров КриптоПро CSP.
pub(super) fn detect_tokens() -> Result<Vec<DetectedToken>, crate::signer::SignerError> {
    let mut tokens: Vec<DetectedToken> = Vec::new();
    let mut last_error = 0u32;
    let mut opened = 0usize;
    for provider_type in PROVIDER_TYPES {
        let provider = match api::acquire_provider(provider_type) {
            Ok(provider) => provider,
            Err(code) => {
                last_error = code;
                continue;
            }
        };
        opened += 1;
        let provider_name = api::provider_param(provider.handle(), api::PP_NAME, 0)
            .ok()
            .and_then(|buffer| first_field(&buffer))
            .unwrap_or_default();
        let mut flags = api::CRYPT_FIRST | api::CRYPT_FQCN;
        loop {
            let buffer = match api::provider_param(provider.handle(), api::PP_ENUMCONTAINERS, flags)
            {
                Ok(buffer) => buffer,
                Err(code) => {
                    if code != api::ERROR_NO_MORE_ITEMS {
                        tracing::warn!(
                            provider_type,
                            code = format!("0x{code:08X}"),
                            "PP_ENUMCONTAINERS failed"
                        );
                    }
                    break;
                }
            };
            flags = api::CRYPT_NEXT | api::CRYPT_FQCN;
            let Some(name) = first_field(&buffer) else {
                continue;
            };
            let Some((reader, _)) = split_container_name(&name) else {
                continue;
            };
            if !reader.to_lowercase().contains("rutoken") {
                continue;
            }
            let container = TokenContainer {
                name: name.clone(),
                provider_name: provider_name.clone(),
                provider_type,
            };
            match tokens.iter_mut().find(|token| token.reader == reader) {
                Some(existing) => {
                    if !existing
                        .containers
                        .iter()
                        .any(|entry| entry.name == container.name)
                    {
                        existing.containers.push(container);
                    }
                }
                None => tokens.push(DetectedToken {
                    model: model_from_reader(&reader),
                    reader,
                    containers: vec![container],
                }),
            }
        }
    }
    if opened == 0 {
        return Err(crate::signer::SignerError::CspNotFound(tr!(
            "ни один провайдер КриптоПро CSP не открылся (код КриптоПро 0x{last_error:08X})",
            "no CryptoPro CSP provider could be opened (CryptoPro code 0x{last_error:08X})"
        )));
    }
    tokens.sort_by(|left, right| left.reader.cmp(&right.reader));
    Ok(tokens)
}

/// Первая строка буфера параметра провайдера (байты cp1251, как у ANSI-функций CSP).
pub(super) fn first_field(buffer: &[u8]) -> Option<String> {
    let end = buffer.iter().position(|byte| *byte == 0)?;
    Some(api::from_ansi(&buffer[..end]))
}

/// Считыватель и имя контейнера из полного имени `\\.\<считыватель>\<контейнер>`.
fn split_container_name(name: &str) -> Option<(String, String)> {
    let rest = name.strip_prefix(r"\\.\")?;
    let (reader, container) = rest.split_once('\\')?;
    if reader.is_empty() || container.is_empty() {
        return None;
    }
    Some((reader.to_owned(), container.to_owned()))
}

/// Короткая модель токена: `Aktiv Rutoken lite 00 00` → `Lite`, `Rutoken PKCS#11` → `PKCS#11`.
pub(super) fn model_from_reader(reader: &str) -> String {
    let mut value = reader.trim().to_owned();
    loop {
        let lower = value.to_lowercase();
        let prefix = if lower.starts_with("aktiv ") {
            "aktiv ".len()
        } else if lower.starts_with("rutoken ") {
            "rutoken ".len()
        } else {
            break;
        };
        value = value[prefix..].to_owned();
    }
    // Хвостовые группы цифр — служебный номер устройства, а не модель.
    loop {
        let trimmed = value.trim_end();
        match trimmed.rsplit_once(' ') {
            Some((head, tail)) if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) => {
                value = head.trim_end().to_owned();
            }
            _ => {
                value = trimmed.to_owned();
                break;
            }
        }
    }
    let mut characters = value.chars();
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
            "Linux · Личное хранилище (Рутокен)",
            "Linux · Personal store (Rutoken)"
        )
    } else {
        tr!(
            "Linux · Личное хранилище (Рутокен {model})",
            "Linux · Personal store (Rutoken {model})"
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
        .find(|token| container_belongs_to_token(container, token))
}

/// Контейнер относится к токену: полное имя начинается с `\\.\<считыватель>\`.
pub(super) fn container_belongs_to_token(container: &str, token: &DetectedToken) -> bool {
    container
        .to_lowercase()
        .starts_with(&format!(r"\\.\{}", token.reader.to_lowercase()))
}

/// Сертификаты всех контейнеров обнаруженных токенов.
///
/// Возвращает пару «сертификат для списка» и детали контейнера (если их удалось
/// получить) для последующей подписи. Дубликаты по `id` отбрасываются: первый
/// найденный контейнер выигрывает.
pub(super) fn collect_token_certificates(
    tokens: &[DetectedToken],
) -> Vec<(crate::signer::CertInfo, Option<TokenDetails>)> {
    let mut collected: Vec<(crate::signer::CertInfo, Option<TokenDetails>)> = Vec::new();
    for token in tokens {
        let source = token_source(&token.model);
        let mut found = 0usize;
        for container in &token.containers {
            let Some(details) = read_container_certificate(container) else {
                continue;
            };
            let context = match api::certificate_from_der(&details.der) {
                Ok(context) => context,
                Err(error) => {
                    tracing::warn!(container = %container.name, %error, "token certificate is unusable");
                    continue;
                }
            };
            let Some(mut info) = api::read_certificate(context.as_ptr(), &source) else {
                continue;
            };
            info.has_private_key = true;
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
/// Детали контейнера здесь не извлекаются: разбор wide-строк `CRYPT_KEY_PROV_INFO`
/// на Linux не подтверждён, а подпись находит контейнер обычным путём.
fn collect_from_user_certstore(
    token: &DetectedToken,
) -> Vec<(crate::signer::CertInfo, Option<TokenDetails>)> {
    let source = token_source(&token.model);
    let mut collected: Vec<(crate::signer::CertInfo, Option<TokenDetails>)> = Vec::new();
    for container in &token.containers {
        let Ok(provider) = api::open_container(
            &container.name,
            &container.provider_name,
            container.provider_type,
            api::CRYPT_SILENT,
        ) else {
            continue;
        };
        let Some(store) = api::user_certstore(provider.handle()) else {
            continue;
        };
        let store = api::Store::from_handle(store);
        let Ok(api) = api::api() else {
            continue;
        };
        let mut previous: api::CertContextPtr = ptr::null();
        loop {
            // CertEnumCertificatesInStore освобождает предыдущий контекст.
            let current = unsafe { (api.cert_enum_certificates_in_store)(store.handle(), previous) };
            if current.is_null() {
                break;
            }
            previous = current;
            let Some(info) = api::read_certificate(current, &source) else {
                continue;
            };
            if collected.iter().any(|(existing, _)| existing.id == info.id) {
                continue;
            }
            collected.push((info, None));
        }
        if !collected.is_empty() {
            return collected;
        }
    }
    collected
}

/// Читает сертификат открытого ключа контейнера.
///
/// Контейнер открывается с `CRYPT_SILENT`, поэтому PIN не запрашивается; если провайдер
/// по имени недоступен, повторяется попытка без имени провайдера.
fn read_container_certificate(container: &TokenContainer) -> Option<TokenDetails> {
    let mut attempts = vec![container.provider_name.clone()];
    if !container.provider_name.is_empty() {
        attempts.push(String::new());
    }
    for provider_name in attempts {
        let provider = match api::open_container(
            &container.name,
            &provider_name,
            container.provider_type,
            api::CRYPT_SILENT,
        ) {
            Ok(provider) => provider,
            Err(code) => {
                tracing::warn!(
                    container = %container.name,
                    provider_type = container.provider_type,
                    code = format!("0x{code:08X}"),
                    "token container is not available"
                );
                continue;
            }
        };
        let key_spec = match api::signing_key_spec(provider.handle()) {
            Ok(key_spec) => key_spec,
            Err(error) => {
                tracing::warn!(container = %container.name, %error, "token container has no key");
                continue;
            }
        };
        let Some(der) = key_certificate(provider.handle(), key_spec) else {
            tracing::warn!(container = %container.name, "container has no KP_CERTIFICATE");
            continue;
        };
        return Some(TokenDetails {
            der,
            container: container.name.clone(),
            provider_name,
            provider_type: container.provider_type,
            key_spec,
        });
    }
    None
}

/// `KP_CERTIFICATE` ключа контейнера: размер, затем DER.
fn key_certificate(provider: usize, key_spec: u32) -> Option<Vec<u8>> {
    let api = api::api().ok()?;
    let mut key = 0usize;
    if unsafe { (api.crypt_get_user_key)(provider, key_spec, &mut key) } == 0 {
        return None;
    }
    let mut length = 0u32;
    let sized = unsafe {
        (api.crypt_get_key_param)(key, api::KP_CERTIFICATE, ptr::null_mut(), &mut length, 0)
    };
    if sized == 0 || length == 0 {
        unsafe { (api.crypt_destroy_key)(key) };
        return None;
    }
    let mut der = vec![0u8; length as usize];
    let read = unsafe {
        (api.crypt_get_key_param)(
            key,
            api::KP_CERTIFICATE,
            der.as_mut_ptr(),
            &mut length,
            0,
        )
    };
    unsafe { (api.crypt_destroy_key)(key) };
    if read == 0 || length == 0 {
        return None;
    }
    der.truncate(length as usize);
    Some(der)
}

/// Хранилища сертификатов всех обнаруженных токенов — для расшифрования.
///
/// На каждый токен открывается первый доступный контейнер; ошибки отдельных
/// токенов пропускаются.
pub(super) fn open_all_token_stores() -> Vec<api::Store> {
    let mut stores = Vec::new();
    let tokens = match detect_tokens() {
        Ok(tokens) => tokens,
        Err(error) => {
            tracing::warn!(%error, "token detection failed");
            return stores;
        }
    };
    for token in &tokens {
        let mut opened = false;
        for container in &token.containers {
            for provider_name in [container.provider_name.as_str(), ""] {
                let Ok(provider) = api::open_container(
                    &container.name,
                    provider_name,
                    container.provider_type,
                    api::CRYPT_SILENT,
                ) else {
                    continue;
                };
                if let Some(store) = api::user_certstore(provider.handle()) {
                    stores.push(api::Store::from_handle(store));
                    opened = true;
                    break;
                }
            }
            if opened {
                break;
            }
        }
        if !opened {
            tracing::warn!(reader = %token.reader, "token has no certificate store");
        }
    }
    stores
}
