#![allow(unsafe_code)]

//! Криптография на Linux: CryptoAPI 2.0 КриптоПро CSP.
//!
//! Повторяет поведение Windows-ветки: те же `Cert*`/`CryptMsg*` вызовы, те же тексты,
//! тот же порядок разрешения сертификата и ключа. Отличия только там, где Linux-сборка
//! КриптоПро ведёт себя иначе: библиотеки грузятся через `dlopen`, CAdES-BES/T делает
//! штатный `cryptcp`, а `PP_LICENSE` может быть не поддержан.

mod api;
pub mod cryptcp;
mod token;

use crate::signer::{
    CertInfo, CspStatus, DecryptRequest, DecryptResult, EncryptRequest, EncryptResult, SignRequest,
    SignResult, SignerError, TokenInfo, VerifyRequest, VerifyResult, VerifySignerInfo,
};
use crate::tr;
use std::ffi::c_char;
use std::ptr;

// OID алгоритмов дайджеста, которые встречаются в сертификатах ГОСТ (NUL-терминированные).
const DIGEST_OID_GOST_2012_256: &[u8] = b"1.2.643.7.1.1.2.2\0";
const DIGEST_OID_GOST_2012_512: &[u8] = b"1.2.643.7.1.1.2.3\0";
const DIGEST_OID_GOST_2001: &[u8] = b"1.2.643.2.2.9\0";

/// Порядок типов провайдера: 2012-256, 2012-512, 2001.
const PROVIDER_TYPES: [u32; 3] = [80, 81, 75];

// ---------------------------------------------------------------------------
// Состояние CSP
// ---------------------------------------------------------------------------

/// Доступны ли форматы CAdES: нужны и `cryptcp`, и компонент CAdES (`libcades`).
pub fn cades_available() -> bool {
    cryptcp::binary_path().is_some() && cryptcp::cades_component_present()
}

pub fn probe() -> CspStatus {
    let mut last_error = 0u32;
    let mut csp_version = None;
    let mut selected = None;
    for provider_type in PROVIDER_TYPES {
        match api::acquire_provider(provider_type) {
            Ok(provider) => {
                csp_version = api::provider_version(&provider);
                selected = Some((provider_type, provider));
                break;
            }
            Err(code) => last_error = code,
        }
    }
    let Some((provider_type, context)) = selected else {
        return CspStatus::unavailable(tr!(
            "Не удалось открыть провайдеры КриптоПро CSP типов 80, 81 или 75 (код КриптоПро 0x{last_error:08X}). Убедитесь, что установлен КриптоПро CSP.",
            "Could not open CryptoPro CSP providers of type 80, 81, or 75 (CryptoPro code 0x{last_error:08X}). Make sure CryptoPro CSP is installed."
        ));
    };
    // Лицензия спрашивается у открытого провайдера: проверка не открывает ключи.
    let license = api::provider_license(&context);
    drop(context);
    let cades_available = cades_available();
    let license_note = match license {
        Some(true) => tr!("лицензия действительна", "the license is valid"),
        Some(false) => tr!(
            "действующая лицензия не найдена, подпись может быть недоступна",
            "no valid license was found, signing may be unavailable"
        ),
        None => tr!(
            "состояние лицензии этой сборкой CSP не сообщается",
            "the license state is not reported by this CSP build"
        ),
    };
    let features = if cades_available {
        tr!(
            "CMS/PKCS#7 и CAdES (cryptcp) доступны",
            "CMS/PKCS#7 and CAdES (cryptcp) are available"
        )
    } else if cryptcp::binary_path().is_none() {
        tr!(
            "cryptcp не найден; доступна CMS/PKCS#7, форматы CAdES недоступны",
            "cryptcp was not found; CMS/PKCS#7 is available, CAdES formats are not"
        )
    } else {
        tr!(
            "компонент CAdES не установлен (пакет cprocsp-pki-cades-64); доступна CMS/PKCS#7",
            "the CAdES component is not installed (cprocsp-pki-cades-64); CMS/PKCS#7 is available"
        )
    };
    CspStatus {
        available: true,
        cades_available,
        // Отсутствие лицензии в хранилище не блокирует подпись: лицензия может быть
        // встроена в носитель ключа, а окончательную проверку даёт сама операция подписи.
        signing_available: true,
        license_available: license.unwrap_or(false),
        license_supported: license.is_some(),
        provider_type: Some(provider_type),
        version: csp_version,
        message: tr!(
            "КриптоПро CSP обнаружен: {license_note}. {features}.",
            "CryptoPro CSP detected: {license_note}. {features}."
        ),
    }
}

// ---------------------------------------------------------------------------
// Список сертификатов и токенов
// ---------------------------------------------------------------------------

pub fn list_certificates() -> Result<Vec<CertInfo>, SignerError> {
    let tokens = match token::detect_tokens() {
        Ok(tokens) => tokens,
        Err(error) => {
            tracing::warn!(%error, "Rutoken detection failed");
            Vec::new()
        }
    };
    let mut certificates = api::list_personal_certificates(&tokens)?;
    let collected = token::collect_token_certificates(&tokens);
    let details = merge_token_certificates(&mut certificates, collected);
    token::replace_token_details(details);
    Ok(certificates)
}

/// Физические токены для счётчика в «О программе».
pub fn list_tokens() -> Vec<TokenInfo> {
    match token::detect_tokens() {
        Ok(tokens) => tokens
            .into_iter()
            .map(|token| TokenInfo {
                reader: token.reader,
                model: token.model,
            })
            .collect(),
        Err(error) => {
            tracing::warn!(%error, "Rutoken detection failed");
            Vec::new()
        }
    }
}

/// Добавляет сертификаты контейнеров токенов в список личного хранилища.
///
/// Совпадение по `id` не создаёт вторую строку: у существующего сертификата
/// обновляется источник и объединяется признак закрытого ключа.
fn merge_token_certificates(
    certificates: &mut Vec<CertInfo>,
    collected: Vec<(CertInfo, Option<token::TokenDetails>)>,
) -> std::collections::HashMap<String, Vec<token::TokenDetails>> {
    let mut details: std::collections::HashMap<String, Vec<token::TokenDetails>> =
        std::collections::HashMap::new();
    for (info, container) in collected {
        let id = info.id.clone();
        match certificates
            .iter_mut()
            .find(|certificate| certificate.id == info.id)
        {
            Some(existing) => {
                existing.source = info.source;
                existing.has_private_key |= info.has_private_key;
            }
            None => certificates.push(info),
        }
        if let Some(container) = container {
            details.entry(id).or_default().push(container);
        }
    }
    details
}

// ---------------------------------------------------------------------------
// Разрешение сертификата и ключа
// ---------------------------------------------------------------------------

/// Сертификат с открытым контейнером закрытого ключа.
struct Resolved {
    cert: api::CertContext,
    provider: Option<api::Provider>,
    key_spec: u32,
}

fn certificate_not_found() -> SignerError {
    SignerError::Signing(tr!(
        "выбранный сертификат больше не найден ни в личном хранилище, ни в контейнерах токена",
        "the selected certificate is no longer present in the personal store or in the token containers"
    ))
}

fn cached_token_details(id: &str) -> Option<token::TokenDetails> {
    let cached = token::details_for_certificate(id);
    if cached.is_empty() {
        token::find_details_by_id(id)
    } else {
        cached.into_iter().next()
    }
}

/// Контекст сертификата без открытия закрытого ключа.
fn resolve_certificate(certificate_id: &str) -> Result<api::CertContext, SignerError> {
    if let Some(details) = cached_token_details(certificate_id) {
        if let Ok(context) = api::certificate_from_der(&details.der) {
            return Ok(context);
        }
    }
    let store = api::open_personal_store().ok_or_else(|| {
        api::store_error(tr!(
            "не удалось открыть личное хранилище",
            "could not open the personal store"
        ))
    })?;
    api::find_certificate(&store, certificate_id).map_err(|_| certificate_not_found())
}

/// Сертификат и открытый контейнер ключа для подписи.
///
/// Сначала контейнеры обнаруженных токенов, затем личное хранилище: то же правило,
/// что в Windows-ветке.
fn resolve_for_signing(certificate_id: &str) -> Result<Resolved, SignerError> {
    if let Some(details) = cached_token_details(certificate_id) {
        if let Ok(resolved) = resolved_from_token(&details) {
            return Ok(resolved);
        }
    }
    let store = api::open_personal_store().ok_or_else(|| {
        api::store_error(tr!(
            "не удалось открыть личное хранилище",
            "could not open the personal store"
        ))
    })?;
    let cert = api::find_certificate(&store, certificate_id).map_err(|_| certificate_not_found())?;
    let (provider, key_spec) = acquire_private_key(&cert)?;
    Ok(Resolved {
        cert,
        provider: Some(provider),
        key_spec,
    })
}

/// Открывает контейнер закрытого ключа сертификата из личного хранилища.
///
/// Основной путь — `CryptAcquireCertificatePrivateKey`; если он не поддержан,
/// используется свойство `CERT_KEY_PROV_INFO_PROP_ID`, как это делает Windows-ветка.
fn acquire_private_key(cert: &api::CertContext) -> Result<(api::Provider, u32), SignerError> {
    let api = api::api()?;
    let mut provider = 0usize;
    let mut key_spec = 0u32;
    let mut caller_free: api::Bool = 0;
    let acquired = unsafe {
        (api.crypt_acquire_certificate_private_key)(
            cert.as_ptr(),
            0,
            ptr::null_mut(),
            &mut provider,
            &mut key_spec,
            &mut caller_free,
        )
    };
    if acquired == 0 {
        let info = api::certificate_key_prov_names(cert.as_ptr()).ok_or_else(|| {
            SignerError::Signing(tr!(
                "у сертификата подписанта нет сведений о закрытом ключе (код КриптоПро 0x{:08X})",
                "the signer certificate has no private key information (CryptoPro code 0x{:08X})",
                api::last_error(api)
            ))
        })?;
        let provider = api::open_container(&info.container, &info.provider, info.provider_type, 0)
            .map_err(|code| {
                SignerError::Signing(tr!(
                    "не удалось открыть контейнер закрытого ключа подписанта (код КриптоПро 0x{code:08X})",
                    "could not open the signer's private key container (CryptoPro code 0x{code:08X})"
                ))
            })?;
        let key_spec = match info.key_spec {
            0 => api::signing_key_spec(provider.handle())?,
            spec => spec,
        };
        return Ok((provider, key_spec));
    }
    let provider = if caller_free != 0 {
        api::Provider::owned(provider)
    } else {
        api::Provider::borrowed(provider)
    };
    // Спецификация проверяется по фактическим ключам контейнера: подпись требует
    // тот ключ, который в нём есть, а CSP может вернуть другой.
    let key_spec = match api::signing_key_spec(provider.handle()) {
        Ok(spec) => spec,
        Err(error) if key_spec != 0 => {
            tracing::debug!(%error, key_spec, "signing key probe failed, keeping the CSP key spec");
            key_spec
        }
        Err(error) => return Err(error),
    };
    Ok((provider, key_spec))
}

/// Открывает контейнер токена без `CRYPT_SILENT`: PIN запрашивает сам CSP при подписи.
fn resolved_from_token(details: &token::TokenDetails) -> Result<Resolved, SignerError> {
    let provider = api::open_container(
        &details.container,
        &details.provider_name,
        details.provider_type,
        0,
    )
    .or_else(|_| api::open_container(&details.container, "", details.provider_type, 0))
    .map_err(|code| {
        SignerError::Signing(tr!(
            "контейнер ключа на токене недоступен (код КриптоПро 0x{code:08X})",
            "the key container on the token is not available (CryptoPro code 0x{code:08X})"
        ))
    })?;
    let cert = api::certificate_from_der(&details.der)?;
    let key_spec = if details.key_spec != 0 {
        details.key_spec
    } else {
        api::signing_key_spec(provider.handle())?
    };
    Ok(Resolved {
        cert,
        provider: Some(provider),
        key_spec,
    })
}

/// OID хэш-алгоритма по открытому ключу сертификата.
fn hash_oid_for_certificate(context: api::CertContextPtr) -> Result<Vec<u8>, SignerError> {
    let public_key_oid =
        api::certificate_public_key_oid(context).ok_or_else(|| {
            SignerError::Signing(tr!(
                "в сертификате отсутствует OID открытого ключа",
                "the certificate has no public key OID"
            ))
        })?;
    let hash_oid: &[u8] = match public_key_oid.as_str() {
        "1.2.643.7.1.1.1.1" => DIGEST_OID_GOST_2012_256,
        "1.2.643.7.1.1.1.2" => DIGEST_OID_GOST_2012_512,
        "1.2.643.2.2.19" => DIGEST_OID_GOST_2001,
        _ => {
            return Err(SignerError::Signing(tr!(
                "алгоритм сертификата пока не поддерживается (OID {public_key_oid})",
                "the certificate algorithm is not supported yet (OID {public_key_oid})"
            )))
        }
    };
    Ok(hash_oid.to_vec())
}

// ---------------------------------------------------------------------------
// Подпись CMS
// ---------------------------------------------------------------------------

/// CMS SignedData с отдельным `SignerInfo` на каждый сертификат.
///
/// Тот же путь, что в Windows-ветке: `CryptMsgOpenToEncode` + `CryptMsgUpdate`,
/// поэтому одиночная и многоподписантская подписи совпадают по формату.
fn sign_message(
    certificates: &[Resolved],
    hash_oids: &[Vec<u8>],
    content: &[u8],
    detached: bool,
) -> Result<Vec<u8>, SignerError> {
    let api = api::api()?;
    let mut signer_infos = Vec::with_capacity(certificates.len());
    let mut cert_blobs = Vec::with_capacity(certificates.len());

    for (index, certificate) in certificates.iter().enumerate() {
        let context = certificate.cert.as_ptr();
        let context_ref = unsafe { context.as_ref() }.ok_or_else(|| {
            SignerError::Signing(tr!("повреждённый сертификат", "corrupt certificate"))
        })?;
        let cert_info = unsafe { context_ref.pCertInfo.as_ref() }.ok_or_else(|| {
            SignerError::Signing(tr!("повреждённый сертификат", "corrupt certificate"))
        })?;
        let provider = certificate.provider.as_ref().ok_or_else(|| {
            SignerError::Signing(tr!(
                "у сертификата подписанта нет открытого контейнера закрытого ключа",
                "the signer certificate has no open private key container"
            ))
        })?;
        cert_blobs.push(api::CRYPT_INTEGER_BLOB {
            cbData: context_ref.cbCertEncoded,
            pbData: context_ref.pbCertEncoded,
        });
        let hash_oid = &hash_oids[index];
        signer_infos.push(api::CMSG_SIGNER_ENCODE_INFO {
            cbSize: std::mem::size_of::<api::CMSG_SIGNER_ENCODE_INFO>() as u32,
            pCertInfo: cert_info as *const api::CERT_INFO as *mut api::CERT_INFO,
            Anonymous: api::CMSG_SIGNER_ENCODE_INFO_0 {
                hCryptProv: provider.handle(),
            },
            dwKeySpec: certificate.key_spec,
            HashAlgorithm: api::CRYPT_ALGORITHM_IDENTIFIER {
                pszObjId: hash_oid.as_ptr() as *mut c_char,
                ..Default::default()
            },
            pvHashAuxInfo: ptr::null_mut(),
            cAuthAttr: 0,
            rgAuthAttr: ptr::null_mut(),
            cUnauthAttr: 0,
            rgUnauthAttr: ptr::null_mut(),
        });
    }

    let signer_count = u32::try_from(signer_infos.len()).map_err(|_| {
        SignerError::Signing(tr!(
            "слишком много сертификатов подписантов",
            "too many signer certificates"
        ))
    })?;
    let cert_count = u32::try_from(cert_blobs.len()).map_err(|_| {
        SignerError::Signing(tr!(
            "слишком много сертификатов подписантов",
            "too many signer certificates"
        ))
    })?;
    let mut signed_encode_info = api::CMSG_SIGNED_ENCODE_INFO {
        cbSize: std::mem::size_of::<api::CMSG_SIGNED_ENCODE_INFO>() as u32,
        cSigners: signer_count,
        rgSigners: signer_infos.as_mut_ptr(),
        cCertEncoded: cert_count,
        rgCertEncoded: cert_blobs.as_mut_ptr(),
        cCrlEncoded: 0,
        rgCrlEncoded: ptr::null_mut(),
    };
    let mut flags = 0u32;
    if detached {
        flags |= api::CMSG_DETACHED_FLAG;
    }
    let message = unsafe {
        (api.crypt_msg_open_to_encode)(
            api::X509_ASN_ENCODING | api::PKCS_7_ASN_ENCODING,
            flags,
            api::CMSG_SIGNED,
            &mut signed_encode_info as *mut api::CMSG_SIGNED_ENCODE_INFO as *const std::ffi::c_void,
            ptr::null(),
            ptr::null_mut(),
        )
    };
    if message == 0 {
        return Err(SignerError::Signing(tr!(
            "не удалось открыть CMS-сообщение для подписания (код КриптоПро 0x{:08X})",
            "could not open the CMS message for signing (CryptoPro code 0x{:08X})",
            api::last_error(api)
        )));
    }
    let content_length = u32::try_from(content.len()).map_err(|_| {
        unsafe { (api.crypt_msg_close)(message) };
        SignerError::Signing(tr!(
            "исходный файл превышает лимит CryptoAPI",
            "the source file exceeds the CryptoAPI limit"
        ))
    })?;
    let updated = unsafe { (api.crypt_msg_update)(message, content.as_ptr(), content_length, 1) };
    if updated == 0 {
        unsafe { (api.crypt_msg_close)(message) };
        return Err(SignerError::Signing(tr!(
            "не удалось добавить данные в CMS-сообщение (код КриптоПро 0x{:08X})",
            "could not add data to the CMS message (CryptoPro code 0x{:08X})",
            api::last_error(api)
        )));
    }
    let mut encoded_length = 0u32;
    let sized = unsafe {
        (api.crypt_msg_get_param)(
            message,
            api::CMSG_CONTENT_PARAM,
            0,
            ptr::null_mut(),
            &mut encoded_length,
        )
    };
    if sized == 0 || encoded_length == 0 {
        unsafe { (api.crypt_msg_close)(message) };
        return Err(SignerError::Signing(tr!(
            "не удалось определить размер CMS-подписи (код КриптоПро 0x{:08X})",
            "could not determine the CMS signature size (CryptoPro code 0x{:08X})",
            api::last_error(api)
        )));
    }
    let mut encoded = vec![0u8; encoded_length as usize];
    let got = unsafe {
        (api.crypt_msg_get_param)(
            message,
            api::CMSG_CONTENT_PARAM,
            0,
            encoded.as_mut_ptr() as *mut std::ffi::c_void,
            &mut encoded_length,
        )
    };
    unsafe { (api.crypt_msg_close)(message) };
    if got == 0 {
        return Err(SignerError::Signing(tr!(
            "не удалось получить закодированную CMS-подпись (код КриптоПро 0x{:08X})",
            "could not obtain the encoded CMS signature (CryptoPro code 0x{:08X})",
            api::last_error(api)
        )));
    }
    encoded.truncate(encoded_length as usize);
    Ok(encoded)
}

/// Подпись файла: один CMS со всеми выбранными сертификатами.
pub fn sign_file(request: SignRequest) -> Result<SignResult, SignerError> {
    let input = std::fs::read(&request.input_path).map_err(|error| {
        SignerError::Signing(tr!(
            "не удалось прочитать исходный файл: {error}",
            "could not read the source file: {error}"
        ))
    })?;
    if request.certificate_ids.is_empty() {
        return Err(SignerError::Signing(tr!(
            "выберите хотя бы один сертификат для подписания",
            "select at least one certificate for signing"
        )));
    }
    let certificates = request
        .certificate_ids
        .iter()
        .map(|id| resolve_for_signing(id))
        .collect::<Result<Vec<_>, _>>()?;
    let hash_oids = certificates
        .iter()
        .map(|certificate| hash_oid_for_certificate(certificate.cert.as_ptr()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut output = sign_message(&certificates, &hash_oids, &input, request.detached)?;
    if request.base64 {
        output = encode_base64(&output).into_bytes();
    }
    let requested = std::path::PathBuf::from(&request.output_path);
    let final_path = crate::signer::output::write_unique(&requested, &output).map_err(|error| {
        SignerError::Signing(tr!(
            "не удалось записать файл результата ({}): {error}",
            "could not write the result file ({}): {error}",
            requested.display()
        ))
    })?;
    Ok(SignResult {
        output_path: final_path.display().to_string(),
        bytes_written: output.len(),
    })
}

/// Подпись подписываемого диапазона PDF: detached CMS одним сертификатом.
pub fn sign_pdf_range(certificate_id: &str, content: &[u8]) -> Result<Vec<u8>, SignerError> {
    let certificate = resolve_for_signing(certificate_id)?;
    let hash_oid = hash_oid_for_certificate(certificate.cert.as_ptr())?;
    sign_message(
        std::slice::from_ref(&certificate),
        std::slice::from_ref(&hash_oid),
        content,
        true,
    )
}

/// OID открытого ключа выбранного сертификата — им выбирается алгоритм хэша для PDF.
pub fn pdf_certificate_public_key_oid(certificate_id: &str) -> Result<Vec<u8>, SignerError> {
    let context = resolve_certificate(certificate_id)?;
    let oid = api::certificate_public_key_oid(context.as_ptr()).ok_or_else(|| {
        SignerError::Signing(tr!(
            "в сертификате отсутствует OID открытого ключа",
            "the certificate has no public key OID"
        ))
    })?;
    Ok(oid.into_bytes())
}

// ---------------------------------------------------------------------------
// Проверка подписи
// ---------------------------------------------------------------------------

/// Проверка подписи файла: чтение, Base64/PEM-декодирование и проверка подписантов.
pub fn verify_signature(request: VerifyRequest) -> Result<VerifyResult, SignerError> {
    let signature_path = request.signature_path.clone();
    let signature = std::fs::read(&request.signature_path).map_err(|error| {
        SignerError::Signing(tr!(
            "не удалось прочитать файл подписи: {error}",
            "could not read the signature file: {error}"
        ))
    })?;
    let signature = if request.base64 {
        decode_base64(&signature)?
    } else {
        signature
    };
    let content_path = request.content_path.clone();
    let content = match content_path.as_ref() {
        Some(path) => Some(std::fs::read(path).map_err(|error| {
            SignerError::Signing(tr!(
                "не удалось прочитать исходный документ: {error}",
                "could not read the source document: {error}"
            ))
        })?),
        None => None,
    };
    let (signers, failure) = verify_cms_signers(
        &signature,
        content.as_deref(),
        request.detached,
        request.check_crl,
    )?;
    if let Some((signer_index, code)) = failure {
        return Ok(VerifyResult {
            valid: false,
            signature_path,
            content_path,
            signers,
            message: tr!(
                "Подпись подписанта №{} не прошла криптографическую проверку (код КриптоПро 0x{code:08X}).",
                "The signature of signer #{} failed cryptographic verification (CryptoPro code 0x{code:08X}).",
                signer_index + 1
            ),
        });
    }
    let revoked = signers
        .iter()
        .any(|signer| signer.revocation_status == "revoked");
    let message = if revoked {
        tr!(
            "Криптографическая подпись верна, но в цепочке есть сертификат, отозванный по CRL.",
            "The cryptographic signature is valid, but a certificate in the chain is revoked according to the CRL."
        )
    } else if request.check_crl {
        tr!(
            "Криптографические подписи всех подписантов верны; проверка отзыва по CRL выполнена.",
            "The cryptographic signatures of all signers are valid; revocation was checked against the CRL."
        )
    } else {
        tr!(
            "Криптографические подписи всех подписантов верны.",
            "The cryptographic signatures of all signers are valid."
        )
    };
    Ok(VerifyResult {
        valid: !signers.is_empty() && !revoked,
        signature_path,
        content_path,
        signers,
        message,
    })
}

/// Проверка CMS по байтам: встроенные подписи PDF проверяются этой функцией.
///
/// Возвращает подписантов и номер подписанта, не прошедшего проверку, с кодом ошибки CSP.
pub fn verify_cms_signers(
    signature: &[u8],
    content: Option<&[u8]>,
    detached: bool,
    check_crl: bool,
) -> Result<(Vec<VerifySignerInfo>, Option<(u32, u32)>), SignerError> {
    if detached && content.is_none() {
        return Err(SignerError::Signing(tr!(
            "для отсоединённой подписи выберите исходный документ",
            "select the source document for a detached signature"
        )));
    }
    let api = api::api()?;
    let signature_len = u32::try_from(signature.len()).map_err(|_| {
        SignerError::Signing(tr!(
            "файл подписи слишком велик для CryptoAPI",
            "the signature file is too large for CryptoAPI"
        ))
    })?;
    let mut parameters = api::CRYPT_VERIFY_MESSAGE_PARA::default();
    parameters.cbSize = std::mem::size_of::<api::CRYPT_VERIFY_MESSAGE_PARA>() as u32;
    parameters.dwMsgAndCertEncodingType = api::X509_ASN_ENCODING | api::PKCS_7_ASN_ENCODING;
    let content_bytes = content
        .map(|bytes| {
            u32::try_from(bytes.len()).map_err(|_| {
                SignerError::Signing(tr!(
                    "исходный документ слишком велик для CryptoAPI",
                    "the source document is too large for CryptoAPI"
                ))
            })
        })
        .transpose()?;
    let count = unsafe {
        (api.crypt_get_message_signer_count)(
            api::X509_ASN_ENCODING | api::PKCS_7_ASN_ENCODING,
            signature.as_ptr(),
            signature_len,
        )
    };
    let limit = if count > 0 { count as u32 } else { 128 };
    let mut signers = Vec::new();
    let mut signer_index = 0u32;
    loop {
        if signer_index >= limit {
            if count > 0 {
                break;
            }
            // Счётчик подписантов неизвестен: больше 127 подписантов не поддерживается.
            return Err(SignerError::Signing(tr!(
                "В CMS найдено больше 127 подписантов; проверка остановлена.",
                "More than 127 signers were found in the CMS; verification stopped."
            )));
        }
        let mut signer: *mut api::CERT_CONTEXT = ptr::null_mut();
        let valid = if detached {
            let bytes = content.expect("checked above");
            let content_ptr = bytes.as_ptr();
            unsafe {
                (api.crypt_verify_detached_message_signature)(
                    &parameters,
                    signer_index,
                    signature.as_ptr(),
                    signature_len,
                    1,
                    &content_ptr,
                    content_bytes.as_ref().expect("content length checked"),
                    &mut signer,
                ) != 0
            }
        } else {
            verify_attached_signer(
                api,
                &parameters,
                signer_index,
                signature,
                signature_len,
                &mut signer,
            )
        };
        if !valid {
            let code = api::last_error(api);
            if count <= 0 && !signers.is_empty() {
                break;
            }
            return Ok((signers, Some((signer_index, code))));
        }
        let signer_context = api::CertContext::new(signer);
        if let Some(cert) =
            unsafe { signer_context.as_ptr().as_ref() }.and_then(|context| unsafe {
                context.pCertInfo.as_ref()
            })
        {
            let chain = certificate_chain_status(api, signer_context.as_ptr(), check_crl);
            signers.push(VerifySignerInfo {
                subject: api::certificate_name(signer_context.as_ptr(), false),
                issuer: api::certificate_name(signer_context.as_ptr(), true),
                expires_at: api::filetime_to_date(
                    cert.NotAfter.dwHighDateTime,
                    cert.NotAfter.dwLowDateTime,
                ),
                chain_trusted: chain.trusted,
                chain_message: chain.message,
                revocation_status: chain.revocation_status.to_owned(),
                revocation_message: chain.revocation_message,
            });
        }
        signer_index += 1;
    }
    Ok((signers, None))
}

/// Проверка одного подписанта присоединённой подписи.
///
/// Первый вызов может вернуть `ERROR_MORE_DATA`: тогда буфер создаётся по запрошенному
/// размеру, а контекст сертификата перезапрашивается.
fn verify_attached_signer(
    api: &api::Api,
    parameters: &api::CRYPT_VERIFY_MESSAGE_PARA,
    signer_index: u32,
    signature: &[u8],
    signature_len: u32,
    signer: &mut *mut api::CERT_CONTEXT,
) -> bool {
    let mut decoded_len = 0u32;
    let first = unsafe {
        (api.crypt_verify_message_signature)(
            parameters,
            signer_index,
            signature.as_ptr(),
            signature_len,
            ptr::null_mut(),
            &mut decoded_len,
            signer,
        )
    };
    if first != 0 {
        return true;
    }
    if api::last_error(api) != api::ERROR_MORE_DATA {
        return false;
    }
    if !(*signer).is_null() {
        unsafe { (api.cert_free_certificate_context)(*signer) };
        *signer = ptr::null_mut();
    }
    let mut decoded = vec![0u8; decoded_len as usize];
    unsafe {
        (api.crypt_verify_message_signature)(
            parameters,
            signer_index,
            signature.as_ptr(),
            signature_len,
            decoded.as_mut_ptr(),
            &mut decoded_len,
            signer,
        ) != 0
    }
}

/// Итог проверки цепочки: доверие CSP и отдельный статус отзыва по CRL.
struct ChainStatus {
    trusted: bool,
    message: String,
    revocation_status: &'static str,
    revocation_message: String,
}

fn certificate_chain_status(
    api: &api::Api,
    certificate: api::CertContextPtr,
    check_revocation: bool,
) -> ChainStatus {
    let mut chain_parameters = api::CERT_CHAIN_PARA::default();
    chain_parameters.cbSize = std::mem::size_of::<api::CERT_CHAIN_PARA>() as u32;
    chain_parameters.dwUrlRetrievalTimeout = if check_revocation { 20_000 } else { 0 };
    // Без флагов отзыва цепочка строится только по локальному кэшу; с ними CSP
    // скачивает CRL по адресам из сертификата, поэтому вызову нужна сеть.
    let flags = if check_revocation {
        api::CERT_CHAIN_REVOCATION_CHECK_CHAIN | api::CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT
    } else {
        api::CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL
    };
    let mut chain: *mut api::CERT_CHAIN_CONTEXT = ptr::null_mut();
    let built = unsafe {
        (api.cert_get_certificate_chain)(
            0,
            certificate,
            ptr::null(),
            ptr::null_mut(),
            &chain_parameters,
            flags,
            ptr::null_mut(),
            &mut chain,
        )
    };
    if built == 0 || chain.is_null() {
        let code = api::last_error(api);
        return ChainStatus {
            trusted: false,
            message: tr!(
                "КриптоПро CSP не смог построить цепочку сертификата (0x{code:08X}).",
                "CryptoPro CSP could not build the certificate chain (0x{code:08X})."
            ),
            revocation_status: if check_revocation { "unknown" } else { "notChecked" },
            revocation_message: if check_revocation {
                tr!(
                    "Не удалось проверить CRL: цепочка не построена (код КриптоПро 0x{code:08X}).",
                    "Could not check the CRL: the chain was not built (CryptoPro code 0x{code:08X})."
                )
            } else {
                tr!(
                    "Проверка отзыва по CRL не выполнялась.",
                    "Revocation was not checked against a CRL."
                )
            },
        };
    }
    let mut policy_parameters = api::CERT_CHAIN_POLICY_PARA::default();
    policy_parameters.cbSize = std::mem::size_of::<api::CERT_CHAIN_POLICY_PARA>() as u32;
    let mut policy_status = api::CERT_CHAIN_POLICY_STATUS::default();
    policy_status.cbSize = std::mem::size_of::<api::CERT_CHAIN_POLICY_STATUS>() as u32;
    let checked = unsafe {
        (api.cert_verify_certificate_chain_policy)(
            api::CERT_CHAIN_POLICY_BASE,
            chain,
            &policy_parameters,
            &mut policy_status,
        )
    };
    // Статус отзыва читается только из живой цепочки; ниже она освобождается.
    let revocation = if check_revocation {
        Some(revocation_status(chain))
    } else {
        None
    };
    // Политика BASE может быть не реализована этой сборкой CSP: тогда доверие считается
    // по статусу самой цепочки, а не подтверждается пустым результатом политики.
    let policy_code = if checked == 0 {
        api::last_error(api)
    } else {
        policy_status.dwError
    };
    let policy_unsupported = checked == 0
        && matches!(policy_code, 50 | 0x8007_0032)
        && unsafe { &*chain }.TrustStatus.dwErrorStatus == 0;
    let trusted = if policy_unsupported {
        true
    } else {
        checked != 0 && policy_status.dwError == 0
    };
    let message = match (check_revocation, trusted) {
        (false, true) if policy_unsupported => tr!(
            "Цепочка доверия построена КриптоПро CSP (политика BASE не поддерживается, код 0x{policy_code:08X}); проверка отзыва не выполнялась.",
            "The trust chain was built by CryptoPro CSP (the BASE policy is not supported, code 0x{policy_code:08X}); revocation was not checked."
        ),
        (false, true) => tr!(
            "Цепочка доверия подтверждена КриптоПро CSP; проверка отзыва не выполнялась.",
            "The trust chain was confirmed by CryptoPro CSP; revocation was not checked."
        ),
        (false, false) => tr!(
            "КриптоПро CSP не подтвердил цепочку доверия (код 0x{policy_code:08X}); проверка отзыва не выполнялась.",
            "CryptoPro CSP did not confirm the trust chain (code 0x{policy_code:08X}); revocation was not checked."
        ),
        (true, true) => tr!(
            "Цепочка доверия подтверждена КриптоПро CSP; статус отзыва проверен по CRL.",
            "The trust chain was confirmed by CryptoPro CSP; revocation status was checked against the CRL."
        ),
        (true, false) => tr!(
            "КриптоПро CSP не подтвердил цепочку доверия (код 0x{policy_code:08X}); статус отзыва проверен по CRL.",
            "CryptoPro CSP did not confirm the trust chain (code 0x{policy_code:08X}); revocation status was checked against the CRL."
        ),
    };
    unsafe { (api.cert_free_certificate_chain)(chain) };
    let (revocation_status, revocation_message) = match revocation {
        Some((status, message)) => (status, message),
        None => (
            "notChecked",
            tr!(
                "Проверка отзыва по CRL не выполнялась.",
                "Revocation was not checked against a CRL."
            ),
        ),
    };
    ChainStatus {
        trusted,
        message,
        revocation_status,
        revocation_message,
    }
}

/// Статус отзыва по CRL: отзыв любого элемента цепочки делает подпись недействительной.
fn revocation_status(chain: *const api::CERT_CHAIN_CONTEXT) -> (&'static str, String) {
    let context = unsafe { &*chain };
    let unknown_without_chain = || {
        (
            "unknown",
            tr!(
                "КриптоПро CSP не вернул цепочку для проверки CRL; статус отзыва неизвестен.",
                "CryptoPro CSP did not return a chain for the CRL check; the revocation status is unknown."
            ),
        )
    };
    if context.cChain == 0 || context.rgpChain.is_null() {
        return unknown_without_chain();
    }
    let simple = unsafe { *context.rgpChain };
    if simple.is_null() {
        return unknown_without_chain();
    }
    let simple: &api::CERT_SIMPLE_CHAIN = unsafe { &*simple };
    if simple.cElement == 0 || simple.rgpElement.is_null() {
        return (
            "unknown",
            tr!(
                "КриптоПро CSP не вернул элементы цепочки для проверки CRL; статус отзыва неизвестен.",
                "CryptoPro CSP did not return chain elements for the CRL check; the revocation status is unknown."
            ),
        );
    }
    let mut revoked = false;
    let mut leaf_revoked = false;
    let mut has_leaf_info = false;
    let mut leaf_result = None;
    let mut leaf_unknown = false;
    let mut leaf_revocation_date = None;
    for index in 0..simple.cElement as usize {
        let element = unsafe { *simple.rgpElement.add(index) };
        if element.is_null() {
            continue;
        }
        let element: &api::CERT_CHAIN_ELEMENT = unsafe { &*element };
        let element_revoked = element.TrustStatus.dwErrorStatus & api::CERT_TRUST_IS_REVOKED != 0;
        revoked |= element_revoked;
        if index != 0 {
            continue;
        }
        leaf_revoked = element_revoked;
        let info = unsafe { element.pRevocationInfo.as_ref() };
        has_leaf_info = info.is_some();
        if let Some(info) = info {
            let info: &api::CERT_REVOCATION_INFO = info;
            leaf_result = Some(info.dwRevocationResult);
            leaf_unknown = element.TrustStatus.dwErrorStatus
                & (api::CERT_TRUST_REVOCATION_STATUS_UNKNOWN | api::CERT_TRUST_IS_OFFLINE_REVOCATION)
                != 0;
            if let Some(entry) = unsafe { info.pCrlInfo.as_ref() }
                .and_then(|crl| unsafe { crl.pCrlEntry.as_ref() })
            {
                leaf_revocation_date = Some(api::filetime_to_date(
                    entry.RevocationDate.dwHighDateTime,
                    entry.RevocationDate.dwLowDateTime,
                ));
            }
        }
    }
    let code = leaf_result.unwrap_or(0);
    if revoked {
        if leaf_revoked {
            return match leaf_revocation_date {
                Some(date) => (
                    "revoked",
                    tr!(
                        "Сертификат подписанта отозван по CRL (дата отзыва {date}).",
                        "The signer certificate is revoked by the CRL (revocation date {date})."
                    ),
                ),
                None => (
                    "revoked",
                    tr!(
                        "Сертификат подписанта отозван по CRL.",
                        "The signer certificate is revoked by the CRL."
                    ),
                ),
            };
        }
        return (
            "revoked",
            tr!(
                "В цепочке сертификатов есть отозванный по CRL сертификат.",
                "A certificate in the chain is revoked by the CRL."
            ),
        );
    }
    if !has_leaf_info {
        return (
            "unknown",
            tr!(
                "КриптоПро CSP не выполнил проверку CRL для сертификата; статус отзыва неизвестен.",
                "CryptoPro CSP did not perform a CRL check for the certificate; the revocation status is unknown."
            ),
        );
    }
    if leaf_unknown || leaf_result != Some(0) {
        if leaf_result == Some(api::CRYPT_E_REVOCATION_OFFLINE) {
            return (
                "unknown",
                tr!(
                    "CRL недоступна или устарела; статус отзыва неизвестен (код КриптоПро 0x{code:08X}).",
                    "The CRL is unavailable or stale; the revocation status is unknown (CryptoPro code 0x{code:08X})."
                ),
            );
        }
        if leaf_result == Some(api::CRYPT_E_NO_REVOCATION_CHECK) {
            return (
                "unknown",
                tr!(
                    "У сертификата нет доступной точки распространения CRL; статус отзыва неизвестен (код КриптоПро 0x{code:08X}).",
                    "The certificate has no reachable CRL distribution point; the revocation status is unknown (CryptoPro code 0x{code:08X})."
                ),
            );
        }
        if leaf_result != Some(0) {
            return (
                "unknown",
                tr!(
                    "Не удалось проверить CRL; статус отзыва неизвестен (код КриптоПро 0x{code:08X}).",
                    "Could not check the CRL; the revocation status is unknown (CryptoPro code 0x{code:08X})."
                ),
            );
        }
        return (
            "unknown",
            tr!(
                "КриптоПро CSP не подтвердил проверку CRL; статус отзыва неизвестен.",
                "CryptoPro CSP did not confirm the CRL check; the revocation status is unknown."
            ),
        );
    }
    (
        "good",
        tr!(
            "По CRL сертификат не отозван.",
            "The certificate is not revoked according to the CRL."
        ),
    )
}

// ---------------------------------------------------------------------------
// Шифрование и расшифрование CMS
// ---------------------------------------------------------------------------

pub fn encrypt_file(request: EncryptRequest) -> Result<EncryptResult, SignerError> {
    let input = std::fs::read(&request.input_path).map_err(|error| {
        SignerError::Encryption(tr!(
            "не удалось прочитать исходный файл: {error}",
            "could not read the source file: {error}"
        ))
    })?;
    if request.certificate_ids.is_empty() {
        return Err(SignerError::Encryption(tr!(
            "выберите хотя бы один сертификат получателя",
            "select at least one recipient certificate"
        )));
    }
    let recipients = request
        .certificate_ids
        .iter()
        .map(|id| resolve_certificate(id))
        .collect::<Result<Vec<_>, _>>()?;
    let content_encryption_oid = content_encryption_oid_for_certificates(&recipients)?;
    let mut output = encrypt_message(&recipients, &content_encryption_oid, &input)?;
    if request.base64 {
        output = encode_base64(&output).into_bytes();
    }
    let final_path = write_result(&request.output_path, &output, ResultFileKind::Encryption)?;
    Ok(EncryptResult {
        output_path: final_path,
        bytes_written: output.len(),
    })
}

pub fn decrypt_file(request: DecryptRequest) -> Result<DecryptResult, SignerError> {
    let input = std::fs::read(&request.input_path).map_err(|error| {
        SignerError::Decryption(tr!(
            "не удалось прочитать зашифрованный файл: {error}",
            "could not read the encrypted file: {error}"
        ))
    })?;
    let input = if request.base64 {
        decode_base64(&input)?
    } else {
        input
    };
    let store = api::open_personal_store().ok_or_else(|| {
        api::store_error(tr!(
            "не удалось открыть личное хранилище",
            "could not open the personal store"
        ))
    })?;
    // Получатель мог быть выбран сертификатом токена: без хранилищ токенов
    // расшифрование своим ключом было бы недоступно.
    let mut stores = vec![store];
    stores.extend(token::open_all_token_stores());
    let output = decrypt_message(&stores, &input)?;
    let final_path = write_result(&request.output_path, &output, ResultFileKind::Decryption)?;
    Ok(DecryptResult {
        output_path: final_path,
        bytes_written: output.len(),
    })
}

fn content_encryption_oid_for_certificates(
    recipients: &[api::CertContext],
) -> Result<Vec<u8>, SignerError> {
    // Алгоритм шифрования содержимого выбирается по ключам получателей: ГОСТ 2012 —
    // «Кузнечик», ГОСТ 2001 — «Магма».
    let mut saw_gost_2012 = false;
    for recipient in recipients {
        let oid = api::certificate_public_key_oid(recipient.as_ptr()).ok_or_else(|| {
            SignerError::Encryption(tr!(
                "не удалось определить алгоритм ключа получателя",
                "could not determine the recipient key algorithm"
            ))
        })?;
        if oid.starts_with("1.2.643.7.1.1.1") {
            saw_gost_2012 = true;
        }
    }
    let oid: &[u8] = if saw_gost_2012 {
        b"1.2.643.7.1.1.5.1\0"
    } else {
        b"1.2.643.2.2.21\0"
    };
    Ok(oid.to_vec())
}

fn encrypt_message(
    recipients: &[api::CertContext],
    content_encryption_oid: &[u8],
    content: &[u8],
) -> Result<Vec<u8>, SignerError> {
    let api = api::api()?;
    let recipient_pointers = recipients
        .iter()
        .map(api::CertContext::as_ptr)
        .collect::<Vec<_>>();
    let mut parameters = api::CRYPT_ENCRYPT_MESSAGE_PARA::default();
    parameters.cbSize = std::mem::size_of::<api::CRYPT_ENCRYPT_MESSAGE_PARA>() as u32;
    parameters.dwMsgEncodingType = api::X509_ASN_ENCODING | api::PKCS_7_ASN_ENCODING;
    parameters.ContentEncryptionAlgorithm = api::CRYPT_ALGORITHM_IDENTIFIER {
        pszObjId: content_encryption_oid.as_ptr() as *mut c_char,
        ..Default::default()
    };
    let content_length = u32::try_from(content.len()).map_err(|_| {
        SignerError::Encryption(tr!(
            "исходный файл превышает лимит CryptoAPI",
            "the source file exceeds the CryptoAPI limit"
        ))
    })?;
    let recipient_count = u32::try_from(recipient_pointers.len()).map_err(|_| {
        SignerError::Encryption(tr!("слишком много получателей", "too many recipients"))
    })?;
    let mut encrypted_length = 0u32;
    let measured = unsafe {
        (api.crypt_encrypt_message)(
            &parameters,
            recipient_count,
            recipient_pointers.as_ptr(),
            content.as_ptr(),
            content_length,
            ptr::null_mut(),
            &mut encrypted_length,
        )
    };
    if measured == 0 {
        let code = api::last_error(api);
        return Err(SignerError::Encryption(tr!(
            "не удалось подготовить CMS EnvelopedData (код КриптоПро 0x{code:08X})",
            "could not prepare CMS EnvelopedData (CryptoPro code 0x{code:08X})"
        )));
    }
    let mut encrypted = vec![0u8; encrypted_length as usize];
    let created = unsafe {
        (api.crypt_encrypt_message)(
            &parameters,
            recipient_count,
            recipient_pointers.as_ptr(),
            content.as_ptr(),
            content_length,
            encrypted.as_mut_ptr(),
            &mut encrypted_length,
        )
    };
    if created == 0 {
        let code = api::last_error(api);
        return Err(SignerError::Encryption(tr!(
            "CryptoAPI не смог создать CMS EnvelopedData (код КриптоПро 0x{code:08X})",
            "CryptoAPI could not create CMS EnvelopedData (CryptoPro code 0x{code:08X})"
        )));
    }
    encrypted.truncate(encrypted_length as usize);
    Ok(encrypted)
}

fn decrypt_message(
    stores: &[api::Store],
    encrypted: &[u8],
) -> Result<Vec<u8>, SignerError> {
    let api = api::api()?;
    let mut parameters = api::CRYPT_DECRYPT_MESSAGE_PARA::default();
    parameters.cbSize = std::mem::size_of::<api::CRYPT_DECRYPT_MESSAGE_PARA>() as u32;
    parameters.dwMsgAndCertEncodingType = api::X509_ASN_ENCODING | api::PKCS_7_ASN_ENCODING;
    let mut handles = stores.iter().map(api::Store::handle).collect::<Vec<_>>();
    parameters.cCertStore = u32::try_from(handles.len()).unwrap_or(u32::MAX);
    parameters.rghCertStore = handles.as_mut_ptr();
    let encrypted_length = u32::try_from(encrypted.len()).map_err(|_| {
        SignerError::Decryption(tr!(
            "зашифрованный файл слишком велик для CryptoAPI",
            "the encrypted file is too large for CryptoAPI"
        ))
    })?;
    let mut decrypted_length = 0u32;
    let measured = unsafe {
        (api.crypt_decrypt_message)(
            &parameters,
            encrypted.as_ptr(),
            encrypted_length,
            ptr::null_mut(),
            &mut decrypted_length,
            ptr::null_mut(),
        )
    };
    if measured == 0 {
        let code = api::last_error(api);
        return Err(SignerError::Decryption(tr!(
            "не удалось определить размер расшифрованных данных (код КриптоПро 0x{code:08X})",
            "could not determine the decrypted data size (CryptoPro code 0x{code:08X})"
        )));
    }
    let mut decrypted = vec![0u8; decrypted_length as usize];
    let mut decrypted_cert: *mut api::CERT_CONTEXT = ptr::null_mut();
    let decoded = unsafe {
        (api.crypt_decrypt_message)(
            &parameters,
            encrypted.as_ptr(),
            encrypted_length,
            decrypted.as_mut_ptr(),
            &mut decrypted_length,
            &mut decrypted_cert,
        )
    };
    if decoded == 0 {
        let code = api::last_error(api);
        return Err(SignerError::Decryption(tr!(
            "не удалось расшифровать файл (код КриптоПро 0x{code:08X})",
            "could not decrypt the file (CryptoPro code 0x{code:08X})"
        )));
    }
    if !decrypted_cert.is_null() {
        unsafe { (api.cert_free_certificate_context)(decrypted_cert) };
    }
    decrypted.truncate(decrypted_length as usize);
    Ok(decrypted)
}

#[derive(Clone, Copy)]
enum ResultFileKind {
    Encryption,
    Decryption,
}

fn write_result(
    output_path: &str,
    output: &[u8],
    kind: ResultFileKind,
) -> Result<String, SignerError> {
    let make_error = |message: String| match kind {
        ResultFileKind::Decryption => SignerError::Decryption(message),
        ResultFileKind::Encryption => SignerError::Encryption(message),
    };
    let requested = std::path::PathBuf::from(output_path);
    crate::signer::output::write_unique(&requested, output)
        .map(|path| path.display().to_string())
        .map_err(|error| {
            let message = match kind {
                ResultFileKind::Encryption => tr!(
                    "не удалось записать файл результата шифрования ({}): {error}",
                    "could not write the encryption result file ({}): {error}",
                    requested.display()
                ),
                ResultFileKind::Decryption => tr!(
                    "не удалось записать файл результата расшифрования ({}): {error}",
                    "could not write the decryption result file ({}): {error}",
                    requested.display()
                ),
            };
            make_error(message)
        })
}

// ---------------------------------------------------------------------------
// Base64
// ---------------------------------------------------------------------------

fn encode_base64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn decode_base64(bytes: &[u8]) -> Result<Vec<u8>, SignerError> {
    use base64::Engine as _;
    let compact = bytes
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    let compact = if compact.starts_with(b"-----BEGIN") {
        String::from_utf8_lossy(&compact)
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .flat_map(str::bytes)
            .collect::<Vec<_>>()
    } else {
        compact
    };
    base64::engine::general_purpose::STANDARD
        .decode(compact)
        .map_err(|_| {
            SignerError::Signing(tr!(
                "файл не является корректной Base64/PEM подписью",
                "the file is not a valid Base64/PEM signature"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::{DecryptRequest, EncryptRequest, SignRequest, Signer, VerifyRequest};
    use std::path::{Path, PathBuf};

    fn token(reader: &str) -> token::DetectedToken {
        token::DetectedToken {
            reader: reader.to_owned(),
            model: token::model_from_reader(reader),
            containers: Vec::new(),
        }
    }

    #[test]
    fn token_model_is_shortened_to_the_device_name() {
        assert_eq!(token::model_from_reader("Aktiv Rutoken lite 00 00"), "Lite");
        assert_eq!(token::model_from_reader("Aktiv Rutoken ECP 00 00"), "ECP");
        assert_eq!(token::model_from_reader("Rutoken PKCS#11"), "PKCS#11");
    }

    #[test]
    fn container_matches_only_its_own_token() {
        let lite = token("Aktiv Rutoken lite 00 00");
        assert!(token::container_belongs_to_token(
            r"\\.\Aktiv Rutoken lite 00 00\1022202864452 831094549",
            &lite
        ));
        assert!(!token::container_belongs_to_token(
            r"\\.\Aktiv Rutoken ECP 00 00\key",
            &lite
        ));
        assert!(!token::container_belongs_to_token(r"\\.\HDIMAGE\key", &lite));
    }

    #[test]
    fn cryptcp_arguments_follow_the_requested_standard() {
        let input = Path::new("/tmp/in.txt");
        let output = Path::new("/tmp/out.der");
        let container = cryptcp::container_selector(r"\\.\Aktiv Rutoken lite 00 00\key");
        let attached = cryptcp::build_args("cades-bes", None, false, &container, input, output);
        let expected: Vec<std::ffi::OsString> = [
            "-sign",
            "-der",
            "-cadesbes",
            "-cont",
            r"\\.\Aktiv Rutoken lite 00 00\key",
            "/tmp/in.txt",
            "/tmp/out.der",
        ]
        .map(std::ffi::OsString::from)
        .to_vec();
        assert_eq!(attached, expected);

        let thumbprint = cryptcp::thumbprint_selector(b"cryptolite");
        let timestamped = cryptcp::build_args(
            "cades-t",
            Some("http://tsp.example/tsp.srf"),
            true,
            &thumbprint,
            input,
            output,
        );
        assert_eq!(
            timestamped[..5].to_vec(),
            ["-sign", "-der", "-cadest", "-cadestsa", "http://tsp.example/tsp.srf"]
                .map(std::ffi::OsString::from)
                .to_vec()
        );
        assert_eq!(timestamped[5], std::ffi::OsString::from("-detached"));
        assert_eq!(timestamped[6], std::ffi::OsString::from("-thumbprint"));
        let hash = timestamped[7].to_string_lossy().into_owned();
        assert_eq!(hash.len(), 40, "SHA-1 hex must be 40 characters");
        assert!(hash
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase()));
        assert_eq!(timestamped[8], std::ffi::OsString::from("/tmp/in.txt"));
        assert_eq!(timestamped[9], std::ffi::OsString::from("/tmp/out.der"));
    }

    #[test]
    fn ber_signature_is_normalised_to_der() {
        // `cryptcp -cadesbes` возвращает `30 80 02 01 01 00 00`: неопределённая длина.
        assert_eq!(
            cryptcp::ber_to_der(&[0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00]).expect("convert"),
            vec![0x30, 0x03, 0x02, 0x01, 0x01]
        );
        // Вложенная неопределённая длина тоже становится определённой.
        assert_eq!(
            cryptcp::ber_to_der(&[0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x07, 0x00, 0x00, 0x00, 0x00])
                .expect("convert"),
            vec![0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x07]
        );
        // Готовая DER-запись не меняется, а не минимальная длина переписывается минимально.
        let der = vec![0x30, 0x03, 0x02, 0x01, 0x01];
        assert_eq!(cryptcp::ber_to_der(&der).expect("convert"), der);
        let mut nested = vec![0x30, 0x80, 0x04, 0x82, 0x00, 0x83];
        nested.extend(std::iter::repeat(0xaa).take(0x83));
        nested.extend_from_slice(&[0x00, 0x00]);
        let normalised = cryptcp::ber_to_der(&nested).expect("convert");
        assert_eq!(&normalised[..6], &[0x30, 0x81, 0x86, 0x04, 0x81, 0x83]);
    }

    fn required_env(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| panic!("set {name} to run this test"))
    }

    fn unique_id() -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("{nanos:x}")
    }

    /// Сквозная проверка живого CSP: подпись, проверка, шифрование и CAdES на стенде.
    #[test]
    #[ignore = "requires CryptoPro CSP and an explicitly selected test certificate"]
    fn real_cms_signing_and_verification() {
        let serial = required_env("CRYPTOLITE_TEST_CERT_SERIAL");
        let input = PathBuf::from(required_env("CRYPTOLITE_TEST_INPUT"));
        let output = PathBuf::from(required_env("CRYPTOLITE_TEST_OUTPUT_DIR"));
        let tsp_server = std::env::var("CRYPTOLITE_TEST_TSP").ok();
        assert!(
            input.is_absolute() && input.is_file(),
            "input file must be an absolute existing file"
        );
        assert!(output.is_dir(), "output directory must already exist");
        let content = std::fs::read(&input).expect("read the input file");
        let directory = output.join(format!("cryptolite-linux-{}", unique_id()));
        std::fs::create_dir(&directory).expect("create a unique output directory");
        println!("output: {}", directory.display());

        let certificates = crate::signer::native::NativeSigner
            .list_certs()
            .unwrap_or_else(|error| panic!("certificate enumeration failed: {error}"));
        for certificate in &certificates {
            println!(
                "certificate: id={} serial={} source={} has_private_key={}",
                certificate.id, certificate.serial_number, certificate.source, certificate.has_private_key
            );
        }
        let certificate = certificates
            .iter()
            .find(|certificate| certificate.serial_number.eq_ignore_ascii_case(&serial))
            .unwrap_or_else(|| {
                let available = certificates
                    .iter()
                    .map(|certificate| {
                        format!("{} serial={}", certificate.id, certificate.serial_number)
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                panic!("certificate with serial {serial} not found. Available:\n{available}")
            });
        assert!(
            certificate.has_private_key,
            "the selected certificate has no private key"
        );
        println!("selected: {} · {}", certificate.subject, certificate.source);

        let sign = |standard: &str,
                    detached: bool,
                    base64: bool,
                    certificate_ids: Vec<String>,
                    name: &str|
         -> PathBuf {
            let requested = directory.join(name);
            let result = SignRequest {
                standard: standard.to_owned(),
                input_path: input.to_string_lossy().into_owned(),
                output_path: requested.to_string_lossy().into_owned(),
                certificate_ids,
                detached,
                base64,
                tsp_server: tsp_server.clone(),
            };
            let signed = crate::signer::native::NativeSigner
                .sign_file(result)
                .unwrap_or_else(|error| panic!("{name}: signing failed: {error}"));
            println!("{name}: {} bytes", signed.bytes_written);
            PathBuf::from(signed.output_path)
        };

        let verify = |path: &Path, detached: bool, base64: bool, check_crl: bool| {
            crate::signer::native::verify_signature(VerifyRequest {
                signature_path: path.to_string_lossy().into_owned(),
                content_path: detached
                    .then(|| input.to_string_lossy().into_owned()),
                detached,
                base64,
                check_crl,
            })
            .unwrap_or_else(|error| panic!("{}: verification failed: {error}", path.display()))
        };

        let single = vec![certificate.id.clone()];
        for (name, detached, base64) in [
            ("attached-der.sig", false, false),
            ("attached-base64.sig", false, true),
            ("detached-der.sig", true, false),
            ("detached-base64.sig", true, true),
        ] {
            let path = sign("cms", detached, base64, single.clone(), name);
            for check_crl in [false, true] {
                let result = verify(&path, detached, base64, check_crl);
                println!("{name} (check_crl={check_crl}): {}", result.message);
                assert!(result.valid, "{name}: signature is not valid");
                assert_eq!(result.signers.len(), 1, "{name}: expected one signer");
                let signer = &result.signers[0];
                println!(
                    "  chain_trusted={} revocation={} ({})",
                    signer.chain_trusted, signer.revocation_status, signer.revocation_message
                );
                if !check_crl {
                    assert_eq!(signer.revocation_status, "notChecked");
                } else {
                    assert!(
                        matches!(signer.revocation_status.as_str(), "good" | "unknown"),
                        "{name}: unexpected revocation status {}",
                        signer.revocation_status
                    );
                }
            }
        }

        let keyed = certificates
            .iter()
            .filter(|certificate| certificate.has_private_key)
            .collect::<Vec<_>>();
        if keyed.len() >= 2 {
            let ids = vec![keyed[0].id.clone(), keyed[1].id.clone()];
            let path = sign("cms", true, false, ids, "two-signers.sig");
            let result = verify(&path, true, false, false);
            assert!(result.valid, "two-signer CMS is not valid");
            assert_eq!(result.signers.len(), 2, "two-signer CMS must have two signers");
            for signer in &result.signers {
                println!("two-signer: {} · {}", signer.subject, signer.chain_message);
            }
        } else {
            println!("skipped the multi-signer check: fewer than two certificates with a private key");
        }

        if cades_available() {
            let cades = sign("cades-bes", false, false, single.clone(), "cades-bes.p7s");
            let result = verify(&cades, false, false, false);
            println!("cades-bes: {}", result.message);
            assert!(result.valid, "CAdES-BES signature is not valid");
            assert_eq!(result.signers.len(), 1);
        } else {
            // Без компонента CAdES подпись CAdES-BES должна падать с внятным текстом.
            let requested = directory.join("cades-bes.p7s");
            let outcome = crate::signer::native::NativeSigner.sign_file(SignRequest {
                standard: "cades-bes".to_owned(),
                input_path: input.to_string_lossy().into_owned(),
                output_path: requested.to_string_lossy().into_owned(),
                certificate_ids: single.clone(),
                detached: false,
                base64: false,
                tsp_server: None,
            });
            let message = outcome
                .expect_err("CAdES-BES must fail without the CAdES component")
                .to_string();
            println!("cades-bes unavailable: {message}");
            assert!(
                message.contains("libcades"),
                "the error must name the missing CAdES component: {message}"
            );
        }

        if let Some(tsp) = tsp_server.as_deref() {
            let requested = directory.join("cades-t.p7s");
            let outcome = crate::signer::native::NativeSigner.sign_file(SignRequest {
                standard: "cades-t".to_owned(),
                input_path: input.to_string_lossy().into_owned(),
                output_path: requested.to_string_lossy().into_owned(),
                certificate_ids: single.clone(),
                detached: false,
                base64: false,
                tsp_server: Some(tsp.to_owned()),
            });
            match outcome {
                Ok(signed) => {
                    let result = verify(Path::new(&signed.output_path), false, false, false);
                    println!("cades-t: {}", result.message);
                    assert!(result.valid, "CAdES-T signature is not valid");
                }
                Err(error) => {
                    let message = error.to_string();
                    println!("cades-t failed: {message}");
                    assert!(
                        message.contains(tsp),
                        "CAdES-T error must mention the TSP address: {message}"
                    );
                }
            }
        }

        let recipients = vec![certificate.id.clone()];
        let encrypted_path = directory.join("encrypted.p7m");
        let encrypted = crate::signer::native::encrypt_file(EncryptRequest {
            input_path: input.to_string_lossy().into_owned(),
            output_path: encrypted_path.to_string_lossy().into_owned(),
            certificate_ids: recipients,
            base64: false,
        })
        .unwrap_or_else(|error| panic!("encryption failed: {error}"));
        println!("encrypted: {} bytes", encrypted.bytes_written);
        let decrypted_path = directory.join("decrypted.bin");
        let decrypted = crate::signer::native::decrypt_file(DecryptRequest {
            input_path: encrypted.output_path.clone(),
            output_path: decrypted_path.to_string_lossy().into_owned(),
            base64: false,
        })
        .unwrap_or_else(|error| panic!("decryption failed: {error}"));
        let decrypted_bytes = std::fs::read(&decrypted.output_path).expect("read decrypted file");
        assert_eq!(decrypted_bytes, content, "decrypted bytes differ from the source");
        println!("decryption: {} bytes match", decrypted_bytes.len());
    }
}

