#![deny(unsafe_code)]
//! Встроенная подпись PDF (PAdES-BES) с видимой отметкой об ЭП.
//!
//! Криптографии здесь нет: подпись диапазона PDF выполняет CAdESCOM (`sign_hash`), а этот
//! модуль ведёт последовательность: подготовка поля `/Sig` → подпись диапазона → вписывание CMS.

use crate::signer::csp_native;
use crate::signer::csp_native::windows::digest;
use crate::signer::pdf_layer::{self, PreparedDocument};
use crate::signer::{PdfSignaturePayload, PdfStampSpec, SignResult, SignerError};

fn signing_error(message: impl Into<String>) -> SignerError {
    SignerError::Signing(message.into())
}

fn new_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{nanos:x}")
}

/// Восстанавливает подготовленный PDF по пути из результата подготовки.
pub fn restore(prepared_path: &str) -> Result<PreparedDocument, SignerError> {
    let path = std::path::PathBuf::from(prepared_path);
    let bytes = std::fs::read(&path).map_err(|error| {
        signing_error(format!("не удалось прочитать подготовленный PDF: {error}"))
    })?;
    let (offsets_at, contents_at, contents_end) = pdf_layer::locate(&bytes)?;
    Ok(PreparedDocument {
        path,
        page_count: 0,
        digest_algorithm: String::new(),
        bytes,
        offsets_at,
        contents_at,
        contents_end,
    })
}

/// Готовит PDF: в последнюю версию добавляется поле `/Sig` с отметкой.
pub fn prepare(
    input_path: &str,
    certificate_id: &str,
    stamp: &PdfStampSpec,
) -> Result<PreparedDocument, SignerError> {
    let public_key_oid = csp_native::windows::pdf_certificate_public_key_oid(certificate_id)?;
    let (_, algorithm) = digest::hash_for_public_key(&public_key_oid).map_err(signing_error)?;
    pdf_layer::prepare(
        std::path::Path::new(input_path),
        stamp,
        certificate_id,
        algorithm,
        &new_id(),
    )
}

/// Подписывает диапазон PDF сертификатом: CMS CAdES-BES (DER).
///
/// Подписывается содержимое диапазона `/ByteRange`: байты до `<` в `/Contents` и всё после
/// `>` — ровно то, что Acrobat и КриптоАРМ вычисляют для проверки подписи (ISO 32000-1, 7.6.2).
pub fn sign_prepared(
    prepared: &PreparedDocument,
    certificate_id: &str,
) -> Result<PdfSignaturePayload, SignerError> {
    // Проверка типа и положения поля подписи выполнена при подготовке документа.
    // Тот же путь сборки, что и в `finish`, но вместо CMS — нули того же размера:
    // длина зарезервированного поля не зависит от содержимого, поэтому подписанные байты
    // (с уже подставленным `/ByteRange`) совпадут с итоговым файлом побайтово.
    let capacity = prepared
        .contents_end
        .saturating_sub(prepared.contents_at + 1);
    let placeholder = "0".repeat(capacity);
    let document = pdf_layer::assemble_document(
        &prepared.bytes,
        prepared.contents_at,
        prepared.contents_end,
        placeholder.as_bytes(),
    )?;
    let (_offsets, contents_at, contents_end) = pdf_layer::locate(&document)?;
    let content = pdf_layer::signed_content(&document, contents_at, contents_end)?;
    let cms = csp_native::windows::sign_pdf_range(certificate_id, &content)?;
    Ok(PdfSignaturePayload {
        cms,
        contents_at: prepared.contents_at,
    })
}

/// Вписывает готовую CMS в `/Contents` и записывает подписанный PDF.
pub fn finish_signed(
    prepared: &PreparedDocument,
    payload: &PdfSignaturePayload,
    output_path: &str,
) -> Result<SignResult, SignerError> {
    pdf_layer::finish(prepared, payload, std::path::Path::new(output_path))
}

/// Один подписант одного PDF: подготовка, подпись и встраивание.
pub fn sign_document(
    input_path: &str,
    output_path: &str,
    certificate_id: &str,
    stamp: &PdfStampSpec,
) -> Result<SignResult, SignerError> {
    let prepared = prepare(input_path, certificate_id, stamp)?;
    let payload = sign_prepared(&prepared, certificate_id)?;
    finish_signed(&prepared, &payload, output_path)
}
