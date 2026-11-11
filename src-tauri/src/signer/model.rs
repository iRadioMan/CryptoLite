#![deny(unsafe_code)]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CspStatus {
    pub available: bool,
    pub cades_available: bool,
    pub signing_available: bool,
    pub license_available: bool,
    pub provider_type: Option<u32>,
    pub version: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertInfo {
    pub id: String,
    pub subject: String,
    pub issuer: String,
    pub expires_at: String,
    pub expired: bool,
    pub has_private_key: bool,
    pub source: String,
    pub serial_number: String,
    pub not_before: String,
    pub not_after: String,
    pub owner_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignRequest {
    pub standard: String,
    pub input_path: String,
    pub output_path: String,
    pub certificate_ids: Vec<String>,
    pub detached: bool,
    pub base64: bool,
    /// RFC 3161 TSP endpoint, используется только форматом CAdES-T.
    #[serde(default)]
    pub tsp_server: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignResult {
    pub output_path: String,
    pub bytes_written: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignBatchItemResult {
    pub input_path: String,
    pub output_path: String,
    pub success: bool,
    pub error: Option<String>,
}

/// Параметры визуальной отметки об электронной подписи (ГОСТ Р 7.0.97-2025, п. 5.23).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PdfStampSpec {
    /// Номер страницы, считая с нуля.
    pub page: usize,
    /// Прямоугольник отметки в миллиметрах от левого верхнего угла отображаемой страницы.
    pub left_mm: f64,
    pub top_mm: f64,
    pub width_mm: f64,
    pub height_mm: f64,
    /// Наименование должности; пустая строка скрывает строку.
    #[serde(default)]
    pub position: String,
}

/// Новый поворот страницы в итоговом документе.
///
/// Абсолютный угол на видимой стороне: 0/90/180/270. Так повторная подпись
/// того же PDF не накапливает поворот — странице задаётся одно и то же значение.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PageRotation {
    /// Номер страницы, считая с нуля.
    pub page: usize,
    pub rotation: i64,
}

/// Содержимое подписи, которым заполняется зарезервированное `/Contents`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PdfSignaturePayload {
    /// CMS CAdES-BES (DER) от подписанного диапазона PDF.
    pub cms: Vec<u8>,
    /// Смещение `<` в `/Contents`: исключается всё `<...>`, подписываются обе части PDF.
    pub contents_at: usize,
}

/// Запрос на подпись PDF с отметкой: один сертификат, один документ.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PdfSignRequest {
    pub input_path: String,
    pub output_path: String,
    pub certificate_id: String,
    pub stamp: PdfStampSpec,
    /// Новые повороты страниц, сохраняются в подписываемой ревизии PDF.
    #[serde(default)]
    pub page_rotations: Vec<PageRotation>,
}

/// Запрос на подготовку поля подписи PDF (нитка «подготовка → подпись → встраивание»).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PdfSignPrepareRequest {
    pub input_path: String,
    pub certificate_id: String,
    pub stamp: PdfStampSpec,
    /// Новые повороты страниц, сохраняются в подписываемой ревизии PDF.
    #[serde(default)]
    pub page_rotations: Vec<PageRotation>,
}

/// Подготовленный PDF: что именно нужно подписать CAdES-BES.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PdfSignPrepareResult {
    pub prepared_path: String,
    /// Префикс и суффикс PDF без `<Contents>`, с уже заполненным `/ByteRange`.
    pub signed_bytes: Vec<u8>,
    /// Смещение начала `/Contents` в подготовленном файле.
    pub contents_at: usize,
    pub page_count: usize,
}

/// Запрос на встраивание подписи в подготовленный PDF.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PdfSignFinishRequest {
    pub prepared_path: String,
    pub payload: PdfSignaturePayload,
    pub output_path: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyRequest {
    pub signature_path: String,
    pub content_path: Option<String>,
    pub detached: bool,
    pub base64: bool,
    /// Проверять отзыв сертификатов по CRL (может использовать сеть).
    #[serde(default)]
    pub check_crl: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifySignerInfo {
    pub subject: String,
    pub issuer: String,
    pub expires_at: String,
    pub chain_trusted: bool,
    pub chain_message: String,
    /// "notChecked" | "good" | "revoked" | "unknown".
    pub revocation_status: String,
    pub revocation_message: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResult {
    pub valid: bool,
    pub signature_path: String,
    pub content_path: Option<String>,
    pub signers: Vec<VerifySignerInfo>,
    pub message: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptRequest {
    pub input_path: String,
    pub output_path: String,
    pub certificate_ids: Vec<String>,
    pub base64: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptResult {
    pub output_path: String,
    pub bytes_written: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptRequest {
    pub input_path: String,
    pub output_path: String,
    pub base64: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptResult {
    pub output_path: String,
    pub bytes_written: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AppSettings {
    pub language: String,
    pub theme: String,
    pub animations: bool,
    pub default_standard: String,
    pub default_encoding: String,
    pub default_detached: bool,
    /// Вид подписи: attached, detached или stamp (встроенная подпись PDF).
    pub default_signature_type: String,
    pub default_signature_extension: String,
    pub default_certificate_ids: Vec<String>,
    pub default_output_directory: String,
    pub save_last_signing_settings: bool,
    pub tsp_server: String,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            language: "system".to_owned(),
            theme: "system".to_owned(),
            animations: true,
            default_standard: "cms".to_owned(),
            default_encoding: "der".to_owned(),
            default_detached: true,
            default_signature_type: "detached".to_owned(),
            default_signature_extension: "sig".to_owned(),
            default_certificate_ids: Vec::new(),
            default_output_directory: String::new(),
            save_last_signing_settings: true,
            tsp_server: "http://pki.tax.gov.ru/tsp/tsp.srf".to_owned(),
        }
    }
}

impl CspStatus {
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self {
            available: false,
            cades_available: false,
            signing_available: false,
            license_available: false,
            provider_type: None,
            version: None,
            message: message.into(),
        }
    }
}
