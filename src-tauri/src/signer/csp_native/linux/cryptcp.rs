#![allow(unsafe_code)]

//! CAdES-BES/T на Linux через штатную утилиту `cryptcp` из состава КриптоПро CSP.
//!
//! Аналога CAdESCOM на Linux нет (`libcades.so` не поставляется), поэтому подписанные
//! атрибуты CAdES формирует `cryptcp`: `-cadesbes` для BES, `-cadest -cadestsa <url>`
//! для T. Выбор ключа — `-cont <FQCN>` для контейнера токена либо `-thumbprint <sha1>`
//! для сертификата личного хранилища.

use super::{api, token};
use crate::signer::{SignRequest, SignResult, SignerError};
use crate::tr;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;

/// Адрес TSP-сервера по умолчанию не подставляется: CAdES-T без адреса — ошибка.
const MAX_DETAILS_LENGTH: usize = 2000;

/// Установлен ли компонент CAdES КриптоПро CSP.
///
/// `cryptcp` создаёт CAdES-BES/T не сам: он загружает `libcades.so` и вызывает
/// `CadesMsgOpenToEncode`. Без этой библиотеки `-cadesbes`/`-cadest` завершаются ошибкой
/// «Не удалось открыть файл 'cades library'» (0x20000065), поэтому возможность
/// проверяется заранее и попадает в состояние CSP.
pub fn cades_component_present() -> bool {
    api::library_directories().iter().any(|directory| {
        ["libcades.so.2", "libcades.so"]
            .iter()
            .any(|name| directory.join(name).is_file())
    })
}

/// Путь к `cryptcp`: переменная окружения, затем стандартные каталоги КриптоПро.
pub fn binary_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("CRYPTOLITE_CRYPTCP") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }
    [
        "/opt/cprocsp/bin/amd64/cryptcp",
        "/usr/bin/cryptcp",
        "/usr/local/bin/cryptcp",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.is_file())
}

/// Селектор сертификата: контейнер токена или отпечаток сертификата.
pub(super) fn container_selector(container: &str) -> Vec<OsString> {
    vec!["-cont".into(), container.into()]
}

/// `-thumbprint` принимает SHA-1 сертификата в hex.
pub(super) fn thumbprint_selector(der: &[u8]) -> Vec<OsString> {
    vec!["-thumbprint".into(), sha1_thumbprint(der).into()]
}

fn sha1_thumbprint(der: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    Sha1::digest(der)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Аргументы `cryptcp` для подписи файла.
///
/// Порядок фиксирован: режим (`-sign -der`), стандарт CAdES, отсоединённость,
/// селектор сертификата, затем входной и выходной файлы.
pub(super) fn build_args(
    standard: &str,
    tsp_server: Option<&str>,
    detached: bool,
    selector: &[OsString],
    input: &Path,
    output: &Path,
) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec!["-sign".into(), "-der".into()];
    if standard == "cades-t" {
        args.push("-cadest".into());
        args.push("-cadestsa".into());
        args.push(tsp_server.unwrap_or_default().into());
    } else {
        args.push("-cadesbes".into());
    }
    if detached {
        args.push("-detached".into());
    }
    args.extend(selector.iter().cloned());
    args.push(input.as_os_str().to_owned());
    args.push(output.as_os_str().to_owned());
    args
}

/// Приводит BER-кодировку КриптоПро к DER.
///
/// `cryptcp -cadesbes` выдаёт CMS с неопределёнными длинами (`30 80 … 00 00`): отдельным
/// файлом такая подпись проверяется, но в `/Contents` PDF нужна определённая длина
/// (`30 82 …`), иначе Adobe и КриптоАРМ не находят подпись. Запись с определённой
/// длиной возвращается без изменений — `cryptcp -cadest` уже отдаёт DER.
pub(super) fn ber_to_der(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() < 2 || bytes[0] != 0x30 || bytes[1] != 0x80 {
        return Ok(bytes.to_vec());
    }
    let mut reader = Reader {
        data: bytes,
        position: 0,
    };
    let mut output = Vec::with_capacity(bytes.len());
    while reader.position < bytes.len() {
        match reader.element()? {
            Some(element) => output.extend_from_slice(&element),
            None => break,
        }
    }
    if reader.position != bytes.len() {
        return Err(format!(
            "trailing bytes after the CMS: {} of {}",
            reader.position,
            bytes.len()
        ));
    }
    Ok(output)
}

struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl Reader<'_> {
    /// Один элемент: содержимое неопределённой длины собирается до маркера `00 00`.
    fn element(&mut self) -> Result<Option<Vec<u8>>, String> {
        let tag = self.byte()?;
        if tag == 0 {
            if self.byte()? != 0 {
                return Err("unexpected end-of-contents".to_owned());
            }
            return Ok(None);
        }
        let declared = self.length()?;
        let constructed = tag & 0x20 != 0;
        let content = match declared {
            None => {
                if !constructed {
                    return Err("indefinite length on a primitive element".to_owned());
                }
                let mut content = Vec::new();
                loop {
                    match self.element()? {
                        Some(element) => content.extend_from_slice(&element),
                        None => break,
                    }
                }
                content
            }
            Some(length) => {
                let end = self
                    .position
                    .checked_add(length)
                    .ok_or_else(|| "length overflow".to_owned())?;
                if end > self.data.len() {
                    return Err("truncated content".to_owned());
                }
                if constructed {
                    let mut content = Vec::new();
                    while self.position < end {
                        match self.element()? {
                            Some(element) => content.extend_from_slice(&element),
                            None => break,
                        }
                    }
                    if self.position != end {
                        return Err("content length mismatch".to_owned());
                    }
                    content
                } else {
                    let content = self.data[self.position..end].to_vec();
                    self.position = end;
                    content
                }
            }
        };
        let mut element = vec![tag];
        write_length(&mut element, content.len());
        element.extend_from_slice(&content);
        Ok(Some(element))
    }

    fn byte(&mut self) -> Result<u8, String> {
        let byte = *self
            .data
            .get(self.position)
            .ok_or_else(|| "truncated element".to_owned())?;
        self.position += 1;
        Ok(byte)
    }

    /// `None` — неопределённая длина (`0x80`).
    fn length(&mut self) -> Result<Option<usize>, String> {
        let first = self.byte()?;
        if first == 0x80 {
            return Ok(None);
        }
        if first < 0x80 {
            return Ok(Some(first as usize));
        }
        let count = (first & 0x7f) as usize;
        if count == 0 || count > std::mem::size_of::<usize>() {
            return Err("invalid length".to_owned());
        }
        let mut length = 0usize;
        for _ in 0..count {
            let byte = self.byte()?;
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(byte as usize))
                .ok_or_else(|| "length overflow".to_owned())?;
        }
        Ok(Some(length))
    }
}

/// Минимальная (DER) запись длины.
fn write_length(output: &mut Vec<u8>, length: usize) {
    if length < 0x80 {
        output.push(length as u8);
        return;
    }
    let bytes = length.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let significant = &bytes[first..];
    output.push(0x80 | significant.len() as u8);
    output.extend_from_slice(significant);
}

/// Сертификат, которым подписывает `cryptcp`.
struct CertificateSource {
    der: Vec<u8>,
    /// Контейнер токена: если `cryptcp` не примет `-cont`, повтор идёт по отпечатку.
    container: Option<String>,
}

fn resolve_certificate(certificate_id: &str) -> Result<CertificateSource, SignerError> {
    let details = {
        let cached = token::details_for_certificate(certificate_id);
        if cached.is_empty() {
            token::find_details_by_id(certificate_id)
        } else {
            cached.into_iter().next()
        }
    };
    if let Some(details) = details {
        return Ok(CertificateSource {
            der: details.der,
            container: Some(details.container),
        });
    }
    let store = api::open_personal_store().ok_or_else(|| {
        api::store_error(tr!(
            "не удалось открыть личное хранилище;",
            "could not open the personal store;"
        ))
    })?;
    let context = api::find_certificate(&store, certificate_id)?;
    let der = api::certificate_der(context.as_ptr()).ok_or_else(|| {
        SignerError::Signing(tr!(
            "у выбранного сертификата нет DER-кодировки",
            "the selected certificate has no DER encoding"
        ))
    })?;
    Ok(CertificateSource { der, container: None })
}

/// Временный каталог подписи; удаляется при выходе, в том числе по ошибке.
struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn create() -> Result<Self, SignerError> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("cryptolite-cades-{nanos:x}"));
        std::fs::create_dir(&path).map_err(|error| {
            SignerError::Signing(tr!(
                "не удалось создать временный каталог ({}): {error}",
                "could not create a temporary directory ({}): {error}",
                path.display()
            ))
        })?;
        Ok(Self { path })
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.path) {
            tracing::warn!(path = %self.path.display(), %error, "could not remove the temporary directory");
        }
    }
}

fn truncate(text: &str) -> String {
    if text.chars().count() <= MAX_DETAILS_LENGTH {
        return text.to_owned();
    }
    format!(
        "{}…",
        text.chars().take(MAX_DETAILS_LENGTH).collect::<String>()
    )
}

fn run(
    binary: &Path,
    args: &[OsString],
    standard: &str,
    tsp_server: Option<&str>,
) -> Result<(), SignerError> {
    let output = std::process::Command::new(binary)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| {
            SignerError::Signing(tr!(
                "не удалось запустить cryptcp ({}): {error}",
                "could not start cryptcp ({}): {error}",
                binary.display()
            ))
        })?;
    if output.status.success() {
        return Ok(());
    }
    let mut details = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.trim().is_empty() {
        if !details.is_empty() {
            details.push('\n');
        }
        details.push_str(stderr.trim());
    }
    let details = truncate(&details);
    let code = match output.status.code() {
        Some(code) => code.to_string(),
        None => tr!("сигнал", "signal").to_owned(),
    };
    let tsp = tsp_server.unwrap_or_default();
    Err(SignerError::Signing(if standard == "cades-t" {
        tr!(
            "Не удалось создать подпись CAdES-T через TSP {tsp}: cryptcp завершился с кодом {code}. {details}",
            "Could not create a CAdES-T signature via TSP {tsp}: cryptcp exited with code {code}. {details}"
        )
    } else {
        tr!(
            "Не удалось создать подпись CAdES-BES: cryptcp завершился с кодом {code}. {details}",
            "Could not create a CAdES-BES signature: cryptcp exited with code {code}. {details}"
        )
    }))
}

/// Подпись CAdES-BES/T: ровно один сертификат, файл создаётся `cryptcp`.
pub fn sign_file(request: SignRequest) -> Result<SignResult, SignerError> {
    if request.certificate_ids.len() != 1 {
        return Err(SignerError::Signing(tr!(
            "Форматы CAdES-BES и CAdES-T поддерживают подпись ровно одним сертификатом; для нескольких подписантов выберите CMS / PKCS#7",
            "CAdES-BES and CAdES-T support signing with exactly one certificate; for multiple signers, choose CMS / PKCS#7"
        )));
    }
    let standard = match request.standard.as_str() {
        "cades-bes" => "cades-bes",
        "cades-t" => "cades-t",
        other => {
            return Err(SignerError::Signing(tr!(
                "Неизвестный формат подписи CAdES: {other}",
                "Unknown CAdES signature format: {other}"
            )))
        }
    };
    let tsp_server = request
        .tsp_server
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if standard == "cades-t" {
        let Some(tsp) = tsp_server else {
            return Err(SignerError::Signing(tr!(
                "Укажите адрес TSP-сервера в настройках для подписи CAdES-T.",
                "Set the TSP server address in Settings to create a CAdES-T signature."
            )));
        };
        if !tsp.starts_with("http://") && !tsp.starts_with("https://") {
            return Err(SignerError::Signing(tr!(
                "Адрес TSP-сервера должен начинаться с http:// или https://.",
                "The TSP server address must start with http:// or https://."
            )));
        }
    }
    let certificate_id = request
        .certificate_ids
        .first()
        .cloned()
        .ok_or_else(|| {
            SignerError::Signing(tr!(
                "не выбран сертификат подписи",
                "no signing certificate selected"
            ))
        })?;
    let binary = match binary_path() {
        Some(binary) if cades_component_present() => binary,
        Some(_) => {
            // cryptcp без libcades падает на «Не удалось открыть файл 'cades library'»:
            // лучше сказать об этом прямо и предложить рабочий формат.
            let tsp = tsp_server.unwrap_or_default();
            return Err(SignerError::Signing(if standard == "cades-t" {
                tr!(
                    "Не установлен компонент CAdES КриптоПро CSP: подпись CAdES-T через TSP {tsp} невозможна. Установите пакет cprocsp-pki-cades-64; доступна подпись CMS / PKCS#7.",
                    "The CryptoPro CSP CAdES component is not installed: a CAdES-T signature via TSP {tsp} is not possible. Install the cprocsp-pki-cades-64 package; CMS / PKCS#7 signing is available."
                )
            } else {
                tr!(
                    "Не установлен компонент CAdES КриптоПро CSP: подпись CAdES-BES невозможна. Установите пакет cprocsp-pki-cades-64; доступна подпись CMS / PKCS#7.",
                    "The CryptoPro CSP CAdES component is not installed: a CAdES-BES signature is not possible. Install the cprocsp-pki-cades-64 package; CMS / PKCS#7 signing is available."
                )
            }));
        }
        None => {
            return Err(SignerError::Signing(tr!(
                "не найден cryptcp: CAdES-BES и CAdES-T формирует штатная утилита КриптоПро CSP. Проверены CRYPTOLITE_CRYPTCP, /opt/cprocsp/bin/amd64/cryptcp, /usr/bin/cryptcp, /usr/local/bin/cryptcp.",
                "cryptcp was not found: CAdES-BES and CAdES-T are produced by the CryptoPro CSP tool. Checked CRYPTOLITE_CRYPTCP, /opt/cprocsp/bin/amd64/cryptcp, /usr/bin/cryptcp, /usr/local/bin/cryptcp."
            )));
        }
    };
    let source = resolve_certificate(&certificate_id)?;
    let temporary = TemporaryDirectory::create()?;
    let output_path = temporary.path.join("signature.der");
    let input = PathBuf::from(&request.input_path);

    let primary = match &source.container {
        Some(container) => container_selector(container),
        None => thumbprint_selector(&source.der),
    };
    let args = build_args(
        standard,
        tsp_server,
        request.detached,
        &primary,
        &input,
        &output_path,
    );
    if let Err(first_error) = run(&binary, &args, standard, tsp_server) {
        if source.container.is_none() {
            return Err(first_error);
        }
        // Контейнер мог не подойти правилу выбора `cryptcp`: пробуем по отпечатку.
        let fallback = build_args(
            standard,
            tsp_server,
            request.detached,
            &thumbprint_selector(&source.der),
            &input,
            &output_path,
        );
        if run(&binary, &fallback, standard, tsp_server).is_err() {
            return Err(first_error);
        }
    }

    let bytes = std::fs::read(&output_path).map_err(|error| {
        SignerError::Signing(tr!(
            "cryptcp не создал файл подписи ({}): {error}",
            "cryptcp did not produce a signature file ({}): {error}",
            output_path.display()
        ))
    })?;
    if bytes.is_empty() {
        return Err(SignerError::Signing(tr!(
            "cryptcp создал пустой файл подписи",
            "cryptcp produced an empty signature file"
        )));
    }
    let bytes = ber_to_der(&bytes).map_err(|details| {
        SignerError::Signing(tr!(
            "некорректная BER-кодировка подписи CAdES: {details}",
            "the CAdES signature has an invalid BER encoding: {details}"
        ))
    })?;
    let bytes = if request.base64 {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .encode(&bytes)
            .into_bytes()
    } else {
        bytes
    };
    let requested = PathBuf::from(&request.output_path);
    let final_path = crate::signer::output::write_unique(&requested, &bytes).map_err(|error| {
        SignerError::Signing(tr!(
            "Не удалось записать результат CAdES ({}): {error}",
            "Could not write the CAdES result ({}): {error}",
            requested.display()
        ))
    })?;
    Ok(SignResult {
        output_path: final_path.display().to_string(),
        bytes_written: bytes.len(),
    })
}
