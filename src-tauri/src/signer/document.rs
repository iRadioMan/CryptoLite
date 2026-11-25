#![deny(unsafe_code)]
//! Преобразование DOC/DOCX/ODT в PDF: Microsoft Word через COM на Windows, LibreOffice на Linux.
//!
//! Исходный документ не изменяется: PDF создаётся рядом с ним через
//! [`crate::signer::output::write_unique`] и не перезаписывает занятое имя.

use crate::signer::output::write_unique;
use crate::signer::ConvertedPdf;
use crate::tr;
use base64::Engine as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(target_os = "linux")]
#[path = "libreoffice.rs"]
mod libreoffice;
#[cfg(target_os = "windows")]
#[path = "word.rs"]
mod word;

/// Временный PDF конвертера: удаляется при выходе из области видимости.
struct TempPdf(PathBuf);

impl TempPdf {
    /// Свободный путь в системном каталоге: файл не создаётся заранее,
    /// иначе Word и LibreOffice откажутся в него писать.
    fn reserve() -> Self {
        let directory = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut attempt = 0u32;
        loop {
            let name = format!(
                "cryptolite-converted-{}-{nanos}-{attempt}.pdf",
                std::process::id()
            );
            let candidate = directory.join(name);
            if !candidate.exists() {
                return Self(candidate);
            }
            attempt += 1;
        }
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempPdf {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Обрезает диагностику внешнего процесса до 2000 символов по границе UTF-8.
pub(crate) fn truncated(text: &str) -> String {
    text.trim().chars().take(2000).collect()
}

/// Преобразует DOC/DOCX/ODT в PDF и возвращает путь к нему вместе с содержимым в Base64.
pub fn convert_to_pdf(input: &Path) -> Result<ConvertedPdf, String> {
    let extension = input
        .extension()
        .map(|extension| extension.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if !matches!(extension.as_str(), "doc" | "docx" | "odt") {
        return Err(tr!(
            "Преобразование в PDF поддерживается только для файлов DOC, DOCX и ODT",
            "Only DOC, DOCX and ODT files can be converted to PDF"
        ));
    }
    if !input.is_file() {
        let path = input.display();
        return Err(tr!(
            "Документ не найден: {path}",
            "The document was not found: {path}"
        ));
    }
    let temp = TempPdf::reserve();
    #[cfg(target_os = "windows")]
    word::convert(input, temp.path())?;
    #[cfg(target_os = "linux")]
    libreoffice::convert(input, temp.path())?;
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = &temp;
        return Err(tr!(
            "Преобразование DOC/DOCX/ODT в PDF поддерживается только на Windows и Linux",
            "DOC/DOCX/ODT to PDF conversion is supported only on Windows and Linux"
        ));
    }
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    {
        let bytes = std::fs::read(temp.path()).map_err(|error| {
            tr!(
                "Не удалось прочитать преобразованный PDF: {error}",
                "Could not read the converted PDF: {error}"
            )
        })?;
        if bytes.is_empty() {
            return Err(tr!(
                "Документ преобразован в пустой PDF",
                "The document produced an empty PDF"
            ));
        }
        let directory = input
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let stem = input
            .file_stem()
            .ok_or_else(|| tr!("У пути нет имени файла", "The path has no file name"))?;
        // Имя не должно терять точки из основы: `file.v2.docx` → `file.v2.pdf`.
        let mut name = std::ffi::OsString::from(stem);
        name.push(".pdf");
        let desired = directory.join(name);
        let pdf_path = write_unique(&desired, &bytes).map_err(|error| {
            tr!(
                "Не удалось сохранить преобразованный PDF: {error}",
                "Could not save the converted PDF: {error}"
            )
        })?;
        Ok(ConvertedPdf {
            pdf_path: pdf_path.to_string_lossy().into_owned(),
            pdf_base64: base64::engine::general_purpose::STANDARD.encode(&bytes),
            bytes: bytes.len(),
        })
    }
}
