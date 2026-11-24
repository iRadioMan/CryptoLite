#![deny(unsafe_code)]
//! Преобразование DOC/DOCX в PDF через LibreOffice в headless-режиме.

use crate::signer::document::truncated;
use crate::tr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// Куда смотреть, если `soffice` не нашёлся в `PATH`.
const KNOWN_PATHS: [&str; 3] = [
    "/usr/bin/soffice",
    "/usr/lib/libreoffice/program/soffice",
    "/opt/libreoffice/program/soffice",
];

/// Рабочий каталог конвертера: удаляется вместе с профилем и результатом.
struct WorkDir(PathBuf);

impl WorkDir {
    fn new() -> Result<Self, String> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("cryptolite-lo-{}-{nanos}", std::process::id()));
        for directory in [path.clone(), path.join("profile"), path.join("out")] {
            std::fs::create_dir(&directory).map_err(|error| {
                tr!(
                    "Не удалось создать временный каталог: {error}",
                    "Could not create a temporary directory: {error}"
                )
            })?;
        }
        Ok(Self(path))
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn convert(input: &Path, output: &Path) -> Result<(), String> {
    let soffice = find_soffice().ok_or_else(|| {
        tr!(
            "LibreOffice не найден. Установите LibreOffice или задайте путь в переменной CRYPTOLITE_SOFFICE",
            "LibreOffice was not found. Install LibreOffice or set CRYPTOLITE_SOFFICE"
        )
    })?;
    let work = WorkDir::new()?;
    let profile = work.0.join("profile");
    let out = work.0.join("out");
    // Абсолютный путь на Linux начинается с `/`: URL получается `file:///tmp/...`.
    let profile_url = format!("-env:UserInstallation=file://{}", profile.display());
    let result = Command::new(&soffice)
        .arg(profile_url)
        .args([
            "--headless",
            "--norestore",
            "--nodefault",
            "--nolockcheck",
            "--convert-to",
            "pdf:writer_pdf_Export",
            "--outdir",
        ])
        .arg(&out)
        .arg(input)
        .output()
        .map_err(|error| {
            tr!(
                "Не удалось запустить LibreOffice: {error}",
                "Could not start LibreOffice: {error}"
            )
        })?;
    let stem = input
        .file_stem()
        .ok_or_else(|| tr!("У пути нет имени файла", "The path has no file name"))?;
    // LibreOffice называет результат `<имя без расширения>.pdf`, точки в имени сохраняются.
    let mut name = std::ffi::OsString::from(stem);
    name.push(".pdf");
    let converted = out.join(name);
    if !result.status.success() || !converted.is_file() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        let stdout = String::from_utf8_lossy(&result.stdout);
        let raw = format!("{}\n{}", stderr.trim(), stdout.trim());
        let details = truncated(&raw);
        return Err(tr!(
            "Не удалось преобразовать документ через LibreOffice: {details}",
            "Could not convert the document with LibreOffice: {details}"
        ));
    }
    if std::fs::rename(&converted, output).is_err() {
        std::fs::copy(&converted, output)
            .and_then(|_| std::fs::remove_file(&converted))
            .map_err(|error| {
                tr!(
                    "Не удалось сохранить преобразованный PDF: {error}",
                    "Could not save the converted PDF: {error}"
                )
            })?;
    }
    Ok(())
}

/// `CRYPTOLITE_SOFFICE`, затем `PATH`, затем типовые пути установки.
fn find_soffice() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("CRYPTOLITE_SOFFICE") {
        let candidate = PathBuf::from(path);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for directory in std::env::split_paths(&paths) {
            let candidate = directory.join("soffice");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    KNOWN_PATHS
        .iter()
        .map(PathBuf::from)
        .find(|candidate| candidate.is_file())
}
