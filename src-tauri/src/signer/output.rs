#![deny(unsafe_code)]
//! Единая точка записи файлов результата: имя подбирается без перезаписи существующих файлов.

use crate::tr;
use std::ffi::OsString;
use std::fs::File;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

/// Сколько суффиксов перебирать: `имя (1).ext` … `имя (9999).ext`.
const MAX_ATTEMPTS: u32 = 10_000;

/// Записывает `bytes` в новый файл по пути `desired`, не перезаписывая существующий.
///
/// Если имя занято, добавляет суффикс перед расширением: `doc.pdf` → `doc (1).pdf`,
/// `doc` → `doc (1)`, `archive.tar.gz` → `archive.tar (1).gz`.
/// Возвращает фактический путь. После записи данные синхронизируются (`sync_all`);
/// при ошибке записи созданный файл удаляется.
pub(crate) fn write_unique(desired: &Path, bytes: &[u8]) -> std::io::Result<PathBuf> {
    let (mut file, path) = create_unique(desired)?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(&path);
        return Err(error);
    }
    Ok(path)
}

/// Открывает новый файл, добавляя ` (n)` к имени, пока оно занято.
fn create_unique(desired: &Path) -> std::io::Result<(File, PathBuf)> {
    let directory = desired.parent().unwrap_or_else(|| Path::new("."));
    let mut attempt = 0u32;
    loop {
        let candidate = if attempt == 0 {
            desired.to_path_buf()
        } else {
            directory.join(suffixed_name(desired, attempt)?)
        };
        match File::create_new(&candidate) {
            Ok(file) => return Ok((file, candidate)),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                attempt += 1;
                if attempt >= MAX_ATTEMPTS {
                    return Err(std::io::Error::new(
                        ErrorKind::AlreadyExists,
                        tr!(
                            "не удалось подобрать свободное имя файла",
                            "could not find an available file name"
                        ),
                    ));
                }
            }
            Err(error) => return Err(error),
        }
    }
}

/// Имя с суффиксом: `report.pdf` + 1 → `report (1).pdf`; `report` + 1 → `report (1)`.
fn suffixed_name(desired: &Path, attempt: u32) -> std::io::Result<OsString> {
    let stem = desired.file_stem().ok_or_else(|| {
        std::io::Error::new(
            ErrorKind::InvalidInput,
            tr!("у пути нет имени файла", "the path has no file name"),
        )
    })?;
    let mut name = OsString::from(stem);
    name.push(format!(" ({attempt})"));
    if let Some(extension) = desired.extension() {
        name.push(".");
        name.push(extension);
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "cryptolite-output-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn keeps_free_name_and_suffixes_taken_names() {
        let dir = TempDir::new();
        let desired = dir.0.join("report.pdf");
        let first = write_unique(&desired, b"one").unwrap();
        assert_eq!(first, desired);
        let second = write_unique(&desired, b"two").unwrap();
        assert_eq!(second, dir.0.join("report (1).pdf"));
        let third = write_unique(&desired, b"three").unwrap();
        assert_eq!(third, dir.0.join("report (2).pdf"));
        assert_eq!(std::fs::read(&first).unwrap(), b"one");
        assert_eq!(std::fs::read(&second).unwrap(), b"two");
        assert_eq!(std::fs::read(&third).unwrap(), b"three");
    }

    #[test]
    fn suffixes_before_extension_and_handles_no_extension() {
        let dir = TempDir::new();
        std::fs::write(dir.0.join("archive.tar.gz"), b"x").unwrap();
        assert_eq!(
            write_unique(&dir.0.join("archive.tar.gz"), b"y").unwrap(),
            dir.0.join("archive.tar (1).gz")
        );
        std::fs::write(dir.0.join("report"), b"x").unwrap();
        assert_eq!(
            write_unique(&dir.0.join("report"), b"y").unwrap(),
            dir.0.join("report (1)")
        );
    }

    #[test]
    fn missing_directory_is_reported() {
        let dir = TempDir::new();
        let missing = dir.0.join("missing").join("report.pdf");
        assert!(write_unique(&missing, b"x").is_err());
        assert!(!missing.exists());
    }
}
