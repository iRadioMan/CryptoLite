use crate::signer::{
    CertInfo, CspStatus, DecryptRequest, DecryptResult, EncryptRequest, EncryptResult,
    SignBatchItemResult, SignRequest, SignResult, Signer, SignerError, VerifyRequest, VerifyResult,
};
use crate::tr;
use std::path::PathBuf;
use tauri::Manager;

fn settings_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|directory| directory.join("settings.json"))
        .map_err(|error| {
            tr!(
                "Не удалось определить каталог настроек: {error}",
                "Could not determine the settings directory: {error}"
            )
        })
}

#[tauri::command]
pub fn set_language(language: String) {
    if let Some(language) = crate::i18n::Language::from_tag(&language) {
        crate::i18n::set(language);
    }
}

#[tauri::command]
pub async fn load_settings(app: tauri::AppHandle) -> Result<crate::signer::AppSettings, String> {
    let mut settings = tokio::task::spawn_blocking(move || load_settings_sync(&app))
        .await
        .map_err(|error| {
            tr!(
                "Ошибка загрузки настроек: {error}",
                "Could not load settings: {error}"
            )
        })??;
    if settings.tsp_server.trim().is_empty() {
        settings.tsp_server = crate::signer::AppSettings::default().tsp_server;
    }
    Ok(settings)
}

#[cfg(windows)]
fn load_settings_sync(app: &tauri::AppHandle) -> Result<crate::signer::AppSettings, String> {
    use winreg::{enums::HKEY_CURRENT_USER, RegKey};

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    match hkcu.open_subkey("Software\\CryptoLite") {
        Ok(key) => match key.get_value::<String, _>("Settings") {
            Ok(json) => serde_json::from_str(&json).map_err(|error| {
                tr!(
                    "Не удалось прочитать настройки из HKCU: {error}",
                    "Could not read settings from HKCU: {error}"
                )
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                migrate_legacy_settings(app)
            }
            Err(error) => Err(tr!(
                "Не удалось прочитать настройки из HKCU: {error}",
                "Could not read settings from HKCU: {error}"
            )),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => migrate_legacy_settings(app),
        Err(error) => Err(tr!(
            "Не удалось открыть HKCU\\Software\\CryptoLite: {error}",
            "Could not open HKCU\\Software\\CryptoLite: {error}"
        )),
    }
}

#[cfg(windows)]
fn migrate_legacy_settings(app: &tauri::AppHandle) -> Result<crate::signer::AppSettings, String> {
    let path = settings_path(app)?;
    match std::fs::read(&path) {
        Ok(contents) => {
            let settings: crate::signer::AppSettings =
                serde_json::from_slice(&contents).map_err(|error| {
                    tr!(
                        "Не удалось прочитать {}: {error}",
                        "Could not read {}: {error}",
                        path.display()
                    )
                })?;
            save_settings_sync(&settings)?;
            Ok(settings)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(crate::signer::AppSettings::default())
        }
        Err(error) => Err(tr!(
            "Не удалось прочитать {}: {error}",
            "Could not read {}: {error}",
            path.display()
        )),
    }
}

#[cfg(not(windows))]
fn load_settings_sync(app: &tauri::AppHandle) -> Result<crate::signer::AppSettings, String> {
    let path = settings_path(app)?;
    match std::fs::read(&path) {
        Ok(contents) => serde_json::from_slice(&contents).map_err(|error| {
            tr!(
                "Не удалось прочитать {}: {error}",
                "Could not read {}: {error}",
                path.display()
            )
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(crate::signer::AppSettings::default())
        }
        Err(error) => Err(tr!(
            "Не удалось прочитать {}: {error}",
            "Could not read {}: {error}",
            path.display()
        )),
    }
}

#[tauri::command]
pub async fn save_settings(
    app: tauri::AppHandle,
    settings: crate::signer::AppSettings,
) -> Result<(), String> {
    if !["system", "ru", "en"].contains(&settings.language.as_str())
        || !["system", "light", "dark"].contains(&settings.theme.as_str())
        || !["cms", "cades-bes", "cades-t"].contains(&settings.default_standard.as_str())
        || !["der", "base64"].contains(&settings.default_encoding.as_str())
        || !["sig", "p7s"].contains(&settings.default_signature_extension.as_str())
        || !["attached", "detached", "stamp"].contains(&settings.default_signature_type.as_str())
    {
        return Err(tr!(
            "Настройки содержат неподдерживаемые значения",
            "Settings contain unsupported values"
        ));
    }
    if let Some(language) = crate::i18n::Language::from_tag(&settings.language) {
        crate::i18n::set(language);
    }
    tokio::task::spawn_blocking(move || save_settings_sync_for_app(&app, &settings))
        .await
        .map_err(|error| {
            tr!(
                "Ошибка сохранения настроек: {error}",
                "Could not save settings: {error}"
            )
        })?
}

fn save_settings_sync_for_app(
    app: &tauri::AppHandle,
    settings: &crate::signer::AppSettings,
) -> Result<(), String> {
    #[cfg(windows)]
    {
        let _ = app;
        save_settings_sync(settings)
    }
    #[cfg(not(windows))]
    {
        let path = settings_path(app)?;
        save_settings_file(&path, settings)
    }
}

#[cfg(windows)]
fn save_settings_sync(settings: &crate::signer::AppSettings) -> Result<(), String> {
    use winreg::{enums::HKEY_CURRENT_USER, RegKey};

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu
        .create_subkey("Software\\CryptoLite")
        .map_err(|error| {
            tr!(
                "Не удалось создать HKCU\\Software\\CryptoLite: {error}",
                "Could not create HKCU\\Software\\CryptoLite: {error}"
            )
        })?;
    let json = serde_json::to_string(settings).map_err(|error| {
        tr!(
            "Не удалось сериализовать настройки: {error}",
            "Could not serialize settings: {error}"
        )
    })?;
    key.set_value("Settings", &json).map_err(|error| {
        tr!(
            "Не удалось сохранить настройки в HKCU: {error}",
            "Could not save settings to HKCU: {error}"
        )
    })
}

#[cfg(not(windows))]
fn save_settings_file(
    path: &std::path::Path,
    settings: &crate::signer::AppSettings,
) -> Result<(), String> {
    {
        let directory = path.parent().ok_or_else(|| {
            tr!(
                "Не удалось определить каталог настроек",
                "Could not determine the settings directory"
            )
        })?;
        std::fs::create_dir_all(directory).map_err(|error| {
            tr!(
                "Не удалось создать каталог настроек: {error}",
                "Could not create the settings directory: {error}"
            )
        })?;
        let contents = serde_json::to_vec_pretty(settings).map_err(|error| {
            tr!(
                "Не удалось сериализовать настройки: {error}",
                "Could not serialize settings: {error}"
            )
        })?;
        let temporary_path = path.with_extension("json.tmp");
        std::fs::write(&temporary_path, contents).map_err(|error| {
            tr!(
                "Не удалось записать настройки: {error}",
                "Could not write settings: {error}"
            )
        })?;
        match std::fs::rename(&temporary_path, &path) {
            Ok(()) => Ok(()),
            Err(first_error) if path.exists() => {
                // Windows rename does not replace an existing destination.
                std::fs::remove_file(&path).map_err(|error| {
                    let _ = std::fs::remove_file(&temporary_path);
                    tr!(
                        "Не удалось заменить файл настроек {}: {error}",
                        "Could not replace the settings file {}: {error}",
                        path.display()
                    )
                })?;
                std::fs::rename(&temporary_path, &path).map_err(|error| {
                    let _ = std::fs::remove_file(&temporary_path);
                    tr!(
                        "Не удалось сохранить {} (предыдущая ошибка: {first_error}): {error}",
                        "Could not save {} (previous error: {first_error}): {error}",
                        path.display()
                    )
                })
            }
            Err(error) => {
                let _ = std::fs::remove_file(&temporary_path);
                Err(tr!(
                    "Не удалось сохранить {}: {error}",
                    "Could not save {}: {error}",
                    path.display()
                ))
            }
        }
    }
}

#[tauri::command]
pub async fn csp_status() -> CspStatus {
    tokio::task::spawn_blocking(|| crate::signer::native::NativeSigner.csp_status())
        .await
        .unwrap_or_else(|error| {
            CspStatus::unavailable(tr!(
                "Ошибка запуска проверки CSP: {error}",
                "Could not start the CSP check: {error}"
            ))
        })
}

#[tauri::command]
pub async fn list_certs() -> Result<Vec<CertInfo>, String> {
    tokio::task::spawn_blocking(|| crate::signer::native::NativeSigner.list_certs())
        .await
        .map_err(|error| {
            tr!(
                "Не удалось запустить перечисление сертификатов: {error}",
                "Could not start certificate enumeration: {error}"
            )
        })?
        .map_err(|error: SignerError| error.to_string())
}

#[tauri::command]
pub async fn sign_file(request: SignRequest) -> Result<SignResult, String> {
    tokio::task::spawn_blocking(move || crate::signer::native::NativeSigner.sign_file(request))
        .await
        .map_err(|error| {
            tr!(
                "Не удалось запустить подписание: {error}",
                "Could not start signing: {error}"
            )
        })?
        .map_err(|error: SignerError| error.to_string())
}

#[tauri::command]
pub async fn sign_files(requests: Vec<SignRequest>) -> Result<Vec<SignBatchItemResult>, String> {
    tokio::task::spawn_blocking(move || {
        requests
            .into_iter()
            .map(|request| {
                let input_path = request.input_path.clone();
                let output_path = request.output_path.clone();
                match crate::signer::native::NativeSigner.sign_file(request) {
                    Ok(result) => SignBatchItemResult {
                        input_path,
                        output_path: result.output_path,
                        success: true,
                        error: None,
                    },
                    Err(error) => SignBatchItemResult {
                        input_path,
                        output_path,
                        success: false,
                        error: Some(error.to_string()),
                    },
                }
            })
            .collect()
    })
    .await
    .map_err(|error| {
        tr!(
            "Не удалось запустить пакетное подписание: {error}",
            "Could not start batch signing: {error}"
        )
    })
}

#[tauri::command]
pub async fn remove_temp_pdf(path: String) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let candidate = std::path::PathBuf::from(&path);
        let temp = std::env::temp_dir();
        let name = candidate
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        // Удаляется только промежуточный файл партии подписи PDF из системного temp.
        let parent = candidate.parent().and_then(|p| p.canonicalize().ok());
        let temp = std::env::temp_dir().canonicalize().ok();
        if parent.is_some() && parent == temp && name.contains(".signing-") {
            std::fs::remove_file(&candidate).map_err(|error| {
                tr!(
                    "Не удалось удалить промежуточный файл: {error}",
                    "Could not delete the temporary file: {error}"
                )
            })
        } else {
            Err(tr!(
                "Удаление разрешено только для промежуточных файлов подписи",
                "Only temporary PDF signing files may be deleted"
            ))
        }
    })
    .await
    .map_err(|error| {
        tr!(
            "Не удалось запустить удаление: {error}",
            "Could not start deletion: {error}"
        )
    })?
}

/// Оставляет только пути к файлам: папки и недоступные пути отбрасываются.
#[tauri::command]
pub async fn filter_file_paths(paths: Vec<String>) -> Result<Vec<String>, String> {
    tokio::task::spawn_blocking(move || {
        paths
            .into_iter()
            .filter(|path| std::path::Path::new(path).is_file())
            .collect::<Vec<String>>()
    })
    .await
    .map_err(|error| {
        tr!(
            "Не удалось проверить пути к файлам: {error}",
            "Could not check file paths: {error}"
        )
    })
}

#[tauri::command]
pub async fn sign_pdf(request: crate::signer::PdfSignRequest) -> Result<SignResult, String> {
    tokio::task::spawn_blocking(move || {
        crate::signer::pades::sign_document(
            &request.input_path,
            &request.output_path,
            &request.certificate_id,
            &request.stamp,
            &request.page_rotations,
        )
    })
    .await
    .map_err(|error| {
        tr!(
            "Не удалось запустить подпись PDF: {error}",
            "Could not start PDF signing: {error}"
        )
    })?
    .map_err(|error: SignerError| error.to_string())
}

#[tauri::command]
pub async fn sign_pdf_prepare(
    request: crate::signer::PdfSignPrepareRequest,
) -> Result<crate::signer::PdfSignPrepareResult, String> {
    tokio::task::spawn_blocking(move || {
        let prepared = crate::signer::pades::prepare(
            &request.input_path,
            &request.certificate_id,
            &request.stamp,
            &request.page_rotations,
        )?;
        crate::signer::pdf_layer::export_prepared(prepared)
    })
    .await
    .map_err(|error| {
        tr!(
            "Не удалось запустить подготовку поля подписи: {error}",
            "Could not start signature field preparation: {error}"
        )
    })?
    .map_err(|error: SignerError| error.to_string())
}

#[tauri::command]
pub async fn sign_pdf_finish(
    request: crate::signer::PdfSignFinishRequest,
) -> Result<SignResult, String> {
    tokio::task::spawn_blocking(move || {
        let prepared = crate::signer::pades::restore(&request.prepared_path)?;
        crate::signer::pades::finish_signed(&prepared, &request.payload, &request.output_path)
    })
    .await
    .map_err(|error| {
        tr!(
            "Не удалось запустить встраивание подписи: {error}",
            "Could not start signature embedding: {error}"
        )
    })?
    .map_err(|error: SignerError| error.to_string())
}

#[tauri::command]
pub async fn verify_signature(request: VerifyRequest) -> Result<VerifyResult, String> {
    tokio::task::spawn_blocking(move || crate::signer::native::verify_signature(request))
        .await
        .map_err(|error| {
            tr!(
                "Не удалось запустить проверку подписи: {error}",
                "Could not start signature verification: {error}"
            )
        })?
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn verify_pdf(
    request: crate::signer::PdfVerifyRequest,
) -> Result<crate::signer::PdfVerifyResult, String> {
    tokio::task::spawn_blocking(move || {
        crate::signer::pades::verify_document(&request.path, request.check_crl)
    })
    .await
    .map_err(|error| {
        tr!(
            "Не удалось запустить проверку подписей PDF: {error}",
            "Could not start PDF signature verification: {error}"
        )
    })?
    .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn encrypt_file(request: EncryptRequest) -> Result<EncryptResult, String> {
    tokio::task::spawn_blocking(move || crate::signer::native::encrypt_file(request))
        .await
        .map_err(|error| {
            tr!(
                "Не удалось запустить шифрование: {error}",
                "Could not start encryption: {error}"
            )
        })?
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn decrypt_file(request: DecryptRequest) -> Result<DecryptResult, String> {
    tokio::task::spawn_blocking(move || crate::signer::native::decrypt_file(request))
        .await
        .map_err(|error| {
            tr!(
                "Не удалось запустить расшифрование: {error}",
                "Could not start decryption: {error}"
            )
        })?
        .map_err(|error| error.to_string())
}
