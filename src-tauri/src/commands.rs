use crate::signer::{
    CertInfo, CspStatus, SignBatchItemResult, SignRequest, SignResult, Signer, SignerError,
    VerifyRequest, VerifyResult,
};
use std::path::PathBuf;
use tauri::Manager;

fn settings_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|directory| directory.join("settings.json"))
        .map_err(|error| format!("Не удалось определить каталог настроек: {error}"))
}

#[tauri::command]
pub async fn load_settings(app: tauri::AppHandle) -> Result<crate::signer::AppSettings, String> {
    tokio::task::spawn_blocking(move || load_settings_sync(&app))
        .await
        .map_err(|error| format!("Ошибка загрузки настроек: {error}"))?
}

#[cfg(windows)]
fn load_settings_sync(app: &tauri::AppHandle) -> Result<crate::signer::AppSettings, String> {
    use winreg::{enums::HKEY_CURRENT_USER, RegKey};

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    match hkcu.open_subkey("Software\\CryptoLite") {
        Ok(key) => match key.get_value::<String, _>("Settings") {
            Ok(json) => serde_json::from_str(&json)
                .map_err(|error| format!("Не удалось прочитать настройки из HKCU: {error}")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                migrate_legacy_settings(app)
            }
            Err(error) => Err(format!("Не удалось прочитать настройки из HKCU: {error}")),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => migrate_legacy_settings(app),
        Err(error) => Err(format!(
            "Не удалось открыть HKCU\\Software\\CryptoLite: {error}"
        )),
    }
}

#[cfg(windows)]
fn migrate_legacy_settings(app: &tauri::AppHandle) -> Result<crate::signer::AppSettings, String> {
    let path = settings_path(app)?;
    match std::fs::read(&path) {
        Ok(contents) => {
            let settings: crate::signer::AppSettings = serde_json::from_slice(&contents)
                .map_err(|error| format!("Не удалось прочитать {}: {error}", path.display()))?;
            save_settings_sync(&settings)?;
            Ok(settings)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(crate::signer::AppSettings::default())
        }
        Err(error) => Err(format!("Не удалось прочитать {}: {error}", path.display())),
    }
}

#[cfg(not(windows))]
fn load_settings_sync(app: &tauri::AppHandle) -> Result<crate::signer::AppSettings, String> {
    let path = settings_path(app)?;
    match std::fs::read(&path) {
        Ok(contents) => serde_json::from_slice(&contents)
            .map_err(|error| format!("Не удалось прочитать {}: {error}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(crate::signer::AppSettings::default())
        }
        Err(error) => Err(format!("Не удалось прочитать {}: {error}", path.display())),
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
    {
        return Err("Настройки содержат неподдерживаемые значения".to_owned());
    }
    tokio::task::spawn_blocking(move || save_settings_sync_for_app(&app, &settings))
        .await
        .map_err(|error| format!("Ошибка сохранения настроек: {error}"))?
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
        .map_err(|error| format!("Не удалось создать HKCU\\Software\\CryptoLite: {error}"))?;
    let json = serde_json::to_string(settings)
        .map_err(|error| format!("Не удалось сериализовать настройки: {error}"))?;
    key.set_value("Settings", &json)
        .map_err(|error| format!("Не удалось сохранить настройки в HKCU: {error}"))
}

#[cfg(not(windows))]
fn save_settings_file(
    path: &std::path::Path,
    settings: &crate::signer::AppSettings,
) -> Result<(), String> {
    {
        let directory = path
            .parent()
            .ok_or_else(|| "Не удалось определить каталог настроек".to_owned())?;
        std::fs::create_dir_all(directory)
            .map_err(|error| format!("Не удалось создать каталог настроек: {error}"))?;
        let contents = serde_json::to_vec_pretty(settings)
            .map_err(|error| format!("Не удалось сериализовать настройки: {error}"))?;
        let temporary_path = path.with_extension("json.tmp");
        std::fs::write(&temporary_path, contents)
            .map_err(|error| format!("Не удалось записать настройки: {error}"))?;
        match std::fs::rename(&temporary_path, &path) {
            Ok(()) => Ok(()),
            Err(first_error) if path.exists() => {
                // Windows rename does not replace an existing destination.
                std::fs::remove_file(&path).map_err(|error| {
                    let _ = std::fs::remove_file(&temporary_path);
                    format!(
                        "Не удалось заменить файл настроек {}: {error}",
                        path.display()
                    )
                })?;
                std::fs::rename(&temporary_path, &path).map_err(|error| {
                    let _ = std::fs::remove_file(&temporary_path);
                    format!(
                        "Не удалось сохранить {} (предыдущая ошибка: {first_error}): {error}",
                        path.display()
                    )
                })
            }
            Err(error) => {
                let _ = std::fs::remove_file(&temporary_path);
                Err(format!("Не удалось сохранить {}: {error}", path.display()))
            }
        }
    }
}

#[tauri::command]
pub async fn csp_status() -> CspStatus {
    tokio::task::spawn_blocking(|| crate::signer::native::NativeSigner.csp_status())
        .await
        .unwrap_or_else(|error| {
            CspStatus::unavailable(format!("Ошибка запуска проверки CSP: {error}"))
        })
}

#[tauri::command]
pub async fn list_certs() -> Result<Vec<CertInfo>, String> {
    tokio::task::spawn_blocking(|| crate::signer::native::NativeSigner.list_certs())
        .await
        .map_err(|error| format!("Не удалось запустить перечисление сертификатов: {error}"))?
        .map_err(|error: SignerError| error.to_string())
}

#[tauri::command]
pub async fn sign_file(request: SignRequest) -> Result<SignResult, String> {
    tokio::task::spawn_blocking(move || crate::signer::native::NativeSigner.sign_file(request))
        .await
        .map_err(|error| format!("Не удалось запустить подписание: {error}"))?
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
                    Ok(_) => SignBatchItemResult {
                        input_path,
                        output_path,
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
    .map_err(|error| format!("Не удалось запустить пакетное подписание: {error}"))
}

#[tauri::command]
pub async fn verify_signature(request: VerifyRequest) -> Result<VerifyResult, String> {
    tokio::task::spawn_blocking(move || crate::signer::native::verify_signature(request))
        .await
        .map_err(|error| format!("Не удалось запустить проверку подписи: {error}"))?
        .map_err(|error| error.to_string())
}
