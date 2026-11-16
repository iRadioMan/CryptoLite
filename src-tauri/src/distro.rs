#![deny(unsafe_code)]
//! Определение дистрибутива: приложение поддерживает Astra Linux Special Edition 1.8 и выше.
//!
//! На Linux читаются `/etc/astra_version` и `/etc/os-release`; каталог можно подменить
//! переменной `CRYPTOLITE_DISTRO_DIR` — так проверяется предупреждение о неподдерживаемой
//! версии без изменения системы.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentInfo {
    /// `linux` или `windows`: интерфейс подписывает хранилище сертификатов по этой строке.
    pub platform: String,
    pub distro_supported: bool,
    pub distro_name: String,
    pub distro_version: String,
}

/// Сведения о дистрибутиве для предупреждения на старте.
#[tauri::command]
pub fn environment_info() -> EnvironmentInfo {
    #[cfg(target_os = "linux")]
    {
        let directory = std::env::var_os("CRYPTOLITE_DISTRO_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("/etc"));
        let astra_version = std::fs::read_to_string(directory.join("astra_version")).ok();
        let os_release = std::fs::read_to_string(directory.join("os-release")).ok();
        let (distro_supported, distro_name, distro_version) =
            evaluate(astra_version.as_deref(), os_release.as_deref());
        EnvironmentInfo {
            platform: "linux".to_owned(),
            distro_supported,
            distro_name,
            distro_version,
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        EnvironmentInfo {
            platform: "windows".to_owned(),
            distro_supported: true,
            distro_name: "Windows".to_owned(),
            distro_version: String::new(),
        }
    }
}

/// Поддерживается ли дистрибутив, как он называется и какая у него версия.
///
/// `astra_version` (например `1.8.7`) однозначно указывает на Astra Linux;
/// иначе разбирается `os-release`, и поддержка требует `ID=astra`.
fn evaluate(astra_version: Option<&str>, os_release: Option<&str>) -> (bool, String, String) {
    if let Some(version) = astra_version.map(str::trim).filter(|value| !value.is_empty()) {
        return (
            version_at_least_1_8(version),
            "Astra Linux Special Edition".to_owned(),
            version.to_owned(),
        );
    }
    if let Some(contents) = os_release {
        let fields = parse_os_release(contents);
        let id = fields.get("ID").cloned().unwrap_or_default();
        let version = fields.get("VERSION_ID").cloned().unwrap_or_default();
        // `NAME` не содержит версии, поэтому имя и версия не дублируются при показе.
        let name = fields
            .get("NAME")
            .or_else(|| fields.get("PRETTY_NAME"))
            .cloned()
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "Linux".to_owned());
        return (
            id.eq_ignore_ascii_case("astra") && version_at_least_1_8(&version),
            name,
            version,
        );
    }
    (false, "Linux".to_owned(), String::new())
}

/// Пары `KEY=VALUE` из `os-release`; кавычки снимаются, комментарии пропускаются.
fn parse_os_release(contents: &str) -> std::collections::HashMap<String, String> {
    let mut fields = std::collections::HashMap::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .or_else(|| {
                value
                    .strip_prefix('\'')
                    .and_then(|rest| rest.strip_suffix('\''))
            })
            .unwrap_or(value);
        fields.insert(key.trim().to_owned(), value.to_owned());
    }
    fields
}

/// Версия не ниже 1.8: сравниваются первые два числовых компонента.
fn version_at_least_1_8(value: &str) -> bool {
    let mut numbers = Vec::new();
    for part in value.split(|character: char| !character.is_ascii_digit()) {
        if part.is_empty() {
            continue;
        }
        let Ok(number) = part.parse::<u32>() else {
            return false;
        };
        numbers.push(number);
        if numbers.len() == 2 {
            break;
        }
    }
    match numbers.as_slice() {
        [major] => *major > 1,
        [major, minor] => *major > 1 || (*major == 1 && *minor >= 8),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn astra_version_file_marks_supported_versions() {
        let (supported, name, version) = evaluate(Some("1.8.7"), None);
        assert!(supported);
        assert_eq!(name, "Astra Linux Special Edition");
        assert_eq!(version, "1.8.7");
        assert!(evaluate(Some("2.0.0"), None).0);
        assert!(evaluate(Some("1.8_x86-64"), None).0);
    }

    #[test]
    fn older_astra_is_not_supported() {
        let (supported, _, version) = evaluate(Some("1.7.5"), None);
        assert!(!supported);
        assert_eq!(version, "1.7.5");
    }

    #[test]
    fn os_release_requires_astra_identifier() {
        let astra = "NAME=\"Astra Linux Special Edition\"\nID=astra\nVERSION_ID=\"1.8_x86-64\"\nPRETTY_NAME=\"Astra Linux Special Edition 1.8\"\n";
        let (supported, name, version) = evaluate(None, Some(astra));
        assert!(supported);
        assert_eq!(name, "Astra Linux Special Edition");
        assert_eq!(version, "1.8_x86-64");

        let ubuntu = "PRETTY_NAME=\"Ubuntu 24.04\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n";
        let (supported, name, version) = evaluate(None, Some(ubuntu));
        assert!(!supported);
        assert_eq!(name, "Ubuntu 24.04");
        assert_eq!(version, "24.04");

        let named = "NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n";
        assert_eq!(evaluate(None, Some(named)).1, "Ubuntu");
    }

    #[test]
    fn missing_files_mean_unsupported_linux() {
        assert_eq!(evaluate(None, None), (false, "Linux".to_owned(), String::new()));
    }
}
