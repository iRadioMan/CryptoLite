#![deny(unsafe_code)]
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignerError {
    #[error("КриптоПро CSP не найден: {0}")]
    CspNotFound(String),
    #[error("В системе не найдена библиотека {0}")]
    MissingLibrary(String),
    #[error("Не удалось загрузить библиотеку {library}: {details}")]
    LoadFailure { library: String, details: String },
    #[error("Не удалось прочитать личное хранилище сертификатов Windows: {0}")]
    CertificateStore(String),
    #[error("Не удалось подписать файл: {0}")]
    Signing(String),
    #[error("Перечисление сертификатов пока не поддерживается на этой платформе")]
    CertificateEnumerationUnsupported,
}
