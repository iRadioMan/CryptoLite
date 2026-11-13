#![deny(unsafe_code)]
use crate::tr;
use std::fmt;

#[derive(Debug)]
pub enum SignerError {
    CspNotFound(String),
    MissingLibrary(String),
    LoadFailure { library: String, details: String },
    CertificateStore(String),
    Signing(String),
    Pdf(String),
    Encryption(String),
    Decryption(String),
    CertificateEnumerationUnsupported,
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CspNotFound(detail) => write!(
                f,
                "{}",
                tr!(
                    "КриптоПро CSP не найден: {detail}",
                    "CryptoPro CSP not found: {detail}"
                )
            ),
            Self::MissingLibrary(library) => write!(
                f,
                "{}",
                tr!(
                    "В системе не найдена библиотека {library}",
                    "Library not found on the system: {library}"
                )
            ),
            Self::LoadFailure { library, details } => write!(
                f,
                "{}",
                tr!(
                    "Не удалось загрузить библиотеку {library}: {details}",
                    "Could not load library {library}: {details}"
                )
            ),
            Self::CertificateStore(detail) => write!(
                f,
                "{}",
                tr!(
                    "Не удалось прочитать личное хранилище сертификатов: {detail}",
                    "Could not read the personal certificate store: {detail}"
                )
            ),
            Self::Signing(detail) => write!(
                f,
                "{}",
                tr!(
                    "Не удалось подписать файл: {detail}",
                    "Could not sign the file: {detail}"
                )
            ),
            Self::Pdf(detail) => write!(
                f,
                "{}",
                tr!(
                    "Не удалось подписать PDF: {detail}",
                    "Could not sign the PDF: {detail}"
                )
            ),
            Self::Encryption(detail) => write!(
                f,
                "{}",
                tr!(
                    "Не удалось зашифровать файл: {detail}",
                    "Could not encrypt the file: {detail}"
                )
            ),
            Self::Decryption(detail) => write!(
                f,
                "{}",
                tr!(
                    "Не удалось расшифровать файл: {detail}",
                    "Could not decrypt the file: {detail}"
                )
            ),
            Self::CertificateEnumerationUnsupported => write!(
                f,
                "{}",
                tr!(
                    "Перечисление сертификатов пока не поддерживается на этой платформе",
                    "Certificate enumeration is not supported on this platform yet"
                )
            ),
        }
    }
}

impl std::error::Error for SignerError {}
