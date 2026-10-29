#![deny(unsafe_code)]
use crate::signer::{
    CspStatus, DecryptRequest, DecryptResult, EncryptRequest, EncryptResult, SignRequest,
    SignResult, Signer, SignerError, VerifyRequest, VerifyResult,
};

pub fn verify_signature(request: VerifyRequest) -> Result<VerifyResult, SignerError> {
    #[cfg(target_os = "windows")]
    {
        return super::csp_native::windows::verify_signature(request);
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = request;
        Err(SignerError::Signing(
            "Проверка CMS пока реализована только для Windows".to_owned(),
        ))
    }
}

pub fn encrypt_file(request: EncryptRequest) -> Result<EncryptResult, SignerError> {
    #[cfg(target_os = "windows")]
    {
        return super::csp_native::windows::encrypt_file(request);
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = request;
        Err(SignerError::Encryption(
            "Шифрование пока реализовано только для Windows".to_owned(),
        ))
    }
}

pub fn decrypt_file(request: DecryptRequest) -> Result<DecryptResult, SignerError> {
    #[cfg(target_os = "windows")]
    {
        return super::csp_native::windows::decrypt_file(request);
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = request;
        Err(SignerError::Decryption(
            "Расшифрование пока реализовано только для Windows".to_owned(),
        ))
    }
}

pub struct NativeSigner;

impl Signer for NativeSigner {
    fn csp_status(&self) -> CspStatus {
        #[cfg(target_os = "windows")]
        {
            return super::csp_native::windows::probe();
        }

        #[cfg(target_os = "linux")]
        {
            let mut directories = vec![
                std::path::PathBuf::from("/opt/cprocsp/lib/amd64"),
                std::path::PathBuf::from("/usr/lib64"),
                std::path::PathBuf::from("/usr/lib/x86_64-linux-gnu"),
            ];
            if let Some(directory) = std::env::var_os("CPSIGNER_CSP_LIB_DIR") {
                directories.insert(0, std::path::PathBuf::from(directory));
            }
            let names = [
                "libcapi20.so",
                "libcapi20.so.4",
                "libcapi10.so",
                "libcades.so",
                "libcades.so.2",
            ];
            let found = directories
                .iter()
                .flat_map(|directory| names.iter().map(move |name| directory.join(name)))
                .filter(|path| path.is_file())
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>();
            if found.is_empty() {
                CspStatus::unavailable("Библиотеки КриптоПро CSP не найдены. Для проверки нестандартного каталога задайте CPSIGNER_CSP_LIB_DIR.")
            } else {
                CspStatus {
                    available: true,
                    cades_available: found.iter().any(|path| path.contains("cades")),
                    signing_available: false,
                    provider_type: None,
                    version: None,
                    message: format!(
                        "Обнаружены библиотеки, но интеграция API ещё не подключена: {}",
                        found.join(", ")
                    ),
                }
            }
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            CspStatus::unavailable("Эта операционная система не поддерживается.")
        }
    }

    fn list_certs(&self) -> Result<Vec<crate::signer::CertInfo>, crate::signer::SignerError> {
        #[cfg(target_os = "windows")]
        {
            super::csp_native::windows::list_certificates()
        }

        #[cfg(target_os = "linux")]
        {
            Err(crate::signer::SignerError::CertificateEnumerationUnsupported)
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            Err(crate::signer::SignerError::CertificateEnumerationUnsupported)
        }
    }

    fn sign_file(&self, request: SignRequest) -> Result<SignResult, SignerError> {
        #[cfg(target_os = "windows")]
        {
            if request.standard == "cades-bes" {
                return super::csp_native::cadescom::sign_file(request);
            }
            super::csp_native::windows::sign_file(request)
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = request;
            Err(SignerError::Signing(
                "CMS-подписание пока реализовано только для Windows".to_owned(),
            ))
        }
    }
}
