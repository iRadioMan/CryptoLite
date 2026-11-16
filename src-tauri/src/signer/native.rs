#![deny(unsafe_code)]
use crate::signer::{
    CspStatus, DecryptRequest, DecryptResult, EncryptRequest, EncryptResult, SignRequest,
    SignResult, Signer, SignerError, VerifyRequest, VerifyResult,
};
#[cfg(not(any(target_os = "windows", target_os = "linux")))]
use crate::tr;

pub fn verify_signature(request: VerifyRequest) -> Result<VerifyResult, SignerError> {
    #[cfg(target_os = "windows")]
    {
        return super::csp_native::windows::verify_signature(request);
    }
    #[cfg(target_os = "linux")]
    {
        return super::csp_native::linux::verify_signature(request);
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = request;
        Err(SignerError::Signing(tr!(
            "Проверка CMS пока реализована только для Windows и Linux",
            "CMS verification is currently implemented only for Windows and Linux"
        )))
    }
}

/// Проверка CMS по байтам: используется встроенными подписями PDF.
///
/// Возвращает подписантов и номер подписанта, не прошедшего проверку, с кодом ошибки CSP.
pub fn verify_cms_signers(
    signature: &[u8],
    content: Option<&[u8]>,
    detached: bool,
    check_crl: bool,
) -> Result<(Vec<crate::signer::VerifySignerInfo>, Option<(u32, u32)>), SignerError> {
    #[cfg(target_os = "windows")]
    {
        return super::csp_native::windows::verify_cms_signers(
            signature, content, detached, check_crl,
        );
    }
    #[cfg(target_os = "linux")]
    {
        return super::csp_native::linux::verify_cms_signers(
            signature, content, detached, check_crl,
        );
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = (signature, content, detached, check_crl);
        Err(SignerError::Signing(tr!(
            "Проверка CMS пока реализована только для Windows и Linux",
            "CMS verification is currently implemented only for Windows and Linux"
        )))
    }
}

pub fn encrypt_file(request: EncryptRequest) -> Result<EncryptResult, SignerError> {
    #[cfg(target_os = "windows")]
    {
        return super::csp_native::windows::encrypt_file(request);
    }
    #[cfg(target_os = "linux")]
    {
        return super::csp_native::linux::encrypt_file(request);
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = request;
        Err(SignerError::Encryption(tr!(
            "Шифрование пока реализовано только для Windows и Linux",
            "Encryption is currently implemented only for Windows and Linux"
        )))
    }
}

pub fn decrypt_file(request: DecryptRequest) -> Result<DecryptResult, SignerError> {
    #[cfg(target_os = "windows")]
    {
        return super::csp_native::windows::decrypt_file(request);
    }
    #[cfg(target_os = "linux")]
    {
        return super::csp_native::linux::decrypt_file(request);
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = request;
        Err(SignerError::Decryption(tr!(
            "Расшифрование пока реализовано только для Windows и Linux",
            "Decryption is currently implemented only for Windows and Linux"
        )))
    }
}

/// Физические токены (Рутокен), обнаруженные CryptoPro CSP.
///
/// Ошибка обнаружения не пробрасывается в интерфейс: счётчик в «О программе»
/// показывает 0, а причина пишется в лог.
pub fn list_tokens() -> Vec<crate::signer::TokenInfo> {
    #[cfg(target_os = "windows")]
    {
        return super::csp_native::windows::list_tokens();
    }
    #[cfg(target_os = "linux")]
    {
        return super::csp_native::linux::list_tokens();
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Vec::new()
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
            return super::csp_native::linux::probe();
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            CspStatus::unavailable(tr!(
                "Эта операционная система не поддерживается.",
                "This operating system is not supported."
            ))
        }
    }

    fn list_certs(&self) -> Result<Vec<crate::signer::CertInfo>, crate::signer::SignerError> {
        #[cfg(target_os = "windows")]
        {
            super::csp_native::windows::list_certificates()
        }

        #[cfg(target_os = "linux")]
        {
            super::csp_native::linux::list_certificates()
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            Err(crate::signer::SignerError::CertificateEnumerationUnsupported)
        }
    }

    fn sign_file(&self, request: SignRequest) -> Result<SignResult, SignerError> {
        #[cfg(target_os = "windows")]
        {
            if matches!(request.standard.as_str(), "cades-bes" | "cades-t") {
                return super::csp_native::cadescom::sign_file(request);
            }
            super::csp_native::windows::sign_file(request)
        }

        #[cfg(target_os = "linux")]
        {
            if matches!(request.standard.as_str(), "cades-bes" | "cades-t") {
                return super::csp_native::linux::cryptcp::sign_file(request);
            }
            super::csp_native::linux::sign_file(request)
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            let _ = request;
            Err(SignerError::Signing(tr!(
                "CMS-подписание пока реализовано только для Windows и Linux",
                "CMS signing is currently implemented only for Windows and Linux"
            )))
        }
    }
}
