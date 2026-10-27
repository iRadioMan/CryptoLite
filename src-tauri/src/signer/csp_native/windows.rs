#![deny(unsafe_code)]

#[allow(unsafe_code)]
mod ffi {
    use std::ffi::CStr;
    use std::io::Write;
    use std::ptr;
    use windows_sys::Win32::Security::Cryptography::{
        CryptAcquireContextW, CryptGetProvParam, CryptReleaseContext, CRYPT_VERIFYCONTEXT,
    };

    pub(super) struct ProviderContext(usize);

    pub(super) fn acquire_provider(provider_type: u32) -> Result<ProviderContext, u32> {
        let mut handle = 0usize;
        let acquired = unsafe {
            CryptAcquireContextW(
                &mut handle,
                ptr::null(),
                ptr::null(),
                provider_type,
                CRYPT_VERIFYCONTEXT,
            )
        };
        if acquired == 0 {
            Err(unsafe { windows_sys::Win32::Foundation::GetLastError() })
        } else {
            Ok(ProviderContext(handle))
        }
    }

    pub(super) fn provider_version(provider: &ProviderContext) -> Option<String> {
        let mut version = 0u32;
        let mut length = std::mem::size_of::<u32>() as u32;
        let success = unsafe {
            CryptGetProvParam(
                provider.0,
                5, // PP_VERSION
                &mut version as *mut u32 as *mut u8,
                &mut length,
                0,
            )
        };
        (success != 0).then(|| format!("{}.{}", (version >> 8) & 0xff, version & 0xff))
    }

    impl Drop for ProviderContext {
        fn drop(&mut self) {
            unsafe {
                CryptReleaseContext(self.0, 0);
            }
        }
    }

    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Security::Cryptography::{
        CertCloseStore, CertEnumCertificatesInStore, CertFreeCertificateChain,
        CertFreeCertificateContext, CertGetCertificateChain, CertGetCertificateContextProperty,
        CertGetNameStringW, CertOpenSystemStoreW, CertVerifyCertificateChainPolicy,
        CryptSignMessage, CryptVerifyDetachedMessageSignature, CryptVerifyMessageSignature,
        CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, CERT_CHAIN_CONTEXT, CERT_CHAIN_PARA,
        CERT_CHAIN_POLICY_BASE, CERT_CHAIN_POLICY_PARA, CERT_CHAIN_POLICY_STATUS, CERT_CONTEXT,
        CERT_KEY_PROV_INFO_PROP_ID, CERT_NAME_ISSUER_FLAG, CERT_NAME_SIMPLE_DISPLAY_TYPE,
        CRYPT_ALGORITHM_IDENTIFIER, CRYPT_SIGN_MESSAGE_PARA, CRYPT_VERIFY_MESSAGE_PARA, HCERTSTORE,
        PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    };

    pub(super) struct CertificateStore(HCERTSTORE);

    impl Drop for CertificateStore {
        fn drop(&mut self) {
            unsafe {
                CertCloseStore(self.0, 0);
            }
        }
    }

    struct CertificateContext(*const CERT_CONTEXT);

    impl Drop for CertificateContext {
        fn drop(&mut self) {
            unsafe { CertFreeCertificateContext(self.0) };
        }
    }

    impl CertificateContext {
        fn as_ptr(&self) -> *const CERT_CONTEXT {
            self.0
        }
    }

    unsafe fn open_personal_store() -> Option<CertificateStore> {
        let name: Vec<u16> = "MY\0".encode_utf16().collect();
        let store = CertOpenSystemStoreW(0, name.as_ptr());
        (!store.is_null()).then_some(CertificateStore(store))
    }

    unsafe fn next_certificate(
        store: &CertificateStore,
        previous: *const CERT_CONTEXT,
    ) -> *mut CERT_CONTEXT {
        CertEnumCertificatesInStore(store.0, previous)
    }

    unsafe fn read_certificate(context: *const CERT_CONTEXT) -> Option<crate::signer::CertInfo> {
        let context_ref = context.as_ref()?;
        let info = context_ref.pCertInfo.as_ref()?;
        let subject = certificate_name(context, 0);
        if subject.is_empty() {
            return None;
        }
        let issuer = certificate_name(context, CERT_NAME_ISSUER_FLAG);
        let expires_at =
            super::filetime_to_date(info.NotAfter.dwHighDateTime, info.NotAfter.dwLowDateTime);
        let expired =
            filetime_is_expired(info.NotAfter.dwHighDateTime, info.NotAfter.dwLowDateTime);
        let mut property_len = 0u32;
        let has_private_key = CertGetCertificateContextProperty(
            context,
            CERT_KEY_PROV_INFO_PROP_ID,
            ptr::null_mut(),
            &mut property_len,
        ) != 0;
        let serial = &info.SerialNumber;
        let serial_id = if serial.pbData.is_null() || serial.cbData == 0 {
            format!("fallback:{subject}:{expires_at}")
        } else {
            std::slice::from_raw_parts(serial.pbData, serial.cbData as usize)
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<String>()
        };
        let id = format!("{issuer}:{serial_id}");
        Some(crate::signer::CertInfo {
            id,
            subject,
            issuer,
            expires_at,
            expired,
            has_private_key,
            source: "Windows · Личное хранилище".to_owned(),
        })
    }

    fn filetime_is_expired(high: u32, low: u32) -> bool {
        const FILETIME_UNIX_EPOCH_OFFSET_SECS: u128 = 11_644_473_600;
        const TICKS_PER_SECOND: u128 = 10_000_000;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let now_filetime = (now.as_secs() as u128 + FILETIME_UNIX_EPOCH_OFFSET_SECS)
            * TICKS_PER_SECOND
            + (now.subsec_nanos() / 100) as u128;
        let expires_filetime = ((high as u128) << 32) | low as u128;
        expires_filetime <= now_filetime
    }

    pub(super) fn list_personal_certificates(
    ) -> Result<Vec<crate::signer::CertInfo>, crate::signer::SignerError> {
        let store = unsafe { open_personal_store() }.ok_or_else(|| {
            let code = unsafe { GetLastError() };
            crate::signer::SignerError::CertificateStore(format!("код Windows 0x{code:08X}"))
        })?;
        let mut certificates = Vec::new();
        let mut previous = ptr::null();
        loop {
            // CertEnumCertificatesInStore frees the previous context passed to it.
            let current = unsafe { next_certificate(&store, previous) };
            if current.is_null() {
                break;
            }
            if let Some(certificate) = unsafe { read_certificate(current) } {
                certificates.push(certificate);
            }
            previous = current;
        }
        Ok(certificates)
    }

    pub(super) fn sign_cms(
        request: crate::signer::SignRequest,
    ) -> Result<crate::signer::SignResult, crate::signer::SignerError> {
        let input = std::fs::read(&request.input_path).map_err(|error| {
            crate::signer::SignerError::Signing(format!(
                "не удалось прочитать исходный файл: {error}"
            ))
        })?;
        let store = unsafe { open_personal_store() }.ok_or_else(|| {
            let code = unsafe { GetLastError() };
            crate::signer::SignerError::CertificateStore(format!("код Windows 0x{code:08X}"))
        })?;
        let certificate = find_certificate(&store, &request.certificate_id)?;
        let hash_oid = hash_oid_for_certificate(certificate.as_ptr())?;
        let mut output = sign_message(certificate.as_ptr(), &hash_oid, &input, request.detached)?;
        if request.base64 {
            output = encode_base64(&output).into_bytes();
        }

        let output_path = std::path::PathBuf::from(&request.output_path);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output_path)
            .map_err(|error| {
                crate::signer::SignerError::Signing(format!(
                    "не удалось создать файл результата без перезаписи ({}): {error}",
                    output_path.display()
                ))
            })?;
        if let Err(error) = file.write_all(&output) {
            drop(file);
            let _ = std::fs::remove_file(&output_path);
            return Err(crate::signer::SignerError::Signing(format!(
                "не удалось записать файл результата: {error}"
            )));
        }
        Ok(crate::signer::SignResult {
            output_path: output_path.display().to_string(),
            bytes_written: output.len(),
        })
    }

    pub(super) fn verify_cms(
        request: crate::signer::VerifyRequest,
    ) -> Result<crate::signer::VerifyResult, crate::signer::SignerError> {
        let signature_path = request.signature_path.clone();
        let signature = std::fs::read(&request.signature_path).map_err(|error| {
            crate::signer::SignerError::Signing(format!(
                "не удалось прочитать файл подписи: {error}"
            ))
        })?;
        let signature = if request.base64 {
            decode_base64(&signature)?
        } else {
            signature
        };
        let content_path = request.content_path.clone();
        let content = match content_path.as_ref() {
            Some(path) => Some(std::fs::read(path).map_err(|error| {
                crate::signer::SignerError::Signing(format!(
                    "не удалось прочитать исходный документ: {error}"
                ))
            })?),
            None => None,
        };
        if request.detached && content.is_none() {
            return Err(crate::signer::SignerError::Signing(
                "для отсоединённой подписи выберите исходный документ".to_owned(),
            ));
        }
        let signature_len = u32::try_from(signature.len()).map_err(|_| {
            crate::signer::SignerError::Signing(
                "файл подписи слишком велик для CryptoAPI".to_owned(),
            )
        })?;
        let mut parameters = CRYPT_VERIFY_MESSAGE_PARA::default();
        parameters.cbSize = std::mem::size_of::<CRYPT_VERIFY_MESSAGE_PARA>() as u32;
        parameters.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
        let content_bytes = content
            .as_ref()
            .map(|bytes| {
                u32::try_from(bytes.len()).map_err(|_| {
                    crate::signer::SignerError::Signing(
                        "исходный документ слишком велик для CryptoAPI".to_owned(),
                    )
                })
            })
            .transpose()?;
        let mut signers = Vec::new();
        let mut signer_index = 0u32;
        loop {
            let mut signer = ptr::null_mut();
            let valid = if request.detached {
                let bytes = content.as_ref().expect("checked above");
                let content_ptr = bytes.as_ptr();
                unsafe {
                    CryptVerifyDetachedMessageSignature(
                        &parameters,
                        signer_index,
                        signature.as_ptr(),
                        signature_len,
                        1,
                        &content_ptr,
                        content_bytes.as_ref().expect("content length checked"),
                        &mut signer,
                    ) != 0
                }
            } else {
                verify_attached_signer(
                    &parameters,
                    signer_index,
                    &signature,
                    signature_len,
                    &mut signer,
                )
            };
            if !valid {
                let code = unsafe { GetLastError() };
                if code == 0x8009_200E && signer_index > 0 {
                    break;
                } // CRYPT_E_NO_SIGNER
                return Ok(crate::signer::VerifyResult {
                    valid: false, signature_path, content_path, signers,
                    message: format!("Подпись подписанта №{} не прошла криптографическую проверку (код Windows 0x{code:08X}).", signer_index + 1),
                });
            }
            let signer_context = CertificateContext(signer);
            if let Some(cert) = unsafe { signer_context.as_ptr().as_ref() }
                .and_then(|context| unsafe { context.pCertInfo.as_ref() })
            {
                let (chain_trusted, chain_message) =
                    certificate_chain_status(signer_context.as_ptr());
                signers.push(crate::signer::VerifySignerInfo {
                    subject: unsafe { certificate_name(signer_context.as_ptr(), 0) },
                    issuer: unsafe {
                        certificate_name(signer_context.as_ptr(), CERT_NAME_ISSUER_FLAG)
                    },
                    expires_at: super::filetime_to_date(
                        cert.NotAfter.dwHighDateTime,
                        cert.NotAfter.dwLowDateTime,
                    ),
                    chain_trusted,
                    chain_message,
                });
            }
            signer_index += 1;
            if signer_index >= 128 {
                return Ok(crate::signer::VerifyResult {
                    valid: false,
                    signature_path,
                    content_path,
                    signers,
                    message: "В CMS найдено больше 127 подписантов; проверка остановлена."
                        .to_owned(),
                });
            }
        }
        Ok(crate::signer::VerifyResult {
            valid: !signers.is_empty(),
            signature_path,
            content_path,
            signers,
            message: "Криптографические подписи всех подписантов верны.".to_owned(),
        })
    }

    fn certificate_chain_status(certificate: *const CERT_CONTEXT) -> (bool, String) {
        let mut chain_parameters = CERT_CHAIN_PARA::default();
        chain_parameters.cbSize = std::mem::size_of::<CERT_CHAIN_PARA>() as u32;
        let mut chain: *mut CERT_CHAIN_CONTEXT = ptr::null_mut();
        let built = unsafe {
            CertGetCertificateChain(
                ptr::null_mut(),
                certificate,
                ptr::null(),
                ptr::null_mut(),
                &chain_parameters,
                CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL,
                ptr::null(),
                &mut chain,
            )
        };
        if built == 0 || chain.is_null() {
            let code = unsafe { GetLastError() };
            return (
                false,
                format!("Windows не смог построить цепочку сертификата (0x{code:08X})."),
            );
        }
        let mut policy_parameters = CERT_CHAIN_POLICY_PARA::default();
        policy_parameters.cbSize = std::mem::size_of::<CERT_CHAIN_POLICY_PARA>() as u32;
        let mut policy_status = CERT_CHAIN_POLICY_STATUS::default();
        policy_status.cbSize = std::mem::size_of::<CERT_CHAIN_POLICY_STATUS>() as u32;
        let checked = unsafe {
            CertVerifyCertificateChainPolicy(
                CERT_CHAIN_POLICY_BASE,
                chain,
                &policy_parameters,
                &mut policy_status,
            )
        };
        unsafe { CertFreeCertificateChain(chain) };
        if checked != 0 && policy_status.dwError == 0 {
            (
                true,
                "Цепочка доверия подтверждена Windows; проверка отзыва не выполнялась.".to_owned(),
            )
        } else {
            (false, format!("Windows не подтвердил цепочку доверия (код 0x{:08X}); проверка отзыва не выполнялась.", policy_status.dwError))
        }
    }

    fn verify_attached_signer(
        parameters: &CRYPT_VERIFY_MESSAGE_PARA,
        signer_index: u32,
        signature: &[u8],
        signature_len: u32,
        signer: &mut *mut CERT_CONTEXT,
    ) -> bool {
        let mut decoded_len = 0u32;
        let first = unsafe {
            CryptVerifyMessageSignature(
                parameters,
                signer_index,
                signature.as_ptr(),
                signature_len,
                ptr::null_mut(),
                &mut decoded_len,
                signer,
            )
        };
        if first != 0 {
            return true;
        }
        if unsafe { GetLastError() } != 234 {
            return false;
        } // ERROR_MORE_DATA
        if !(*signer).is_null() {
            unsafe { CertFreeCertificateContext(*signer) };
            *signer = ptr::null_mut();
        }
        let mut decoded = vec![0u8; decoded_len as usize];
        unsafe {
            CryptVerifyMessageSignature(
                parameters,
                signer_index,
                signature.as_ptr(),
                signature_len,
                decoded.as_mut_ptr(),
                &mut decoded_len,
                signer,
            ) != 0
        }
    }

    fn decode_base64(bytes: &[u8]) -> Result<Vec<u8>, crate::signer::SignerError> {
        let compact = bytes
            .iter()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>();
        let compact = if compact.starts_with(b"-----BEGIN") {
            String::from_utf8_lossy(&compact)
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .flat_map(str::bytes)
                .collect::<Vec<_>>()
        } else {
            compact
        };
        let mut out = Vec::with_capacity(compact.len() * 3 / 4);
        let mut chunk = [0u8; 4];
        let mut used = 0;
        for byte in compact {
            chunk[used] = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => 64,
                _ => {
                    return Err(crate::signer::SignerError::Signing(
                        "файл не является корректной Base64/PEM подписью".to_owned(),
                    ))
                }
            };
            used += 1;
            if used == 4 {
                out.push((chunk[0] << 2) | (chunk[1] >> 4));
                if chunk[2] != 64 {
                    out.push((chunk[1] << 4) | (chunk[2] >> 2));
                }
                if chunk[3] != 64 {
                    out.push((chunk[2] << 6) | chunk[3]);
                }
                used = 0;
            }
        }
        if used != 0 {
            return Err(crate::signer::SignerError::Signing(
                "некорректная длина Base64 подписи".to_owned(),
            ));
        }
        Ok(out)
    }

    fn find_certificate(
        store: &CertificateStore,
        id: &str,
    ) -> Result<CertificateContext, crate::signer::SignerError> {
        let mut previous = ptr::null();
        loop {
            let current = unsafe { next_certificate(store, previous) };
            if current.is_null() {
                break;
            }
            if unsafe { certificate_id(current) }.as_deref() == Some(id) {
                return Ok(CertificateContext(current));
            }
            previous = current;
        }
        Err(crate::signer::SignerError::Signing(
            "выбранный сертификат больше не найден в Windows Personal".to_owned(),
        ))
    }

    unsafe fn certificate_id(context: *const CERT_CONTEXT) -> Option<String> {
        let info = context.as_ref()?.pCertInfo.as_ref()?;
        let issuer = certificate_name(context, CERT_NAME_ISSUER_FLAG);
        let serial = &info.SerialNumber;
        let serial_id = if serial.pbData.is_null() || serial.cbData == 0 {
            format!("fallback:{}", certificate_name(context, 0))
        } else {
            std::slice::from_raw_parts(serial.pbData, serial.cbData as usize)
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<String>()
        };
        Some(format!("{issuer}:{serial_id}"))
    }

    fn hash_oid_for_certificate(
        context: *const CERT_CONTEXT,
    ) -> Result<Vec<u8>, crate::signer::SignerError> {
        let info = unsafe { context.as_ref() }
            .and_then(|context| unsafe { context.pCertInfo.as_ref() })
            .ok_or_else(|| {
                crate::signer::SignerError::Signing("повреждённый сертификат".to_owned())
            })?;
        let public_key_oid_ptr = info.SubjectPublicKeyInfo.Algorithm.pszObjId;
        if public_key_oid_ptr.is_null() {
            return Err(crate::signer::SignerError::Signing(
                "в сертификате отсутствует OID открытого ключа".to_owned(),
            ));
        }
        let public_key_oid = unsafe { CStr::from_ptr(public_key_oid_ptr.cast()) }.to_bytes();
        let hash_oid: &[u8] = match public_key_oid {
            b"1.2.643.7.1.1.1.1" => b"1.2.643.7.1.1.2.2\0",
            b"1.2.643.7.1.1.1.2" => b"1.2.643.7.1.1.2.3\0",
            b"1.2.643.2.2.19" => b"1.2.643.2.2.9\0",
            _ => {
                return Err(crate::signer::SignerError::Signing(format!(
                    "алгоритм сертификата пока не поддерживается (OID {})",
                    String::from_utf8_lossy(public_key_oid)
                )))
            }
        };
        Ok(hash_oid.to_vec())
    }

    fn sign_message(
        certificate: *const CERT_CONTEXT,
        hash_oid: &[u8],
        content: &[u8],
        detached: bool,
    ) -> Result<Vec<u8>, crate::signer::SignerError> {
        let mut certificate_pointer = certificate as *mut CERT_CONTEXT;
        let mut parameters = CRYPT_SIGN_MESSAGE_PARA::default();
        parameters.cbSize = std::mem::size_of::<CRYPT_SIGN_MESSAGE_PARA>() as u32;
        parameters.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
        parameters.pSigningCert = certificate;
        parameters.HashAlgorithm = CRYPT_ALGORITHM_IDENTIFIER {
            pszObjId: hash_oid.as_ptr() as *mut u8,
            ..Default::default()
        };
        parameters.cMsgCert = 1;
        parameters.rgpMsgCert = &mut certificate_pointer;
        let content_pointer = content.as_ptr();
        let content_length = u32::try_from(content.len()).map_err(|_| {
            crate::signer::SignerError::Signing(
                "исходный файл превышает лимит CryptoAPI".to_owned(),
            )
        })?;
        let mut signed_length = 0u32;
        let measured = unsafe {
            CryptSignMessage(
                &parameters,
                i32::from(detached),
                1,
                &content_pointer,
                &content_length,
                ptr::null_mut(),
                &mut signed_length,
            )
        };
        if measured == 0 {
            return Err(last_crypto_error("не удалось подготовить CMS-подпись"));
        }
        let mut signed = vec![0u8; signed_length as usize];
        let created = unsafe {
            CryptSignMessage(
                &parameters,
                i32::from(detached),
                1,
                &content_pointer,
                &content_length,
                signed.as_mut_ptr(),
                &mut signed_length,
            )
        };
        if created == 0 {
            return Err(last_crypto_error("CryptoAPI не смог создать CMS-подпись"));
        }
        signed.truncate(signed_length as usize);
        Ok(signed)
    }

    fn last_crypto_error(action: &str) -> crate::signer::SignerError {
        let code = unsafe { GetLastError() };
        crate::signer::SignerError::Signing(format!("{action} (код Windows 0x{code:08X})"))
    }

    fn encode_base64(bytes: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let a = chunk[0];
            let b = *chunk.get(1).unwrap_or(&0);
            let c = *chunk.get(2).unwrap_or(&0);
            result.push(TABLE[(a >> 2) as usize] as char);
            result.push(TABLE[(((a & 0x03) << 4) | (b >> 4)) as usize] as char);
            result.push(if chunk.len() > 1 {
                TABLE[(((b & 0x0f) << 2) | (c >> 6)) as usize] as char
            } else {
                '='
            });
            result.push(if chunk.len() > 2 {
                TABLE[(c & 0x3f) as usize] as char
            } else {
                '='
            });
        }
        result
    }

    unsafe fn certificate_name(context: *const CERT_CONTEXT, flags: u32) -> String {
        let size = CertGetNameStringW(
            context,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            flags,
            ptr::null::<c_void>(),
            ptr::null_mut(),
            0,
        );
        if size <= 1 {
            return String::new();
        }
        let mut buffer = vec![0u16; size as usize];
        let written = CertGetNameStringW(
            context,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            flags,
            ptr::null::<c_void>(),
            buffer.as_mut_ptr(),
            size,
        );
        if written <= 1 {
            return String::new();
        }
        String::from_utf16_lossy(&buffer[..written as usize - 1])
    }
}

pub fn probe() -> crate::signer::CspStatus {
    // CryptoPro documents 75/80/81 for GOST 2001, GOST 2012-256 and 2012-512.
    // CRYPT_VERIFYCONTEXT checks provider initialization without opening keys.
    let mut last_error = 0;
    let mut csp_version = None;
    let provider_type =
        [80, 81, 75].into_iter().find(|provider_type| {
            match ffi::acquire_provider(*provider_type) {
                Ok(provider) => {
                    csp_version = ffi::provider_version(&provider);
                    drop(provider);
                    true
                }
                Err(code) => {
                    last_error = code;
                    false
                }
            }
        });

    if let Some(provider_type) = provider_type {
        let cades_result = if cades_library_present() {
            super::cadescom::probe()
        } else {
            Err("CAdESCOM DLL не найдена".to_owned())
        };
        let cades_available = cades_result.is_ok();
        let message = if cades_available {
            "КриптоПро CSP и CAdESCOM обнаружены. Доступны CMS/PKCS#7 и CAdES-BES."
        } else if cades_library_present() {
            "КриптоПро CSP обнаружен, но COM объект CAdESCOM не активировался. CMS/PKCS#7 доступна."
        } else {
            "КриптоПро CSP обнаружен. Доступна подпись CMS/PKCS#7; CAdES-библиотека x64 не найдена."
        };
        crate::signer::CspStatus {
            available: true,
            cades_available,
            signing_available: true,
            provider_type: Some(provider_type),
            version: csp_version,
            message: message.to_owned(),
        }
    } else {
        crate::signer::CspStatus::unavailable(format!(
            "Не удалось открыть провайдеры Crypto-Pro CSP типов 80, 81 или 75 (код Windows 0x{last_error:08X})."
        ))
    }
}

pub fn list_certificates() -> Result<Vec<crate::signer::CertInfo>, crate::signer::SignerError> {
    ffi::list_personal_certificates()
}

pub fn sign_file(
    request: crate::signer::SignRequest,
) -> Result<crate::signer::SignResult, crate::signer::SignerError> {
    ffi::sign_cms(request)
}

pub fn verify_signature(
    request: crate::signer::VerifyRequest,
) -> Result<crate::signer::VerifyResult, crate::signer::SignerError> {
    ffi::verify_cms(request)
}

fn cades_library_present() -> bool {
    let mut roots = Vec::new();
    if let Some(dir) = std::env::var_os("CPSIGNER_CSP_LIB_DIR") {
        roots.push(std::path::PathBuf::from(dir));
    }
    if let Some(program_files) = std::env::var_os("ProgramFiles") {
        let root = std::path::PathBuf::from(program_files);
        roots.push(root.join("Crypto Pro/CSP"));
        roots.push(root.join("Crypto Pro/CAdESCOM"));
        roots.push(root.join("Crypto Pro/CAdES Browser Plug-in"));
        roots.push(root.join("Common Files/Crypto Pro/Shared"));
    }
    ["cadescom.dll", "cades.dll"]
        .iter()
        .any(|name| roots.iter().any(|root| root.join(name).is_file()))
}

fn filetime_to_date(high: u32, low: u32) -> String {
    const WINDOWS_TO_UNIX_EPOCH_SECONDS: i64 = 11_644_473_600;
    let ticks = ((high as u64) << 32) | low as u64;
    let unix_days = (ticks / 10_000_000) as i64 / 86_400 - WINDOWS_TO_UNIX_EPOCH_SECONDS / 86_400;
    let z = unix_days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_part = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_part + 2) / 5 + 1;
    let month = month_part + if month_part < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    format!("{year:04}-{month:02}-{day:02}")
}
