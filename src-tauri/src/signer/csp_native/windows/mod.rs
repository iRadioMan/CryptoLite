#![deny(unsafe_code)]

pub mod digest;

#[allow(unsafe_code)]
mod ffi {
    use std::ffi::CStr;
    use std::ptr;
    use windows_sys::Win32::Security::Cryptography::{
        CryptAcquireContextW, CryptGetProvParam, CryptReleaseContext, CRYPT_VERIFYCONTEXT,
    };

    /// PP_LICENSE из `WinCryptEx.h`: состояние лицензии установленного КриптоПро CSP.
    const PP_LICENSE: u32 = 158;

    /// CALG_GR3411_2012_256 (0x800C), см. документацию КриптоПро по хэш-алгоритмам CSP.
    const HASH_ALG_GOST_2012_256: u32 = 0x0000_800C;
    /// CALG_GR3411_2012_512 (0x800D).
    const HASH_ALG_GOST_2012_512: u32 = 0x0000_800D;

    /// OID алгоритмов дайджеста, которые встречаются в сертификатах ГОСТ.
    const DIGEST_OID_GOST_2012_256: &[u8] = b"1.2.643.7.1.1.2.2\0";
    const DIGEST_OID_GOST_2012_512: &[u8] = b"1.2.643.7.1.1.2.3\0";
    const DIGEST_OID_GOST_2001: &[u8] = b"1.2.643.2.2.9\0";
    const DIGEST_OID_SHA_256: &[u8] = b"2.16.840.1.101.3.4.2.1\0";

    #[link(name = "advapi32")]
    extern "system" {
        /// `CryptSetHashParam` отсутствует в windows-sys: объявляем подпись из advapi32.
        fn CryptSetHashParam(
            h_hash: usize,
            dw_param: u32,
            pb_data: *const u8,
            dw_flags: u32,
        ) -> i32;
    }

    /// OID алгоритма дайджеста для подписи по ключу ГОСТ 2012-512 и CALG Стрибог-2012-512.
    ///
    /// Остальные ГОСТ-ключи подписываются Стрибогом-2012-256 (`CALG_GR3411_2012_256`).
    /// ГОСТ Р 34.10-2012 подписывает хэш той же длины, что и ключ, поэтому 512-битный ключ
    /// не подписывается усечённым Стрибогом-256.
    fn hash_algorithm_for_certificate(
        context: *const CERT_CONTEXT,
    ) -> Result<(u32, &'static [u8]), crate::signer::SignerError> {
        let hash_oid = hash_oid_for_certificate(context)?;
        let algorithm = if hash_oid == DIGEST_OID_GOST_2012_512 {
            HASH_ALG_GOST_2012_512
        } else {
            HASH_ALG_GOST_2012_256
        };
        Ok((algorithm, digest_oid_constant(&hash_oid)?))
    }

    /// Статический OID по значению из сертификата: `pszObjId` живёт вместе с контекстом
    /// сертификата, а OID нужен в CMS до закрытия контекста — поэтому берётся константа.
    fn digest_oid_constant(hash_oid: &[u8]) -> Result<&'static [u8], crate::signer::SignerError> {
        if hash_oid == DIGEST_OID_GOST_2012_256 {
            Ok(DIGEST_OID_GOST_2012_256)
        } else if hash_oid == DIGEST_OID_GOST_2012_512 {
            Ok(DIGEST_OID_GOST_2012_512)
        } else if hash_oid == DIGEST_OID_GOST_2001 {
            Ok(DIGEST_OID_GOST_2001)
        } else {
            Err(crate::signer::SignerError::Signing(tr!(
                "неизвестный OID алгоритма хэша сертификата",
                "unknown certificate hash algorithm OID"
            )))
        }
    }

    /// OID содержимого `id-data`, которым помечен подписанный диапазон PDF.
    ///
    /// Без явного `ContentType` Windows кодирует PKCS#7 v1.5 и не пишет
    /// `contentType`/`messageDigest` в подписанные атрибуты. Такая подпись технически
    /// проходит проверку, но это не CAdES-BES и не PAdES: КриптоПро PDF, Acrobat и
    /// КриптоАРМ требуют CMS v3 с подписанными атрибутами (см. `/SubFilter adbe.pkcs7.detached`
    /// в эталонном файле: подпись начинается с `1.2.840.113549.1.7.2`, signerInfo v3).
    fn id_data_content_type() -> Vec<u8> {
        b"1.2.840.113549.1.7.1\0".to_vec()
    }

    /// Подпись диапазона PDF и подпись готового хэша (структура из cades.h).
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

    /// Есть ли у провайдера действующая лицензия КриптоПро CSP.
    ///
    /// Читается только признак наличия: содержимое лицензии (в том числе серийный номер)
    /// не сохраняется и не логируется.
    pub(super) fn provider_has_license(provider: &ProviderContext) -> bool {
        let mut length = 0u32;
        let sized = unsafe {
            CryptGetProvParam(provider.0, PP_LICENSE, ptr::null_mut(), &mut length, 0)
        };
        if sized == 0 || length == 0 {
            return false;
        }
        let mut buffer = vec![0u8; length as usize];
        let read = unsafe {
            CryptGetProvParam(provider.0, PP_LICENSE, buffer.as_mut_ptr(), &mut length, 0)
        };
        read != 0 && length > 0
    }

    use crate::tr;
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Security::Cryptography::{
        CertCloseStore, CertEnumCertificatesInStore, CertFreeCertificateChain,
        CertFreeCertificateContext, CertGetCertificateChain, CertGetCertificateContextProperty,
        CertGetNameStringW, CertOpenSystemStoreW, CertVerifyCertificateChainPolicy,
        CryptCreateHash, CryptDecryptMessage, CryptDestroyHash, CryptDestroyKey,
        CryptEncryptMessage, CryptGetHashParam, CryptGetUserKey, CryptHashData, CryptMsgClose,
        CryptMsgGetParam, CryptMsgOpenToEncode, CryptMsgUpdate,
        CryptVerifyDetachedMessageSignature, CryptVerifyMessageSignature, AT_KEYEXCHANGE,
        AT_SIGNATURE, CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, CERT_CHAIN_CONTEXT, CERT_CHAIN_PARA,
        CERT_CHAIN_POLICY_BASE, CERT_CHAIN_POLICY_PARA, CERT_CHAIN_POLICY_STATUS, CERT_CONTEXT,
        CERT_INFO, CERT_KEY_PROV_INFO_PROP_ID, CERT_NAME_ISSUER_FLAG,
        CERT_NAME_SIMPLE_DISPLAY_TYPE, CMSG_CONTENT_PARAM, CMSG_DETACHED_FLAG, CMSG_SIGNED,
        CMSG_SIGNED_ENCODE_INFO, CMSG_SIGNER_ENCODE_INFO, CMSG_SIGNER_ENCODE_INFO_0,
        CRYPT_ALGORITHM_IDENTIFIER, CRYPT_DECRYPT_MESSAGE_PARA, CRYPT_ENCRYPT_MESSAGE_PARA,
        CRYPT_INTEGER_BLOB, CRYPT_KEY_PROV_INFO, CRYPT_VERIFY_MESSAGE_PARA, HCERTSTORE,
        HP_HASHSIZE, HP_HASHVAL, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
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

    pub(super) fn sign_pdf_range(
        certificate_id: &str,
        content: &[u8],
    ) -> Result<Vec<u8>, crate::signer::SignerError> {
        let store = unsafe { open_personal_store() }.ok_or_else(|| {
            let code = unsafe { GetLastError() };
            crate::signer::SignerError::CertificateStore(tr!(
                "код Windows 0x{code:08X}",
                "Windows code 0x{code:08X}"
            ))
        })?;
        let certificate = find_certificate(&store, certificate_id)?;
        let hash_oid = hash_oid_for_certificate(certificate.as_ptr())?;
        // тот же путь, что у обычной detached-подписи файлов:
        // CryptoAPI сам хэширует `content` и кладёт хэш в messageDigest
        sign_message(std::slice::from_ref(&certificate), &[hash_oid], content, true)
    }

    /// Открывает контейнер закрытого ключа сертификата (BLOB KEY_PROV_INFO → CryptAcquireContext).
    ///
    /// `key_spec` — предпочтительная спецификация ключа; подпись выбирает фактическую через
    /// [`signing_key_spec`], потому что в токенах доступен не любой ключ контейнера.
    fn provider_for_certificate(
        context: *const CERT_CONTEXT,
        _key_spec: u32,
    ) -> Result<ProviderContext, crate::signer::SignerError> {
        let mut key_info_len = 0u32;
        let ok = unsafe {
            CertGetCertificateContextProperty(
                context,
                CERT_KEY_PROV_INFO_PROP_ID,
                ptr::null_mut(),
                &mut key_info_len,
            )
        };
        if ok == 0 || key_info_len == 0 {
            return Err(crate::signer::SignerError::Signing(tr!(
                "у сертификата подписанта нет сведений о закрытом ключе (код Windows 0x{:08X})",
                "the signer certificate has no private key information (Windows code 0x{:08X})",
                unsafe { GetLastError() }
            )));
        }
        let mut key_info_bytes = vec![0u8; key_info_len as usize];
        let ok = unsafe {
            CertGetCertificateContextProperty(
                context,
                CERT_KEY_PROV_INFO_PROP_ID,
                key_info_bytes.as_mut_ptr() as *mut c_void,
                &mut key_info_len,
            )
        };
        if ok == 0 {
            return Err(crate::signer::SignerError::Signing(tr!(
                "не удалось прочитать сведения о закрытом ключе (код Windows 0x{:08X})",
                "could not read private key information (Windows code 0x{:08X})",
                unsafe { GetLastError() }
            )));
        }
        let key_info = key_info_bytes.as_ptr() as *const CRYPT_KEY_PROV_INFO;
        let mut provider = 0usize;
        let acquired = unsafe {
            CryptAcquireContextW(
                &mut provider,
                (*key_info).pwszContainerName,
                (*key_info).pwszProvName,
                (*key_info).dwProvType,
                0,
            )
        };
        if acquired == 0 {
            return Err(crate::signer::SignerError::Signing(tr!(
                "не удалось открыть контейнер закрытого ключа подписанта (код Windows 0x{:08X})",
                "could not open the signer's private key container (Windows code 0x{:08X})",
                unsafe { GetLastError() }
            )));
        }
        let provider = ProviderContext(provider);
        Ok(provider)
    }

    pub(super) fn sha256_unused() {}

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

    /// `CryptGetUserKey` по спецификации и проверка, что ключ действительно лежит в этом
    /// контейнере. Возвращает false, если ключа нет (например, в токене доступен только один).
    fn container_has_key(provider: usize, key_spec: u32) -> bool {
        let mut key = 0usize;
        if unsafe { CryptGetUserKey(provider, key_spec, &mut key) } == 0 {
            return false;
        }
        unsafe { CryptDestroyKey(key) };
        true
    }

    /// Спецификация ключа для подписи — как в `CryptSignMessage`: сначала `AT_SIGNATURE`,
    /// затем `AT_KEYEXCHANGE`.
    fn signing_key_spec(provider: usize) -> Result<u32, crate::signer::SignerError> {
        if container_has_key(provider, AT_SIGNATURE) {
            return Ok(AT_SIGNATURE);
        }
        if container_has_key(provider, AT_KEYEXCHANGE) {
            return Ok(AT_KEYEXCHANGE);
        }
        Err(crate::signer::SignerError::Signing(tr!(
            "в контейнере закрытого ключа не найден ни ключ подписи, ни ключ обмена (код Windows 0x{:08X})",
            "neither a signature key nor an exchange key was found in the private key container (Windows code 0x{:08X})",
            unsafe { GetLastError() }
        )))
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
        let not_before =
            super::filetime_to_date(info.NotBefore.dwHighDateTime, info.NotBefore.dwLowDateTime);
        let not_after =
            super::filetime_to_date(info.NotAfter.dwHighDateTime, info.NotAfter.dwLowDateTime);
        Some(crate::signer::CertInfo {
            id,
            subject: subject.clone(),
            issuer,
            expires_at,
            expired,
            has_private_key,
            source: tr!("Windows · Личное хранилище", "Windows · Personal store"),
            serial_number: hex_upper(&serial_id),
            not_before,
            not_after,
            owner_name: subject
                .split(',')
                .find_map(|part| part.trim().strip_prefix("CN="))
                .unwrap_or(&subject)
                .to_owned(),
        })
    }

    /// Серийный номер в привычной записи — без служебного префикса fallback.
    fn hex_upper(serial_id: &str) -> String {
        if serial_id.starts_with("fallback:") {
            String::new()
        } else {
            serial_id.to_owned()
        }
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
            crate::signer::SignerError::CertificateStore(tr!(
                "код Windows 0x{code:08X}",
                "Windows code 0x{code:08X}"
            ))
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
            crate::signer::SignerError::Signing(tr!(
                "не удалось прочитать исходный файл: {error}",
                "could not read the source file: {error}"
            ))
        })?;
        if request.certificate_ids.is_empty() {
            return Err(crate::signer::SignerError::Signing(tr!(
                "выберите хотя бы один сертификат для подписания",
                "select at least one certificate for signing"
            )));
        }
        let store = unsafe { open_personal_store() }.ok_or_else(|| {
            let code = unsafe { GetLastError() };
            crate::signer::SignerError::CertificateStore(tr!(
                "код Windows 0x{code:08X}",
                "Windows code 0x{code:08X}"
            ))
        })?;
        // Resolve every selected certificate; all sign the same content into one CMS.
        let certificates = request
            .certificate_ids
            .iter()
            .map(|id| find_certificate(&store, id))
            .collect::<Result<Vec<_>, _>>()?;
        let hash_oids = certificates
            .iter()
            .map(|certificate| hash_oid_for_certificate(certificate.as_ptr()))
            .collect::<Result<Vec<_>, _>>()?;
        let mut output = sign_message(&certificates, &hash_oids, &input, request.detached)?;
        if request.base64 {
            output = encode_base64(&output).into_bytes();
        }

        let requested = std::path::PathBuf::from(&request.output_path);
        let final_path =
            crate::signer::output::write_unique(&requested, &output).map_err(|error| {
                crate::signer::SignerError::Signing(tr!(
                    "не удалось записать файл результата ({}): {error}",
                    "could not write the result file ({}): {error}",
                    requested.display()
                ))
            })?;
        Ok(crate::signer::SignResult {
            output_path: final_path.display().to_string(),
            bytes_written: output.len(),
        })
    }

    pub(super) fn verify_cms(
        request: crate::signer::VerifyRequest,
    ) -> Result<crate::signer::VerifyResult, crate::signer::SignerError> {
        let signature_path = request.signature_path.clone();
        let signature = std::fs::read(&request.signature_path).map_err(|error| {
            crate::signer::SignerError::Signing(tr!(
                "не удалось прочитать файл подписи: {error}",
                "could not read the signature file: {error}"
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
                crate::signer::SignerError::Signing(tr!(
                    "не удалось прочитать исходный документ: {error}",
                    "could not read the source document: {error}"
                ))
            })?),
            None => None,
        };
        if request.detached && content.is_none() {
            return Err(crate::signer::SignerError::Signing(tr!(
                "для отсоединённой подписи выберите исходный документ",
                "select the source document for a detached signature"
            )));
        }
        let signature_len = u32::try_from(signature.len()).map_err(|_| {
            crate::signer::SignerError::Signing(tr!(
                "файл подписи слишком велик для CryptoAPI",
                "the signature file is too large for CryptoAPI"
            ))
        })?;
        let mut parameters = CRYPT_VERIFY_MESSAGE_PARA::default();
        parameters.cbSize = std::mem::size_of::<CRYPT_VERIFY_MESSAGE_PARA>() as u32;
        parameters.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
        let content_bytes = content
            .as_ref()
            .map(|bytes| {
                u32::try_from(bytes.len()).map_err(|_| {
                    crate::signer::SignerError::Signing(tr!(
                        "исходный документ слишком велик для CryptoAPI",
                        "the source document is too large for CryptoAPI"
                    ))
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
                    message: tr!(
                        "Подпись подписанта №{} не прошла криптографическую проверку (код Windows 0x{code:08X}).",
                        "The signature of signer #{} failed cryptographic verification (Windows code 0x{code:08X}).",
                        signer_index + 1
                    ),
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
                    message: tr!(
                        "В CMS найдено больше 127 подписантов; проверка остановлена.",
                        "More than 127 signers were found in the CMS; verification stopped."
                    ),
                });
            }
        }
        Ok(crate::signer::VerifyResult {
            valid: !signers.is_empty(),
            signature_path,
            content_path,
            signers,
            message: tr!(
                "Криптографические подписи всех подписантов верны.",
                "The cryptographic signatures of all signers are valid."
            ),
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
                tr!(
                    "Windows не смог построить цепочку сертификата (0x{code:08X}).",
                    "Windows could not build the certificate chain (0x{code:08X})."
                ),
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
                tr!(
                    "Цепочка доверия подтверждена Windows; проверка отзыва не выполнялась.",
                    "The trust chain was confirmed by Windows; revocation was not checked."
                ),
            )
        } else {
            (false, tr!("Windows не подтвердил цепочку доверия (код 0x{:08X}); проверка отзыва не выполнялась.", "Windows did not confirm the trust chain (code 0x{:08X}); revocation was not checked.", policy_status.dwError))
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
        use base64::Engine as _;
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
        base64::engine::general_purpose::STANDARD
            .decode(compact)
            .map_err(|_| {
                crate::signer::SignerError::Signing(tr!(
                    "файл не является корректной Base64/PEM подписью",
                    "the file is not a valid Base64/PEM signature"
                ))
            })
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
        Err(crate::signer::SignerError::Signing(tr!(
            "выбранный сертификат больше не найден в Windows Personal",
            "the selected certificate is no longer present in the Windows Personal store"
        )))
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

    fn find_certificate_by_id(
        store: &CertificateStore,
        id: &str,
    ) -> Result<CertificateContext, crate::signer::SignerError> {
        find_certificate(store, id)
    }

    pub(super) fn pdf_certificate_public_key_oid(
        id: &str,
    ) -> Result<Vec<u8>, crate::signer::SignerError> {
        let store = unsafe { open_personal_store() }.ok_or_else(|| {
            let code = unsafe { GetLastError() };
            crate::signer::SignerError::CertificateStore(tr!(
                "код Windows 0x{code:08X}",
                "Windows code 0x{code:08X}"
            ))
        })?;
        let certificate = find_certificate_by_id(&store, id)?;
        let info = unsafe { certificate.as_ptr().as_ref() }
            .and_then(|context| unsafe { context.pCertInfo.as_ref() })
            .ok_or_else(|| {
                crate::signer::SignerError::Signing(tr!(
                    "повреждённый сертификат",
                    "corrupt certificate"
                ))
            })?;
        let oid = info.SubjectPublicKeyInfo.Algorithm.pszObjId;
        if oid.is_null() {
            return Err(crate::signer::SignerError::Signing(tr!(
                "в сертификате отсутствует OID открытого ключа",
                "the certificate has no public key OID"
            )));
        }
        Ok(unsafe { CStr::from_ptr(oid.cast()) }.to_bytes().to_vec())
    }

    fn hash_oid_for_certificate(
        context: *const CERT_CONTEXT,
    ) -> Result<Vec<u8>, crate::signer::SignerError> {
        let info = unsafe { context.as_ref() }
            .and_then(|context| unsafe { context.pCertInfo.as_ref() })
            .ok_or_else(|| {
                crate::signer::SignerError::Signing(tr!(
                    "повреждённый сертификат",
                    "corrupt certificate"
                ))
            })?;
        let public_key_oid_ptr = info.SubjectPublicKeyInfo.Algorithm.pszObjId;
        if public_key_oid_ptr.is_null() {
            return Err(crate::signer::SignerError::Signing(tr!(
                "в сертификате отсутствует OID открытого ключа",
                "the certificate has no public key OID"
            )));
        }
        let public_key_oid = unsafe { CStr::from_ptr(public_key_oid_ptr.cast()) }.to_bytes();
        let hash_oid: &[u8] = match public_key_oid {
            b"1.2.643.7.1.1.1.1" => DIGEST_OID_GOST_2012_256,
            b"1.2.643.7.1.1.1.2" => DIGEST_OID_GOST_2012_512,
            b"1.2.643.2.2.19" => DIGEST_OID_GOST_2001,
            _ => {
                return Err(crate::signer::SignerError::Signing(tr!(
                    "алгоритм сертификата пока не поддерживается (OID {})",
                    "the certificate algorithm is not supported yet (OID {})",
                    String::from_utf8_lossy(public_key_oid)
                )))
            }
        };
        Ok(hash_oid.to_vec())
    }

    fn sign_message(
        certificates: &[CertificateContext],
        hash_oids: &[Vec<u8>],
        content: &[u8],
        detached: bool,
    ) -> Result<Vec<u8>, crate::signer::SignerError> {
        // Build one CMS SignedData with a separate SignerInfo for every selected certificate.
        // Key resolution mirrors CryptSignMessage: read CERT_KEY_PROV_INFO_PROP_ID, acquire the
        // CSP context for that container, then determine the key spec by probing AT_SIGNATURE
        // first and falling back to AT_KEYEXCHANGE.
        let mut providers = Vec::with_capacity(certificates.len());
        let mut signer_infos = Vec::with_capacity(certificates.len());
        let mut cert_blobs = Vec::with_capacity(certificates.len());

        for (index, certificate) in certificates.iter().enumerate() {
            let context = certificate.as_ptr();
            let cert_info = unsafe { context.as_ref() }
                .and_then(|ctx| unsafe { ctx.pCertInfo.as_ref() })
                .ok_or_else(|| {
                    crate::signer::SignerError::Signing(tr!(
                        "повреждённый сертификат",
                        "corrupt certificate"
                    ))
                })?;

            // Embed this certificate's DER encoding into the signed message so verifiers can
            // locate the signer's certificate.
            let cert_context = unsafe { context.as_ref() }.ok_or_else(|| {
                crate::signer::SignerError::Signing(tr!(
                    "повреждённый сертификат",
                    "corrupt certificate"
                ))
            })?;
            cert_blobs.push(CRYPT_INTEGER_BLOB {
                cbData: cert_context.cbCertEncoded,
                pbData: cert_context.pbCertEncoded,
            });

            let mut key_info_len = 0u32;
            let ok = unsafe {
                CertGetCertificateContextProperty(
                    context,
                    CERT_KEY_PROV_INFO_PROP_ID,
                    ptr::null_mut(),
                    &mut key_info_len,
                )
            };
            if ok == 0 || key_info_len == 0 {
                return Err(crate::signer::SignerError::Signing(tr!(
                    "у сертификата подписанта нет сведений о закрытом ключе (код Windows 0x{:08X})",
                    "the signer certificate has no private key information (Windows code 0x{:08X})",
                    unsafe { GetLastError() }
                )));
            }
            let mut key_info_bytes = vec![0u8; key_info_len as usize];
            let ok = unsafe {
                CertGetCertificateContextProperty(
                    context,
                    CERT_KEY_PROV_INFO_PROP_ID,
                    key_info_bytes.as_mut_ptr() as *mut c_void,
                    &mut key_info_len,
                )
            };
            if ok == 0 {
                return Err(crate::signer::SignerError::Signing(tr!(
                    "не удалось прочитать сведения о закрытом ключе (код Windows 0x{:08X})",
                    "could not read private key information (Windows code 0x{:08X})",
                    unsafe { GetLastError() }
                )));
            }
            let key_info = key_info_bytes.as_ptr() as *const CRYPT_KEY_PROV_INFO;

            let mut provider = 0usize;
            let acquired = unsafe {
                CryptAcquireContextW(
                    &mut provider,
                    (*key_info).pwszContainerName,
                    (*key_info).pwszProvName,
                    (*key_info).dwProvType,
                    0,
                )
            };
            if acquired == 0 {
                return Err(crate::signer::SignerError::Signing(tr!(
                    "не удалось открыть контейнер закрытого ключа подписанта (код Windows 0x{:08X})",
                    "could not open the signer's private key container (Windows code 0x{:08X})",
                    unsafe { GetLastError() }
                )));
            }
            providers.push(ProviderContext(provider));

            // Determine the key spec by probing the actual keys in the container, exactly as
            // CryptSignMessage does: prefer AT_SIGNATURE, fall back to AT_KEYEXCHANGE.
            let mut signature_key = 0usize;
            let has_signature =
                unsafe { CryptGetUserKey(provider, AT_SIGNATURE, &mut signature_key) };
            let key_spec = if has_signature != 0 {
                unsafe { CryptDestroyKey(signature_key) };
                AT_SIGNATURE
            } else {
                let mut exchange_key = 0usize;
                let has_exchange =
                    unsafe { CryptGetUserKey(provider, AT_KEYEXCHANGE, &mut exchange_key) };
                if has_exchange == 0 {
                    return Err(crate::signer::SignerError::Signing(tr!(
                        "в контейнере закрытого ключа не найден ни ключ подписи, ни ключ обмена (код Windows 0x{:08X})",
                        "neither a signature key nor an exchange key was found in the private key container (Windows code 0x{:08X})",
                        unsafe { GetLastError() }
                    )));
                }
                unsafe { CryptDestroyKey(exchange_key) };
                AT_KEYEXCHANGE
            };

            let hash_oid = &hash_oids[index];
            let signer_info = CMSG_SIGNER_ENCODE_INFO {
                cbSize: std::mem::size_of::<CMSG_SIGNER_ENCODE_INFO>() as u32,
                pCertInfo: cert_info as *const CERT_INFO as *mut CERT_INFO,
                Anonymous: CMSG_SIGNER_ENCODE_INFO_0 {
                    hCryptProv: provider,
                },
                dwKeySpec: key_spec,
                HashAlgorithm: CRYPT_ALGORITHM_IDENTIFIER {
                    pszObjId: hash_oid.as_ptr() as *mut u8,
                    ..Default::default()
                },
                pvHashAuxInfo: ptr::null_mut(),
                cAuthAttr: 0,
                rgAuthAttr: ptr::null_mut(),
                cUnauthAttr: 0,
                rgUnauthAttr: ptr::null_mut(),
            };
            signer_infos.push(signer_info);
        }

        let signer_count = u32::try_from(signer_infos.len()).map_err(|_| {
            crate::signer::SignerError::Signing(tr!(
                "слишком много сертификатов подписантов",
                "too many signer certificates"
            ))
        })?;
        let cert_count = u32::try_from(cert_blobs.len()).map_err(|_| {
            crate::signer::SignerError::Signing(tr!(
                "слишком много сертификатов подписантов",
                "too many signer certificates"
            ))
        })?;
        let signed_encode_info = CMSG_SIGNED_ENCODE_INFO {
            cbSize: std::mem::size_of::<CMSG_SIGNED_ENCODE_INFO>() as u32,
            cSigners: signer_count,
            rgSigners: signer_infos.as_mut_ptr(),
            cCertEncoded: cert_count,
            rgCertEncoded: cert_blobs.as_mut_ptr(),
            cCrlEncoded: 0,
            rgCrlEncoded: ptr::null_mut(),
        };

        let mut flags = 0u32;
        if detached {
            flags |= CMSG_DETACHED_FLAG;
        }
        let message = unsafe {
            CryptMsgOpenToEncode(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                flags,
                CMSG_SIGNED,
                &signed_encode_info as *const CMSG_SIGNED_ENCODE_INFO as *const c_void,
                ptr::null(),
                ptr::null(),
            )
        };
        if message.is_null() {
            return Err(crate::signer::SignerError::Signing(tr!(
                "не удалось открыть CMS-сообщение для подписания (код Windows 0x{:08X})",
                "could not open the CMS message for signing (Windows code 0x{:08X})",
                unsafe { GetLastError() }
            )));
        }

        let content_length = u32::try_from(content.len()).map_err(|_| {
            crate::signer::SignerError::Signing(tr!(
                "исходный файл превышает лимит CryptoAPI",
                "the source file exceeds the CryptoAPI limit"
            ))
        })?;
        let updated = unsafe { CryptMsgUpdate(message, content.as_ptr(), content_length, 1) };
        if updated == 0 {
            unsafe { CryptMsgClose(message) };
            return Err(crate::signer::SignerError::Signing(tr!(
                "не удалось добавить данные в CMS-сообщение (код Windows 0x{:08X})",
                "could not add data to the CMS message (Windows code 0x{:08X})",
                unsafe { GetLastError() }
            )));
        }

        let mut encoded_length = 0u32;
        let sized = unsafe {
            CryptMsgGetParam(
                message,
                CMSG_CONTENT_PARAM,
                0,
                ptr::null_mut(),
                &mut encoded_length,
            )
        };
        if sized == 0 || encoded_length == 0 {
            unsafe { CryptMsgClose(message) };
            return Err(crate::signer::SignerError::Signing(tr!(
                "не удалось определить размер CMS-подписи (код Windows 0x{:08X})",
                "could not determine the CMS signature size (Windows code 0x{:08X})",
                unsafe { GetLastError() }
            )));
        }
        let mut encoded = vec![0u8; encoded_length as usize];
        let got = unsafe {
            CryptMsgGetParam(
                message,
                CMSG_CONTENT_PARAM,
                0,
                encoded.as_mut_ptr() as *mut c_void,
                &mut encoded_length,
            )
        };
        unsafe { CryptMsgClose(message) };
        if got == 0 {
            return Err(crate::signer::SignerError::Signing(tr!(
                "не удалось получить закодированную CMS-подпись (код Windows 0x{:08X})",
                "could not obtain the encoded CMS signature (Windows code 0x{:08X})",
                unsafe { GetLastError() }
            )));
        }
        encoded.truncate(encoded_length as usize);
        Ok(encoded)
    }

    pub(super) fn encrypt_cms(
        request: crate::signer::EncryptRequest,
    ) -> Result<crate::signer::EncryptResult, crate::signer::SignerError> {
        let input = std::fs::read(&request.input_path).map_err(|error| {
            crate::signer::SignerError::Encryption(tr!(
                "не удалось прочитать исходный файл: {error}",
                "could not read the source file: {error}"
            ))
        })?;
        if request.certificate_ids.is_empty() {
            return Err(crate::signer::SignerError::Encryption(tr!(
                "выберите хотя бы один сертификат получателя",
                "select at least one recipient certificate"
            )));
        }
        let store = unsafe { open_personal_store() }.ok_or_else(|| {
            let code = unsafe { GetLastError() };
            crate::signer::SignerError::CertificateStore(tr!(
                "код Windows 0x{code:08X}",
                "Windows code 0x{code:08X}"
            ))
        })?;
        // Resolve each recipient certificate and keep them alive for the CryptoAPI call.
        let recipients = request
            .certificate_ids
            .iter()
            .map(|id| find_certificate(&store, id))
            .collect::<Result<Vec<_>, _>>()?;
        let content_encryption_oid = content_encryption_oid_for_certificates(&recipients)?;
        let mut output = encrypt_message(&recipients, &content_encryption_oid, &input)?;
        if request.base64 {
            output = encode_base64(&output).into_bytes();
        }

        let final_path = write_result(&request.output_path, &output, ResultFileKind::Encryption)?;
        Ok(crate::signer::EncryptResult {
            output_path: final_path,
            bytes_written: output.len(),
        })
    }

    pub(super) fn decrypt_cms(
        request: crate::signer::DecryptRequest,
    ) -> Result<crate::signer::DecryptResult, crate::signer::SignerError> {
        let input = std::fs::read(&request.input_path).map_err(|error| {
            crate::signer::SignerError::Decryption(tr!(
                "не удалось прочитать зашифрованный файл: {error}",
                "could not read the encrypted file: {error}"
            ))
        })?;
        let input = if request.base64 {
            decode_base64(&input)?
        } else {
            input
        };
        let store = unsafe { open_personal_store() }.ok_or_else(|| {
            let code = unsafe { GetLastError() };
            crate::signer::SignerError::CertificateStore(tr!(
                "код Windows 0x{code:08X}",
                "Windows code 0x{code:08X}"
            ))
        })?;
        let output = decrypt_message(&store, &input)?;
        let final_path = write_result(&request.output_path, &output, ResultFileKind::Decryption)?;
        Ok(crate::signer::DecryptResult {
            output_path: final_path,
            bytes_written: output.len(),
        })
    }

    fn content_encryption_oid_for_certificates(
        recipients: &[CertificateContext],
    ) -> Result<Vec<u8>, crate::signer::SignerError> {
        // Choose a symmetric content algorithm compatible with the recipients' public keys.
        // For GOST 2012 recipients CryptoPro uses Kuznyechik; for GOST 2001 it uses GOST 28147-89.
        let mut saw_gost_2012 = false;
        for recipient in recipients {
            let oid = unsafe { certificate_public_key_oid(recipient.as_ptr()) };
            match oid {
                Some(oid) if oid.starts_with(b"1.2.643.7.1.1.1") => saw_gost_2012 = true,
                Some(_) => {}
                None => {
                    return Err(crate::signer::SignerError::Encryption(tr!(
                        "не удалось определить алгоритм ключа получателя",
                        "could not determine the recipient key algorithm"
                    )))
                }
            }
        }
        // Kuznyechik for GOST 2012-256/512, Magma (GOST 28147-89) otherwise.
        let oid: &[u8] = if saw_gost_2012 {
            b"1.2.643.7.1.1.5.1\0"
        } else {
            b"1.2.643.2.2.21\0"
        };
        Ok(oid.to_vec())
    }

    unsafe fn certificate_public_key_oid(context: *const CERT_CONTEXT) -> Option<&'static [u8]> {
        let info = context.as_ref()?.pCertInfo.as_ref()?;
        let oid_ptr = info.SubjectPublicKeyInfo.Algorithm.pszObjId;
        if oid_ptr.is_null() {
            return None;
        }
        Some(CStr::from_ptr(oid_ptr.cast()).to_bytes())
    }

    fn encrypt_message(
        recipients: &[CertificateContext],
        content_encryption_oid: &[u8],
        content: &[u8],
    ) -> Result<Vec<u8>, crate::signer::SignerError> {
        let recipient_pointers = recipients
            .iter()
            .map(CertificateContext::as_ptr)
            .collect::<Vec<_>>();
        let mut parameters = CRYPT_ENCRYPT_MESSAGE_PARA::default();
        parameters.cbSize = std::mem::size_of::<CRYPT_ENCRYPT_MESSAGE_PARA>() as u32;
        parameters.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
        parameters.ContentEncryptionAlgorithm = CRYPT_ALGORITHM_IDENTIFIER {
            pszObjId: content_encryption_oid.as_ptr() as *mut u8,
            ..Default::default()
        };
        let content_length = u32::try_from(content.len()).map_err(|_| {
            crate::signer::SignerError::Encryption(tr!(
                "исходный файл превышает лимит CryptoAPI",
                "the source file exceeds the CryptoAPI limit"
            ))
        })?;
        let recipient_count = u32::try_from(recipient_pointers.len()).map_err(|_| {
            crate::signer::SignerError::Encryption(tr!(
                "слишком много получателей",
                "too many recipients"
            ))
        })?;
        let mut encrypted_length = 0u32;
        let measured = unsafe {
            CryptEncryptMessage(
                &parameters,
                recipient_count,
                recipient_pointers.as_ptr(),
                content.as_ptr(),
                content_length,
                ptr::null_mut(),
                &mut encrypted_length,
            )
        };
        if measured == 0 {
            let code = unsafe { GetLastError() };
            return Err(crate::signer::SignerError::Encryption(tr!(
                "не удалось подготовить CMS EnvelopedData (код Windows 0x{code:08X})",
                "could not prepare CMS EnvelopedData (Windows code 0x{code:08X})"
            )));
        }
        let mut encrypted = vec![0u8; encrypted_length as usize];
        let created = unsafe {
            CryptEncryptMessage(
                &parameters,
                recipient_count,
                recipient_pointers.as_ptr(),
                content.as_ptr(),
                content_length,
                encrypted.as_mut_ptr(),
                &mut encrypted_length,
            )
        };
        if created == 0 {
            let code = unsafe { GetLastError() };
            return Err(crate::signer::SignerError::Encryption(tr!(
                "CryptoAPI не смог создать CMS EnvelopedData (код Windows 0x{code:08X})",
                "CryptoAPI could not create CMS EnvelopedData (Windows code 0x{code:08X})"
            )));
        }
        encrypted.truncate(encrypted_length as usize);
        Ok(encrypted)
    }

    fn decrypt_message(
        store: &CertificateStore,
        encrypted: &[u8],
    ) -> Result<Vec<u8>, crate::signer::SignerError> {
        let mut parameters = CRYPT_DECRYPT_MESSAGE_PARA::default();
        parameters.cbSize = std::mem::size_of::<CRYPT_DECRYPT_MESSAGE_PARA>() as u32;
        parameters.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
        let mut store_handle = store.0;
        parameters.cCertStore = 1;
        parameters.rghCertStore = &mut store_handle;
        let encrypted_length = u32::try_from(encrypted.len()).map_err(|_| {
            crate::signer::SignerError::Decryption(tr!(
                "зашифрованный файл слишком велик для CryptoAPI",
                "the encrypted file is too large for CryptoAPI"
            ))
        })?;
        let mut decrypted_length = 0u32;
        let measured = unsafe {
            CryptDecryptMessage(
                &parameters,
                encrypted.as_ptr(),
                encrypted_length,
                ptr::null_mut(),
                &mut decrypted_length,
                ptr::null_mut(),
            )
        };
        if measured == 0 {
            let code = unsafe { GetLastError() };
            return Err(crate::signer::SignerError::Decryption(tr!(
                "не удалось определить размер расшифрованных данных (код Windows 0x{code:08X})",
                "could not determine the decrypted data size (Windows code 0x{code:08X})"
            )));
        }
        let mut decrypted = vec![0u8; decrypted_length as usize];
        let mut decrypted_cert = ptr::null_mut();
        let decoded = unsafe {
            CryptDecryptMessage(
                &parameters,
                encrypted.as_ptr(),
                encrypted_length,
                decrypted.as_mut_ptr(),
                &mut decrypted_length,
                &mut decrypted_cert,
            )
        };
        if decoded == 0 {
            let code = unsafe { GetLastError() };
            return Err(crate::signer::SignerError::Decryption(tr!(
                "не удалось расшифровать файл (код Windows 0x{code:08X})",
                "could not decrypt the file (Windows code 0x{code:08X})"
            )));
        }
        if !decrypted_cert.is_null() {
            unsafe { CertFreeCertificateContext(decrypted_cert) };
        }
        decrypted.truncate(decrypted_length as usize);
        Ok(decrypted)
    }

    #[derive(Clone, Copy)]
    enum ResultFileKind {
        Encryption,
        Decryption,
    }

    fn write_result(
        output_path: &str,
        output: &[u8],
        kind: ResultFileKind,
    ) -> Result<String, crate::signer::SignerError> {
        let make_error = |message: String| match kind {
            ResultFileKind::Decryption => crate::signer::SignerError::Decryption(message),
            ResultFileKind::Encryption => crate::signer::SignerError::Encryption(message),
        };
        let requested = std::path::PathBuf::from(output_path);
        crate::signer::output::write_unique(&requested, output)
            .map(|path| path.display().to_string())
            .map_err(|error| {
                let message = match kind {
                    ResultFileKind::Encryption => tr!(
                        "не удалось записать файл результата шифрования ({}): {error}",
                        "could not write the encryption result file ({}): {error}",
                        requested.display()
                    ),
                    ResultFileKind::Decryption => tr!(
                        "не удалось записать файл результата расшифрования ({}): {error}",
                        "could not write the decryption result file ({}): {error}",
                        requested.display()
                    ),
                };
                make_error(message)
            })
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

use crate::tr;

pub fn probe() -> crate::signer::CspStatus {
    // CryptoPro documents 75/80/81 for GOST 2001, GOST 2012-256 and 2012-512.
    // CRYPT_VERIFYCONTEXT checks provider initialization without opening keys.
    let mut last_error = 0;
    let mut csp_version = None;
    let mut selected = None;
    for provider_type in [80, 81, 75] {
        match ffi::acquire_provider(provider_type) {
            Ok(provider) => {
                csp_version = ffi::provider_version(&provider);
                selected = Some((provider_type, provider));
                break;
            }
            Err(code) => last_error = code,
        }
    }

    if let Some((provider_type, context)) = selected {
        // Лицензия спрашивается у открытого провайдера: проверка не открывает ключи.
        let license_available = ffi::provider_has_license(&context);
        drop(context);
        let library_present = cades_library_present();
        let cades_result = if library_present {
            super::cadescom::probe()
        } else {
            Err(tr!("CAdESCOM DLL не найдена", "CAdESCOM DLL not found"))
        };
        let cades_available = cades_result.is_ok();
        let license = if license_available {
            tr!("лицензия действительна", "the license is valid")
        } else {
            tr!(
                "действующая лицензия не найдена, подпись может быть недоступна",
                "no valid license was found, signing may be unavailable"
            )
        };
        let cades = if cades_available {
            tr!(
                "CMS/PKCS#7 и CAdES-BES доступны",
                "CMS/PKCS#7 and CAdES-BES are available"
            )
        } else if library_present {
            tr!(
                "CAdESCOM не активировался; доступна CMS/PKCS#7",
                "CAdESCOM did not activate; CMS/PKCS#7 is available"
            )
        } else {
            tr!(
                "CAdES-библиотека x64 не найдена; доступна CMS/PKCS#7",
                "the x64 CAdES library was not found; CMS/PKCS#7 is available"
            )
        };
        crate::signer::CspStatus {
            available: true,
            cades_available,
            // Отсутствие лицензии в хранилище не блокирует подпись: лицензия может быть
            // встроена в носитель ключа, а окончательную проверку даёт сама операция подписи.
            signing_available: true,
            license_available,
            provider_type: Some(provider_type),
            version: csp_version,
            message: tr!(
                "КриптоПро CSP обнаружен: {license}. {cades}.",
                "CryptoPro CSP detected: {license}. {cades}."
            ),
        }
    } else {
        crate::signer::CspStatus::unavailable(tr!(
            "Не удалось открыть провайдеры Crypto-Pro CSP типов 80, 81 или 75 (код Windows 0x{last_error:08X}).",
            "Could not open CryptoPro CSP providers of type 80, 81, or 75 (Windows code 0x{last_error:08X})."
        ))
    }
}

pub fn list_certificates() -> Result<Vec<crate::signer::CertInfo>, crate::signer::SignerError> {
    ffi::list_personal_certificates()
}

/// Подпись подписываемого диапазона PDF.
///
/// Возвращает CMS CAdES-BES (DER) над байтами диапазона: тот же путь, что описан в
/// документации КриптоПро для встроенной подписи PDF (`SimplifiedSignHashCades.cpp`):
/// хэш диапазона вычисляет CSP, затем CMS формируется по этому хэшу.
pub fn sign_pdf_range(
    certificate_id: &str,
    content: &[u8],
) -> Result<Vec<u8>, crate::signer::SignerError> {
    ffi::sign_pdf_range(certificate_id, content)
}

/// OID открытого ключа выбранного сертификата — им выбирается алгоритм хэша для PDF.
pub fn pdf_certificate_public_key_oid(
    certificate_id: &str,
) -> Result<Vec<u8>, crate::signer::SignerError> {
    ffi::pdf_certificate_public_key_oid(certificate_id)
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

pub fn encrypt_file(
    request: crate::signer::EncryptRequest,
) -> Result<crate::signer::EncryptResult, crate::signer::SignerError> {
    ffi::encrypt_cms(request)
}

pub fn decrypt_file(
    request: crate::signer::DecryptRequest,
) -> Result<crate::signer::DecryptResult, crate::signer::SignerError> {
    ffi::decrypt_cms(request)
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
