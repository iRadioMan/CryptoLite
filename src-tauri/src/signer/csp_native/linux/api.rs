#![allow(unsafe_code)]
#![allow(non_snake_case)]

//! Загрузка CryptoAPI 2.0 КриптоПро CSP на Linux.
//!
//! КриптоПро CSP для Linux экспортирует те же `Cert*`/`Crypt*` функции, что Windows,
//! но библиотеки загружаются через `dlopen` (`libcapi20.so`, `libcapi10.so`).
//! ANSI-функции (`CertOpenSystemStoreA`, `CertGetNameStringA`, `CryptAcquireContextA`)
//! принимают UTF-8, поэтому строки конвертируются только в `CString`.
//!
//! Структуры и константы повторяют определения `windows-sys` (`Win32::Security::Cryptography`):
//! вызовы идут в те же функции с той же раскладкой памяти.

use crate::signer::SignerError;
use crate::tr;
use std::ffi::{c_char, c_void, CStr, CString};
use std::ptr;
use std::sync::LazyLock;

pub(super) type Bool = i32;
pub(super) type HStore = *mut c_void;
pub(super) type HProv = usize;
pub(super) type HKey = usize;
pub(super) type HMsg = usize;
pub(super) type CertContextPtr = *const CERT_CONTEXT;

// ---------------------------------------------------------------------------
// Кодировки
// ---------------------------------------------------------------------------

pub(super) const X509_ASN_ENCODING: u32 = 1;
pub(super) const PKCS_7_ASN_ENCODING: u32 = 0x0001_0000;

// ---------------------------------------------------------------------------
// Хранилища и свойства сертификатов
// ---------------------------------------------------------------------------

pub(super) const CERT_KEY_PROV_INFO_PROP_ID: u32 = 2;
pub(super) const CERT_NAME_ISSUER_FLAG: u32 = 1;
pub(super) const CERT_NAME_SIMPLE_DISPLAY_TYPE: u32 = 4;
pub(super) const CERT_SYSTEM_STORE_CURRENT_USER: u32 = 0x0001_0000;
/// `CERT_STORE_PROV_SYSTEM_A`: имя провайдера хранилища передаётся указателем-константой.
pub(super) const CERT_STORE_PROV_SYSTEM_A: *const c_char = 9usize as *const c_char;

// ---------------------------------------------------------------------------
// Провайдеры и ключи
// ---------------------------------------------------------------------------

pub(super) const AT_KEYEXCHANGE: u32 = 1;
pub(super) const AT_SIGNATURE: u32 = 2;
pub(super) const CRYPT_VERIFYCONTEXT: u32 = 0xF000_0000;
pub(super) const CRYPT_SILENT: u32 = 0x0000_0040;
pub(super) const CRYPT_FIRST: u32 = 0x0000_0001;
pub(super) const CRYPT_NEXT: u32 = 0x0000_0002;
/// `CRYPT_FQCN`: полное имя контейнера (`\\.\<считыватель>\<контейнер>`).
pub(super) const CRYPT_FQCN: u32 = 0x0000_0010;

pub(super) const PP_ENUMCONTAINERS: u32 = 2;
pub(super) const PP_NAME: u32 = 4;
pub(super) const PP_VERSION: u32 = 5;
pub(super) const PP_USER_CERTSTORE: u32 = 42;
/// `PP_LICENSE` из `WinCryptEx.h`: состояние лицензии установленного КриптоПро CSP.
pub(super) const PP_LICENSE: u32 = 158;
/// `KP_CERTIFICATE`: сертификат открытого ключа контейнера.
pub(super) const KP_CERTIFICATE: u32 = 26;

// ---------------------------------------------------------------------------
// CMS
// ---------------------------------------------------------------------------

pub(super) const CMSG_SIGNED: u32 = 2;
pub(super) const CMSG_CONTENT_PARAM: u32 = 2;
pub(super) const CMSG_DETACHED_FLAG: u32 = 4;

// ---------------------------------------------------------------------------
// Цепочка сертификатов и отзыв
// ---------------------------------------------------------------------------

pub(super) const CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL: u32 = 0x0000_0004;
pub(super) const CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT: u32 = 0x0800_0000;
pub(super) const CERT_CHAIN_REVOCATION_CHECK_CHAIN: u32 = 0x2000_0000;
pub(super) const CERT_CHAIN_POLICY_BASE: *const c_char = 1usize as *const c_char;
pub(super) const CERT_TRUST_IS_REVOKED: u32 = 0x0000_0004;
pub(super) const CERT_TRUST_REVOCATION_STATUS_UNKNOWN: u32 = 0x0000_0040;
pub(super) const CERT_TRUST_IS_OFFLINE_REVOCATION: u32 = 0x0100_0000;
/// `CRYPT_E_REVOCATION_OFFLINE`.
pub(super) const CRYPT_E_REVOCATION_OFFLINE: u32 = 0x8009_2013;
/// `CRYPT_E_NO_REVOCATION_CHECK`.
pub(super) const CRYPT_E_NO_REVOCATION_CHECK: u32 = 0x8009_2012;

pub(super) const ERROR_MORE_DATA: u32 = 234;
pub(super) const ERROR_NO_MORE_ITEMS: u32 = 259;

// ---------------------------------------------------------------------------
// Структуры CryptoAPI
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct FILETIME {
    pub dwLowDateTime: u32,
    pub dwHighDateTime: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CRYPT_INTEGER_BLOB {
    pub cbData: u32,
    pub pbData: *mut u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CRYPT_BIT_BLOB {
    pub cbData: u32,
    pub pbData: *mut u8,
    pub cUnusedBits: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CRYPT_ALGORITHM_IDENTIFIER {
    pub pszObjId: *mut c_char,
    pub Parameters: CRYPT_INTEGER_BLOB,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CERT_EXTENSION {
    pub pszObjId: *mut c_char,
    pub fCritical: Bool,
    pub Value: CRYPT_INTEGER_BLOB,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CERT_PUBLIC_KEY_INFO {
    pub Algorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub PublicKey: CRYPT_BIT_BLOB,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CERT_INFO {
    pub dwVersion: u32,
    pub SerialNumber: CRYPT_INTEGER_BLOB,
    pub SignatureAlgorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub Issuer: CRYPT_INTEGER_BLOB,
    pub NotBefore: FILETIME,
    pub NotAfter: FILETIME,
    pub Subject: CRYPT_INTEGER_BLOB,
    pub SubjectPublicKeyInfo: CERT_PUBLIC_KEY_INFO,
    pub IssuerUniqueId: CRYPT_BIT_BLOB,
    pub SubjectUniqueId: CRYPT_BIT_BLOB,
    pub cExtension: u32,
    pub rgExtension: *mut CERT_EXTENSION,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CERT_CONTEXT {
    pub dwCertEncodingType: u32,
    pub pbCertEncoded: *mut u8,
    pub cbCertEncoded: u32,
    pub pCertInfo: *mut CERT_INFO,
    pub hCertStore: HStore,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CRYPT_KEY_PROV_PARAM {
    pub dwParam: u32,
    pub pbData: *mut u8,
    pub cbData: u32,
    pub dwFlags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CRYPT_KEY_PROV_INFO {
    pub pwszContainerName: *mut u16,
    pub pwszProvName: *mut u16,
    pub dwProvType: u32,
    pub dwFlags: u32,
    pub cProvParam: u32,
    pub rgProvParam: *mut CRYPT_KEY_PROV_PARAM,
    pub dwKeySpec: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) union CMSG_SIGNER_ENCODE_INFO_0 {
    pub hCryptProv: HProv,
    pub hNCryptKey: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CMSG_SIGNER_ENCODE_INFO {
    pub cbSize: u32,
    pub pCertInfo: *mut CERT_INFO,
    pub Anonymous: CMSG_SIGNER_ENCODE_INFO_0,
    pub dwKeySpec: u32,
    pub HashAlgorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub pvHashAuxInfo: *mut c_void,
    pub cAuthAttr: u32,
    pub rgAuthAttr: *mut c_void,
    pub cUnauthAttr: u32,
    pub rgUnauthAttr: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CMSG_SIGNED_ENCODE_INFO {
    pub cbSize: u32,
    pub cSigners: u32,
    pub rgSigners: *mut CMSG_SIGNER_ENCODE_INFO,
    pub cCertEncoded: u32,
    pub rgCertEncoded: *mut CRYPT_INTEGER_BLOB,
    pub cCrlEncoded: u32,
    pub rgCrlEncoded: *mut CRYPT_INTEGER_BLOB,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CRYPT_VERIFY_MESSAGE_PARA {
    pub cbSize: u32,
    pub dwMsgAndCertEncodingType: u32,
    pub hCryptProv: usize,
    pub pfnGetSignerCertificate: *mut c_void,
    pub pvGetArg: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CRYPT_ENCRYPT_MESSAGE_PARA {
    pub cbSize: u32,
    pub dwMsgEncodingType: u32,
    pub hCryptProv: usize,
    pub ContentEncryptionAlgorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub pvEncryptionAuxInfo: *mut c_void,
    pub dwFlags: u32,
    pub dwInnerContentType: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CRYPT_DECRYPT_MESSAGE_PARA {
    pub cbSize: u32,
    pub dwMsgAndCertEncodingType: u32,
    pub cCertStore: u32,
    pub rghCertStore: *mut HStore,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CTL_USAGE {
    pub cUsageIdentifier: u32,
    pub rgpszUsageIdentifier: *mut *mut c_char,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CERT_USAGE_MATCH {
    pub dwType: u32,
    pub Usage: CTL_USAGE,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CERT_CHAIN_PARA {
    pub cbSize: u32,
    pub RequestedUsage: CERT_USAGE_MATCH,
    pub RequestedIssuancePolicy: CERT_USAGE_MATCH,
    pub dwUrlRetrievalTimeout: u32,
    pub fCheckRevocationFreshnessTime: Bool,
    pub dwRevocationFreshnessTime: u32,
    pub pftCacheResync: *mut FILETIME,
    pub pStrongSignPara: *mut c_void,
    pub dwStrongSignFlags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CERT_TRUST_STATUS {
    pub dwErrorStatus: u32,
    pub dwInfoStatus: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CRL_ENTRY {
    pub SerialNumber: CRYPT_INTEGER_BLOB,
    pub RevocationDate: FILETIME,
    pub cExtension: u32,
    pub rgExtension: *mut CERT_EXTENSION,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CRL_INFO {
    pub dwVersion: u32,
    pub SignatureAlgorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub Issuer: CRYPT_INTEGER_BLOB,
    pub ThisUpdate: FILETIME,
    pub NextUpdate: FILETIME,
    pub cCRLEntry: u32,
    pub rgCRLEntry: *mut CRL_ENTRY,
    pub cExtension: u32,
    pub rgExtension: *mut CERT_EXTENSION,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CRL_CONTEXT {
    pub dwCertEncodingType: u32,
    pub pbCrlEncoded: *mut u8,
    pub cbCrlEncoded: u32,
    pub pCrlInfo: *mut CRL_INFO,
    pub hCertStore: HStore,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CERT_REVOCATION_CRL_INFO {
    pub cbSize: u32,
    pub pBaseCrlContext: *mut CRL_CONTEXT,
    pub pDeltaCrlContext: *mut CRL_CONTEXT,
    pub pCrlEntry: *mut CRL_ENTRY,
    pub fDeltaCrlEntry: Bool,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CERT_REVOCATION_INFO {
    pub cbSize: u32,
    pub dwRevocationResult: u32,
    pub pszRevocationOid: *const c_char,
    pub pvOidSpecificInfo: *mut c_void,
    pub fHasFreshnessTime: Bool,
    pub dwFreshnessTime: u32,
    pub pCrlInfo: *mut CERT_REVOCATION_CRL_INFO,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CERT_CHAIN_ELEMENT {
    pub cbSize: u32,
    pub pCertContext: *const CERT_CONTEXT,
    pub TrustStatus: CERT_TRUST_STATUS,
    pub pRevocationInfo: *mut CERT_REVOCATION_INFO,
    pub pIssuanceUsage: *mut CTL_USAGE,
    pub pApplicationUsage: *mut CTL_USAGE,
    pub pwszExtendedErrorInfo: *const u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CERT_SIMPLE_CHAIN {
    pub cbSize: u32,
    pub TrustStatus: CERT_TRUST_STATUS,
    pub cElement: u32,
    pub rgpElement: *mut *mut CERT_CHAIN_ELEMENT,
    pub pTrustListInfo: *mut c_void,
    pub fHasRevocationFreshnessTime: Bool,
    pub dwRevocationFreshnessTime: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct GUID {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CERT_CHAIN_CONTEXT {
    pub cbSize: u32,
    pub TrustStatus: CERT_TRUST_STATUS,
    pub cChain: u32,
    pub rgpChain: *mut *mut CERT_SIMPLE_CHAIN,
    pub cLowerQualityChainContext: u32,
    pub rgpLowerQualityChainContext: *mut *mut CERT_CHAIN_CONTEXT,
    pub fHasRevocationFreshnessTime: Bool,
    pub dwRevocationFreshnessTime: u32,
    pub dwCreateFlags: u32,
    pub ChainId: GUID,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CERT_CHAIN_POLICY_PARA {
    pub cbSize: u32,
    pub dwFlags: u32,
    pub pvExtraPolicyPara: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CERT_CHAIN_POLICY_STATUS {
    pub cbSize: u32,
    pub dwError: u32,
    pub lChainIndex: i32,
    pub lElementIndex: i32,
    pub pvExtraPolicyStatus: *mut c_void,
}

macro_rules! zeroed_default {
    ($($name:ident),* $(,)?) => {
        $(impl Default for $name {
            fn default() -> Self {
                // SAFETY: структуры CryptoAPI состоят из целых чисел и указателей,
                // для которых нулевое значение корректно (так же поступает windows-sys).
                unsafe { std::mem::zeroed() }
            }
        })*
    };
}

zeroed_default!(
    CRYPT_ALGORITHM_IDENTIFIER,
    CRYPT_INTEGER_BLOB,
    CRYPT_VERIFY_MESSAGE_PARA,
    CRYPT_ENCRYPT_MESSAGE_PARA,
    CRYPT_DECRYPT_MESSAGE_PARA,
    CERT_CHAIN_PARA,
    CERT_CHAIN_POLICY_PARA,
    CERT_CHAIN_POLICY_STATUS,
);

// ---------------------------------------------------------------------------
// Кодировки строк
// ---------------------------------------------------------------------------

/// Верхняя половина Windows-1251.
///
/// ANSI-функции КриптоПро на Linux отдают и принимают байты в cp1251 (проверено на стенде:
/// `CertGetNameStringA` возвращает `ccd3cdc8...` = «МУНИЦИПАЛЬНОЕ»), поэтому строки
/// перекодируются явно: в UTF-32 через wide-функции и в cp1251 там, где A-функция
/// неизбежна (`PP_ENUMCONTAINERS`, `CryptAcquireContextA`).
const CP1251_HIGH: [char; 128] = [
    '\u{0402}', '\u{0403}', '\u{201a}', '\u{0453}', '\u{201e}', '\u{2026}', '\u{2020}', '\u{2021}',
    '\u{20ac}', '\u{2030}', '\u{0409}', '\u{2039}', '\u{040a}', '\u{040c}', '\u{040b}', '\u{040f}',
    '\u{0452}', '\u{2018}', '\u{2019}', '\u{201c}', '\u{201d}', '\u{2022}', '\u{2013}', '\u{2014}',
    '\u{0098}', '\u{2122}', '\u{0459}', '\u{203a}', '\u{045a}', '\u{045c}', '\u{045b}', '\u{045f}',
    '\u{00a0}', '\u{040e}', '\u{045e}', '\u{0408}', '\u{00a4}', '\u{0490}', '\u{00a6}', '\u{00a7}',
    '\u{0401}', '\u{00a9}', '\u{0404}', '\u{00ab}', '\u{00ac}', '\u{00ad}', '\u{00ae}', '\u{0407}',
    '\u{00b0}', '\u{00b1}', '\u{0406}', '\u{0456}', '\u{0491}', '\u{00b5}', '\u{00b6}', '\u{00b7}',
    '\u{0451}', '\u{2116}', '\u{0454}', '\u{00bb}', '\u{0458}', '\u{0405}', '\u{0455}', '\u{0457}',
    '\u{0410}', '\u{0411}', '\u{0412}', '\u{0413}', '\u{0414}', '\u{0415}', '\u{0416}', '\u{0417}',
    '\u{0418}', '\u{0419}', '\u{041a}', '\u{041b}', '\u{041c}', '\u{041d}', '\u{041e}', '\u{041f}',
    '\u{0420}', '\u{0421}', '\u{0422}', '\u{0423}', '\u{0424}', '\u{0425}', '\u{0426}', '\u{0427}',
    '\u{0428}', '\u{0429}', '\u{042a}', '\u{042b}', '\u{042c}', '\u{042d}', '\u{042e}', '\u{042f}',
    '\u{0430}', '\u{0431}', '\u{0432}', '\u{0433}', '\u{0434}', '\u{0435}', '\u{0436}', '\u{0437}',
    '\u{0438}', '\u{0439}', '\u{043a}', '\u{043b}', '\u{043c}', '\u{043d}', '\u{043e}', '\u{043f}',
    '\u{0440}', '\u{0441}', '\u{0442}', '\u{0443}', '\u{0444}', '\u{0445}', '\u{0446}', '\u{0447}',
    '\u{0448}', '\u{0449}', '\u{044a}', '\u{044b}', '\u{044c}', '\u{044d}', '\u{044e}', '\u{044f}',
];

/// ANSI-строка КриптоПро (cp1251) в Unicode.
pub(super) fn from_ansi(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len());
    for byte in bytes {
        match byte {
            0..=0x7f => text.push(*byte as char),
            _ => text.push(CP1251_HIGH[(byte - 0x80) as usize]),
        }
    }
    text
}

/// Unicode-строка в байты cp1251 — для A-функций КриптоПро.
pub(super) fn ansi_bytes(value: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(value.len());
    for character in value.chars() {
        let code = character as u32;
        if code < 0x80 {
            bytes.push(code as u8);
            continue;
        }
        match CP1251_HIGH.iter().position(|mapped| *mapped == character) {
            Some(index) => bytes.push(0x80 + index as u8),
            None => bytes.push(b'?'),
        }
    }
    bytes
}

// ---------------------------------------------------------------------------
// Загрузчик библиотек
// ---------------------------------------------------------------------------

/// Ошибка загрузки: сообщается один раз, дальше переиспользуется из `OnceLock`.
enum LoadError {
    Missing(String),
    Symbol { library: String, details: String },
}

impl LoadError {
    fn into_signer_error(&self) -> SignerError {
        match self {
            Self::Missing(library) => SignerError::MissingLibrary(library.clone()),
            Self::Symbol { library, details } => SignerError::LoadFailure {
                library: library.clone(),
                details: details.clone(),
            },
        }
    }
}

pub(super) struct Api {
    // libcapi10: провайдеры и ключи
    pub crypt_acquire_context: unsafe extern "C" fn(*mut HProv, *const c_char, *const c_char, u32, u32) -> Bool,
    pub crypt_release_context: unsafe extern "C" fn(HProv, u32) -> Bool,
    pub crypt_get_prov_param: unsafe extern "C" fn(HProv, u32, *mut u8, *mut u32, u32) -> Bool,
    pub crypt_get_user_key: unsafe extern "C" fn(HProv, u32, *mut HKey) -> Bool,
    pub crypt_get_key_param: unsafe extern "C" fn(HKey, u32, *mut u8, *mut u32, u32) -> Bool,
    pub crypt_destroy_key: unsafe extern "C" fn(HKey) -> Bool,
    // libcapi20: хранилища, сертификаты, CMS
    pub cert_open_system_store: unsafe extern "C" fn(usize, *const c_char) -> HStore,
    pub cert_open_store:
        unsafe extern "C" fn(*const c_char, u32, usize, u32, *const c_void) -> HStore,
    pub cert_close_store: unsafe extern "C" fn(HStore, u32) -> Bool,
    pub cert_enum_certificates_in_store:
        unsafe extern "C" fn(HStore, CertContextPtr) -> *mut CERT_CONTEXT,
    pub cert_free_certificate_context: unsafe extern "C" fn(CertContextPtr) -> Bool,
    pub cert_duplicate_certificate_context: unsafe extern "C" fn(CertContextPtr) -> *mut CERT_CONTEXT,
    pub cert_create_certificate_context:
        unsafe extern "C" fn(u32, *const u8, u32) -> *mut CERT_CONTEXT,
    pub cert_get_certificate_context_property:
        unsafe extern "C" fn(CertContextPtr, u32, *mut c_void, *mut u32) -> Bool,
    /// `CertGetNameStringW`: на Linux отдаёт UTF-32 (`wchar_t` в 4 байта).
    pub cert_get_name_string_w:
        Option<unsafe extern "C" fn(CertContextPtr, u32, u32, *mut c_void, *mut u32, u32) -> u32>,
    /// `CertGetNameStringA`: резерв для сборок CSP без wide-варианта, отдаёт cp1251.
    pub cert_get_name_string_a:
        Option<unsafe extern "C" fn(CertContextPtr, u32, u32, *mut c_void, *mut c_char, u32) -> u32>,
    pub cert_get_certificate_chain: unsafe extern "C" fn(
        usize,
        CertContextPtr,
        *const FILETIME,
        HStore,
        *const CERT_CHAIN_PARA,
        u32,
        *mut c_void,
        *mut *mut CERT_CHAIN_CONTEXT,
    ) -> Bool,
    pub cert_free_certificate_chain: unsafe extern "C" fn(*mut CERT_CHAIN_CONTEXT),
    pub cert_verify_certificate_chain_policy: unsafe extern "C" fn(
        *const c_char,
        *const CERT_CHAIN_CONTEXT,
        *const CERT_CHAIN_POLICY_PARA,
        *mut CERT_CHAIN_POLICY_STATUS,
    ) -> Bool,
    pub crypt_acquire_certificate_private_key: unsafe extern "C" fn(
        CertContextPtr,
        u32,
        *mut c_void,
        *mut HProv,
        *mut u32,
        *mut Bool,
    ) -> Bool,
    pub crypt_msg_open_to_encode:
        unsafe extern "C" fn(u32, u32, u32, *const c_void, *const c_char, *mut c_void) -> HMsg,
    pub crypt_msg_update: unsafe extern "C" fn(HMsg, *const u8, u32, Bool) -> Bool,
    pub crypt_msg_get_param: unsafe extern "C" fn(HMsg, u32, u32, *mut c_void, *mut u32) -> Bool,
    pub crypt_msg_close: unsafe extern "C" fn(HMsg) -> Bool,
    pub crypt_get_message_signer_count: unsafe extern "C" fn(u32, *const u8, u32) -> i32,
    pub crypt_verify_message_signature: unsafe extern "C" fn(
        *const CRYPT_VERIFY_MESSAGE_PARA,
        u32,
        *const u8,
        u32,
        *mut u8,
        *mut u32,
        *mut *mut CERT_CONTEXT,
    ) -> Bool,
    pub crypt_verify_detached_message_signature: unsafe extern "C" fn(
        *const CRYPT_VERIFY_MESSAGE_PARA,
        u32,
        *const u8,
        u32,
        u32,
        *const *const u8,
        *const u32,
        *mut *mut CERT_CONTEXT,
    ) -> Bool,
    pub crypt_encrypt_message: unsafe extern "C" fn(
        *const CRYPT_ENCRYPT_MESSAGE_PARA,
        u32,
        *const *const CERT_CONTEXT,
        *const u8,
        u32,
        *mut u8,
        *mut u32,
    ) -> Bool,
    pub crypt_decrypt_message: unsafe extern "C" fn(
        *const CRYPT_DECRYPT_MESSAGE_PARA,
        *const u8,
        u32,
        *mut u8,
        *mut u32,
        *mut *mut CERT_CONTEXT,
    ) -> Bool,
    /// `GetLastError` из `librdrsup.so`: без неё код ошибки берётся из `errno`.
    pub get_last_error: Option<unsafe extern "C" fn() -> u32>,
    // Библиотеки должны жить столько же, сколько указатели на их функции.
    _capi20: libloading::Library,
    _capi10: libloading::Library,
    _rdrsup: Option<libloading::Library>,
}

impl Api {
    fn load() -> Result<Self, LoadError> {
        let capi20 = load_library(
            &["libcapi20.so.4", "libcapi20.so"],
            "libcapi20.so",
            "CryptoPro CryptoAPI 2.0",
        )?;
        let capi10 = load_library(
            &["libcapi10.so.4", "libcapi10.so"],
            "libcapi10.so",
            "CryptoPro CryptoAPI 1.0",
        )?;
        let rdr = load_optional_library(&["librdrsup.so.4", "librdrsup.so"]);
        let rdr_name = "librdrsup.so";

        let api = Self {
            crypt_acquire_context: unsafe {
                symbol(&capi10, "libcapi10.so", "CryptAcquireContextA")?
            },
            crypt_release_context: unsafe {
                symbol(&capi10, "libcapi10.so", "CryptReleaseContext")?
            },
            crypt_get_prov_param: unsafe {
                symbol(&capi10, "libcapi10.so", "CryptGetProvParam")?
            },
            crypt_get_user_key: unsafe { symbol(&capi10, "libcapi10.so", "CryptGetUserKey")? },
            crypt_get_key_param: unsafe { symbol(&capi10, "libcapi10.so", "CryptGetKeyParam")? },
            crypt_destroy_key: unsafe { symbol(&capi10, "libcapi10.so", "CryptDestroyKey")? },
            cert_open_system_store: unsafe {
                symbol(&capi20, "libcapi20.so", "CertOpenSystemStoreA")?
            },
            cert_open_store: unsafe { symbol(&capi20, "libcapi20.so", "CertOpenStore")? },
            cert_close_store: unsafe { symbol(&capi20, "libcapi20.so", "CertCloseStore")? },
            cert_enum_certificates_in_store: unsafe {
                symbol(&capi20, "libcapi20.so", "CertEnumCertificatesInStore")?
            },
            cert_free_certificate_context: unsafe {
                symbol(&capi20, "libcapi20.so", "CertFreeCertificateContext")?
            },
            cert_duplicate_certificate_context: unsafe {
                symbol(&capi20, "libcapi20.so", "CertDuplicateCertificateContext")?
            },
            cert_create_certificate_context: unsafe {
                symbol(&capi20, "libcapi20.so", "CertCreateCertificateContext")?
            },
            cert_get_certificate_context_property: unsafe {
                symbol(&capi20, "libcapi20.so", "CertGetCertificateContextProperty")?
            },
            cert_get_name_string_w: unsafe {
                symbol(&capi20, "libcapi20.so", "CertGetNameStringW").ok()
            },
            cert_get_name_string_a: unsafe {
                symbol(&capi20, "libcapi20.so", "CertGetNameStringA").ok()
            },
            cert_get_certificate_chain: unsafe {
                symbol(&capi20, "libcapi20.so", "CertGetCertificateChain")?
            },
            cert_free_certificate_chain: unsafe {
                symbol(&capi20, "libcapi20.so", "CertFreeCertificateChain")?
            },
            cert_verify_certificate_chain_policy: unsafe {
                symbol(&capi20, "libcapi20.so", "CertVerifyCertificateChainPolicy")?
            },
            crypt_acquire_certificate_private_key: unsafe {
                symbol(&capi20, "libcapi20.so", "CryptAcquireCertificatePrivateKey")?
            },
            crypt_msg_open_to_encode: unsafe {
                symbol(&capi20, "libcapi20.so", "CryptMsgOpenToEncode")?
            },
            crypt_msg_update: unsafe { symbol(&capi20, "libcapi20.so", "CryptMsgUpdate")? },
            crypt_msg_get_param: unsafe { symbol(&capi20, "libcapi20.so", "CryptMsgGetParam")? },
            crypt_msg_close: unsafe { symbol(&capi20, "libcapi20.so", "CryptMsgClose")? },
            crypt_get_message_signer_count: unsafe {
                symbol(&capi20, "libcapi20.so", "CryptGetMessageSignerCount")?
            },
            crypt_verify_message_signature: unsafe {
                symbol(&capi20, "libcapi20.so", "CryptVerifyMessageSignature")?
            },
            crypt_verify_detached_message_signature: unsafe {
                symbol(&capi20, "libcapi20.so", "CryptVerifyDetachedMessageSignature")?
            },
            crypt_encrypt_message: unsafe {
                symbol(&capi20, "libcapi20.so", "CryptEncryptMessage")?
            },
            crypt_decrypt_message: unsafe {
                symbol(&capi20, "libcapi20.so", "CryptDecryptMessage")?
            },
            get_last_error: match &rdr {
                Some(library) => unsafe {
                    symbol::<unsafe extern "C" fn() -> u32>(library, rdr_name, "GetLastError").ok()
                },
                None => None,
            },
            _capi20: capi20,
            _capi10: capi10,
            _rdrsup: rdr,
        };
        Ok(api)
    }
}

static API: LazyLock<Result<Api, LoadError>> = LazyLock::new(Api::load);

/// Загруженный CryptoAPI КриптоПро; библиотеки открываются при первом обращении.
pub(super) fn api() -> Result<&'static Api, SignerError> {
    match &*API {
        Ok(api) => Ok(api),
        Err(error) => Err(error.into_signer_error()),
    }
}

pub(super) fn library_directories() -> Vec<std::path::PathBuf> {
    let mut directories = Vec::new();
    if let Some(directory) = std::env::var_os("CRYPTOLITE_CSP_LIB_DIR") {
        directories.push(std::path::PathBuf::from(directory));
    }
    for directory in [
        "/opt/cprocsp/lib/amd64",
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib64",
        "/usr/lib",
    ] {
        directories.push(std::path::PathBuf::from(directory));
    }
    directories
}

fn find_library(names: &[&str]) -> Option<std::path::PathBuf> {
    let directories = library_directories();
    directories
        .iter()
        .flat_map(|directory| names.iter().map(move |name| directory.join(name)))
        .find(|path| path.is_file())
}

fn load_library(names: &[&str], display: &str, purpose: &str) -> Result<libloading::Library, LoadError> {
    let Some(path) = find_library(names) else {
        let directories = library_directories()
            .iter()
            .map(|directory| directory.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(LoadError::Missing(format!(
            "{display} ({purpose}); {}",
            tr!(
                "проверены каталоги: {directories}",
                "searched directories: {directories}"
            )
        )));
    };
    unsafe { libloading::Library::new(&path) }.map_err(|error| LoadError::Symbol {
        library: display.to_owned(),
        details: tr!(
            "не удалось загрузить {}: {error}",
            "could not load {}: {error}",
            path.display()
        ),
    })
}

fn load_optional_library(names: &[&str]) -> Option<libloading::Library> {
    let path = find_library(names)?;
    unsafe { libloading::Library::new(&path) }.ok()
}

unsafe fn symbol<T: Copy>(
    library: &libloading::Library,
    library_name: &str,
    name: &str,
) -> Result<T, LoadError> {
    match unsafe { library.get::<T>(name.as_bytes()) } {
        Ok(symbol) => Ok(*symbol),
        Err(error) => Err(LoadError::Symbol {
            library: library_name.to_owned(),
            details: format!("{name}: {error}"),
        }),
    }
}

/// Код последней ошибки CryptoAPI.
pub(super) fn last_error(api: &Api) -> u32 {
    match api.get_last_error {
        Some(get_last_error) => unsafe { get_last_error() },
        None => std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32,
    }
}

pub(super) fn cstring(value: &str) -> Result<CString, SignerError> {
    CString::new(value).map_err(|_| {
        SignerError::Signing(tr!(
            "строка содержит нулевой байт: {value}",
            "the string contains a NUL byte: {value}"
        ))
    })
}

// ---------------------------------------------------------------------------
// RAII: провайдер, хранилище, контекст сертификата
// ---------------------------------------------------------------------------

/// Контекст провайдера CSP. `owned` — провайдер нужно освободить самим.
pub(super) struct Provider {
    handle: HProv,
    owned: bool,
}

impl Provider {
    pub(super) fn owned(handle: HProv) -> Self {
        Self { handle, owned: true }
    }

    pub(super) fn borrowed(handle: HProv) -> Self {
        Self {
            handle,
            owned: false,
        }
    }

    pub(super) fn handle(&self) -> HProv {
        self.handle
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        if self.owned {
            if let Ok(api) = api() {
                unsafe { (api.crypt_release_context)(self.handle, 0) };
            }
        }
    }
}

pub(super) struct Store(HStore);

impl Store {
    pub(super) fn from_handle(store: HStore) -> Self {
        Self(store)
    }

    pub(super) fn handle(&self) -> HStore {
        self.0
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        if let Ok(api) = api() {
            unsafe { (api.cert_close_store)(self.0, 0) };
        }
    }
}

/// Контекст сертификата; освобождается при удалении.
pub(super) struct CertContext(CertContextPtr);

impl CertContext {
    pub(super) fn new(context: CertContextPtr) -> Self {
        Self(context)
    }

    pub(super) fn as_ptr(&self) -> CertContextPtr {
        self.0
    }

    /// Независимая копия контекста (`CertDuplicateCertificateContext`).
    pub(super) fn try_clone(&self) -> Option<Self> {
        let api = api().ok()?;
        let duplicate = unsafe { (api.cert_duplicate_certificate_context)(self.0) };
        (!duplicate.is_null()).then(|| Self(duplicate))
    }
}

impl Drop for CertContext {
    fn drop(&mut self) {
        if let Ok(api) = api() {
            unsafe { (api.cert_free_certificate_context)(self.0) };
        }
    }
}

// ---------------------------------------------------------------------------
// Провайдеры
// ---------------------------------------------------------------------------

pub(super) fn acquire_provider(provider_type: u32) -> Result<Provider, u32> {
    let api = api().map_err(|_| 0u32)?;
    let mut handle = 0usize;
    let acquired = unsafe {
        (api.crypt_acquire_context)(
            &mut handle,
            ptr::null(),
            ptr::null(),
            provider_type,
            CRYPT_VERIFYCONTEXT,
        )
    };
    if acquired == 0 {
        Err(last_error(api))
    } else {
        Ok(Provider::owned(handle))
    }
}

/// Открывает контейнер закрытого ключа через указанный провайдер.
///
/// Пустое имя провайдера означает «подобрать по типу»: `CryptAcquireContextA` получает
/// `szProvider = NULL`, как требует запасной путь для токенов.
pub(super) fn open_container(
    container: &str,
    provider_name: &str,
    provider_type: u32,
    flags: u32,
) -> Result<Provider, u32> {
    let api = api().map_err(|_| 0u32)?;
    // A-функция ждёт байты cp1251, а не UTF-8: имя приходит либо из `PP_ENUMCONTAINERS`,
    // либо из wide-свойства сертификата.
    let container = CString::new(ansi_bytes(container)).map_err(|_| 0u32)?;
    let provider_name = if provider_name.is_empty() {
        None
    } else {
        Some(CString::new(ansi_bytes(provider_name)).map_err(|_| 0u32)?)
    };
    let mut handle = 0usize;
    let acquired = unsafe {
        (api.crypt_acquire_context)(
            &mut handle,
            container.as_ptr(),
            provider_name
                .as_ref()
                .map_or(ptr::null(), |name| name.as_ptr()),
            provider_type,
            flags,
        )
    };
    if acquired == 0 {
        Err(last_error(api))
    } else {
        Ok(Provider::owned(handle))
    }
}

pub(super) fn provider_version(provider: &Provider) -> Option<String> {
    let api = api().ok()?;
    let mut version = 0u32;
    let mut length = std::mem::size_of::<u32>() as u32;
    let success = unsafe {
        (api.crypt_get_prov_param)(
            provider.handle(),
            PP_VERSION,
            &mut version as *mut u32 as *mut u8,
            &mut length,
            0,
        )
    };
    (success != 0).then(|| format!("{}.{}", (version >> 8) & 0xff, version & 0xff))
}

/// Есть ли у провайдера действующая лицензия КриптоПро CSP.
///
/// Возвращает `None`, если параметр `PP_LICENSE` не поддерживается этой сборкой CSP:
/// тогда статус лицензии в интерфейсе не показывается, а не считается отсутствующим.
pub(super) fn provider_license(provider: &Provider) -> Option<bool> {
    let api = api().ok()?;
    let mut length = 0u32;
    let sized = unsafe {
        (api.crypt_get_prov_param)(
            provider.handle(),
            PP_LICENSE,
            ptr::null_mut(),
            &mut length,
            0,
        )
    };
    if sized == 0 || length == 0 {
        return None;
    }
    let mut buffer = vec![0u8; length as usize];
    let read = unsafe {
        (api.crypt_get_prov_param)(
            provider.handle(),
            PP_LICENSE,
            buffer.as_mut_ptr(),
            &mut length,
            0,
        )
    };
    if read == 0 {
        return None;
    }
    Some(length > 0)
}

/// Читает параметр провайдера в буфер.
///
/// `pdwDataLen` у перечислимых параметров возвращается равным размеру буфера,
/// поэтому строки разбираются по завершающему нулю, а не по длине.
pub(super) fn provider_param(provider: HProv, param: u32, flags: u32) -> Result<Vec<u8>, u32> {
    const PARAM_BUFFER: usize = 2048;
    let api = api().map_err(|_| 0u32)?;
    let mut capacity = PARAM_BUFFER;
    loop {
        let mut buffer = vec![0u8; capacity];
        let mut length = capacity as u32;
        let read = unsafe {
            (api.crypt_get_prov_param)(provider, param, buffer.as_mut_ptr(), &mut length, flags)
        };
        if read != 0 {
            return Ok(buffer);
        }
        let code = last_error(api);
        let needed = length as usize;
        if code == ERROR_MORE_DATA && needed > capacity {
            capacity = needed;
            continue;
        }
        return Err(code);
    }
}

/// `PP_USER_CERTSTORE` открытого контейнера.
pub(super) fn user_certstore(provider: HProv) -> Option<HStore> {
    let api = api().ok()?;
    let mut store: HStore = ptr::null_mut();
    let mut length = std::mem::size_of::<HStore>() as u32;
    let read = unsafe {
        (api.crypt_get_prov_param)(
            provider,
            PP_USER_CERTSTORE,
            &mut store as *mut HStore as *mut u8,
            &mut length,
            0,
        )
    };
    if read == 0 || store.is_null() {
        None
    } else {
        Some(store)
    }
}

fn container_has_key(provider: HProv, key_spec: u32) -> bool {
    let Ok(api) = api() else {
        return false;
    };
    let mut key = 0usize;
    if unsafe { (api.crypt_get_user_key)(provider, key_spec, &mut key) } == 0 {
        return false;
    }
    unsafe { (api.crypt_destroy_key)(key) };
    true
}

/// Спецификация ключа для подписи: сначала `AT_SIGNATURE`, затем `AT_KEYEXCHANGE`.
pub(super) fn signing_key_spec(provider: HProv) -> Result<u32, SignerError> {
    if container_has_key(provider, AT_SIGNATURE) {
        return Ok(AT_SIGNATURE);
    }
    if container_has_key(provider, AT_KEYEXCHANGE) {
        return Ok(AT_KEYEXCHANGE);
    }
    Err(SignerError::Signing(tr!(
        "в контейнере закрытого ключа не найден ни ключ подписи, ни ключ обмена (код КриптоПро 0x{:08X})",
        "neither a signature key nor an exchange key was found in the private key container (CryptoPro code 0x{:08X})",
        last_error_code()
    )))
}

pub(super) fn last_error_code() -> u32 {
    match api() {
        Ok(api) => last_error(api),
        Err(_) => 0,
    }
}

// ---------------------------------------------------------------------------
// Сертификаты
// ---------------------------------------------------------------------------

/// Открывает личное хранилище текущего пользователя.
///
/// Сначала пробуется системное имя `MY` (в КриптоПро CSP для Linux это `uMy`),
/// затем — хранилище КриптоПро напрямую через `CertOpenStore`.
pub(super) fn open_personal_store() -> Option<Store> {
    let api = api().ok()?;
    unsafe {
        let name = cstring("MY").ok()?;
        let store = (api.cert_open_system_store)(0, name.as_ptr());
        if !store.is_null() {
            return Some(Store::from_handle(store));
        }
        let name = cstring("uMy").ok()?;
        let store = (api.cert_open_store)(
            CERT_STORE_PROV_SYSTEM_A,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_SYSTEM_STORE_CURRENT_USER,
            name.as_ptr() as *const c_void,
        );
        (!store.is_null()).then(|| Store::from_handle(store))
    }
}

pub(super) fn store_error(prefix: String) -> SignerError {
    let code = last_error_code();
    SignerError::CertificateStore(format!(
        "{prefix}: {}",
        tr!(
            "код КриптоПро 0x{code:08X}",
            "CryptoPro code 0x{code:08X}"
        )
    ))
}
/// Ищет сертификат по `id` в хранилище и возвращает владеющий контекст.
///
/// Перечисление освобождает предыдущий контекст, поэтому найденный дублируется
/// и исходный контекст освобождается явно.
pub(super) fn find_certificate(store: &Store, id: &str) -> Result<CertContext, SignerError> {
    let api = api()?;
    let mut previous: CertContextPtr = ptr::null();
    loop {
        let current = unsafe { (api.cert_enum_certificates_in_store)(store.handle(), previous) };
        if current.is_null() {
            break;
        }
        if certificate_id(current).as_deref() == Some(id) {
            // Контекст перечисления освобождается вместе с обёрткой, дубликат живёт дальше.
            let enumerated = CertContext::new(current);
            return enumerated.try_clone().ok_or_else(|| {
                SignerError::Signing(tr!(
                    "не удалось скопировать контекст сертификата (код КриптоПро 0x{:08X})",
                    "could not duplicate the certificate context (CryptoPro code 0x{:08X})",
                    last_error(api)
                ))
            });
        }
        previous = current;
    }
    Err(SignerError::Signing(tr!(
        "выбранный сертификат больше не найден",
        "the selected certificate is no longer present"
    )))
}

/// Имя сертификата для отображения.
///
/// Основной путь — `CertGetNameStringW`: на Linux он отдаёт UTF-32 и переводится в Unicode
/// без таблиц. Сборки CSP без wide-варианта читаются через `CertGetNameStringA`, который
/// возвращает cp1251.
pub(super) fn certificate_name(context: CertContextPtr, issuer: bool) -> String {
    let Ok(api) = api() else {
        return String::new();
    };
    let flags = if issuer { CERT_NAME_ISSUER_FLAG } else { 0 };
    if let Some(get_name) = api.cert_get_name_string_w {
        unsafe {
            let size = get_name(
                context,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                flags,
                ptr::null_mut(),
                ptr::null_mut(),
                0,
            );
            if size <= 1 {
                return String::new();
            }
            let mut buffer = vec![0u32; size as usize];
            let written = get_name(
                context,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                flags,
                ptr::null_mut(),
                buffer.as_mut_ptr(),
                size,
            );
            if written <= 1 {
                return String::new();
            }
            let length = (written as usize - 1).min(buffer.len());
            return buffer[..length]
                .iter()
                .filter_map(|unit| char::from_u32(*unit))
                .collect();
        }
    }
    let Some(get_name) = api.cert_get_name_string_a else {
        return String::new();
    };
    unsafe {
        let size = get_name(
            context,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            flags,
            ptr::null_mut(),
            ptr::null_mut(),
            0,
        );
        if size <= 1 {
            return String::new();
        }
        let mut buffer = vec![0u8; size as usize];
        let written = get_name(
            context,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            flags,
            ptr::null_mut(),
            buffer.as_mut_ptr() as *mut c_char,
            size,
        );
        if written <= 1 {
            return String::new();
        }
        let length = (written as usize - 1).min(buffer.len());
        from_ansi(&buffer[..length])
    }
}

/// Свойство `CERT_KEY_PROV_INFO_PROP_ID` целиком.
pub(super) fn certificate_key_prov_info(context: CertContextPtr) -> Option<Vec<u8>> {
    let api = api().ok()?;
    let mut length = 0u32;
    let sized = unsafe {
        (api.cert_get_certificate_context_property)(
            context,
            CERT_KEY_PROV_INFO_PROP_ID,
            ptr::null_mut(),
            &mut length,
        )
    };
    if sized == 0 || length == 0 {
        return None;
    }
    let mut bytes = vec![0u8; length as usize];
    let read = unsafe {
        (api.cert_get_certificate_context_property)(
            context,
            CERT_KEY_PROV_INFO_PROP_ID,
            bytes.as_mut_ptr() as *mut c_void,
            &mut length,
        )
    };
    if read == 0 {
        return None;
    }
    bytes.truncate(length as usize);
    Some(bytes)
}

pub(super) fn has_private_key_info(context: CertContextPtr) -> bool {
    let Ok(api) = api() else {
        return false;
    };
    let mut length = 0u32;
    unsafe {
        (api.cert_get_certificate_context_property)(
            context,
            CERT_KEY_PROV_INFO_PROP_ID,
            ptr::null_mut(),
            &mut length,
        ) != 0
    }
}

/// Контейнер и провайдер закрытого ключа сертификата из `CRYPT_KEY_PROV_INFO`.
pub(super) struct KeyProvInfo {
    pub container: String,
    pub provider: String,
    pub provider_type: u32,
    pub key_spec: u32,
}

/// Сведения о контейнере закрытого ключа сертификата.
///
/// КриптоПро CSP для Linux собирается с `wchar_t` в 4 байта, поэтому строки читаются
/// с определением ширины символа по первым байтам: имена контейнеров — ASCII,
/// и раскладка `5C 00 5C 00` (`\\.\`) отличается от `5C 00 00 00 5C 00 00 00`.
pub(super) fn certificate_key_prov_names(context: CertContextPtr) -> Option<KeyProvInfo> {
    let bytes = certificate_key_prov_info(context)?;
    if bytes.len() < std::mem::size_of::<CRYPT_KEY_PROV_INFO>() {
        return None;
    }
    let key_info = bytes.as_ptr() as *const CRYPT_KEY_PROV_INFO;
    unsafe {
        let container = wide_string((*key_info).pwszContainerName as *const u8)?;
        let provider =
            wide_string((*key_info).pwszProvName as *const u8).unwrap_or_default();
        Some(KeyProvInfo {
            container,
            provider,
            provider_type: (*key_info).dwProvType,
            key_spec: (*key_info).dwKeySpec,
        })
    }
}

/// Имя контейнера закрытого ключа сертификата, если свойство задано.
pub(super) fn certificate_container(context: CertContextPtr) -> Option<String> {
    certificate_key_prov_names(context).map(|info| info.container)
}

/// Читает NUL-терминированную строку из `wchar_t`-массива шириной 2 или 4 байта.
unsafe fn wide_string(pointer: *const u8) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    let width = unsafe {
        let first = *pointer;
        let second = *pointer.add(1);
        let third = *pointer.add(2);
        let fourth = *pointer.add(3);
        if first != 0 && second == 0 && third == 0 && fourth == 0 {
            4
        } else {
            2
        }
    };
    let mut bytes = Vec::new();
    let mut index = 0usize;
    loop {
        let offset = index * width;
        let unit = match width {
            4 => unsafe { std::ptr::read_unaligned(pointer.add(offset) as *const u32) },
            _ => unsafe { std::ptr::read_unaligned(pointer.add(offset) as *const u16) as u32 },
        };
        if unit == 0 || index > 4096 {
            break;
        }
        let character = char::from_u32(unit).unwrap_or('\u{fffd}');
        let mut buffer = [0u8; 4];
        bytes.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
        index += 1;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// `id` сертификата: издатель и серийный номер в верхнем регистре.
///
/// Формат совпадает с Windows, поэтому идентификаторы, сохранённые в настройках,
/// остаются узнаваемыми.
pub(super) fn certificate_id(context: CertContextPtr) -> Option<String> {
    let info = unsafe { context.as_ref() }?.pCertInfo;
    if info.is_null() {
        return None;
    }
    let info = unsafe { &*info };
    let issuer = certificate_name(context, true);
    let serial = &info.SerialNumber;
    let serial_id = if serial.pbData.is_null() || serial.cbData == 0 {
        format!("fallback:{}", certificate_name(context, false))
    } else {
        unsafe { std::slice::from_raw_parts(serial.pbData, serial.cbData as usize) }
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>()
    };
    Some(format!("{issuer}:{serial_id}"))
}

/// Описание сертификата для списка.
pub(super) fn read_certificate(context: CertContextPtr, source: &str) -> Option<crate::signer::CertInfo> {
    let context_ref = unsafe { context.as_ref() }?;
    let info = unsafe { context_ref.pCertInfo.as_ref() }?;
    let subject = certificate_name(context, false);
    if subject.is_empty() {
        return None;
    }
    let issuer = certificate_name(context, true);
    let expires_at = filetime_to_date(info.NotAfter.dwHighDateTime, info.NotAfter.dwLowDateTime);
    let expired = filetime_is_expired(info.NotAfter.dwHighDateTime, info.NotAfter.dwLowDateTime);
    let has_private_key = has_private_key_info(context);
    let serial = &info.SerialNumber;
    let serial_id = if serial.pbData.is_null() || serial.cbData == 0 {
        format!("fallback:{subject}:{expires_at}")
    } else {
        unsafe { std::slice::from_raw_parts(serial.pbData, serial.cbData as usize) }
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>()
    };
    let id = format!("{issuer}:{serial_id}");
    let not_before = filetime_to_date(info.NotBefore.dwHighDateTime, info.NotBefore.dwLowDateTime);
    let not_after = filetime_to_date(info.NotAfter.dwHighDateTime, info.NotAfter.dwLowDateTime);
    Some(crate::signer::CertInfo {
        id,
        subject: subject.clone(),
        issuer,
        expires_at,
        expired,
        has_private_key,
        source: source.to_owned(),
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

/// OID открытого ключа сертификата.
pub(super) fn certificate_public_key_oid(context: CertContextPtr) -> Option<String> {
    let info = unsafe { context.as_ref() }?.pCertInfo;
    if info.is_null() {
        return None;
    }
    let oid = unsafe { (*info).SubjectPublicKeyInfo.Algorithm.pszObjId };
    if oid.is_null() {
        return None;
    }
    Some(
        unsafe { CStr::from_ptr(oid) }
            .to_string_lossy()
            .into_owned(),
    )
}

/// SERIALNUMBER / DER сертификата.
pub(super) fn certificate_der(context: CertContextPtr) -> Option<Vec<u8>> {
    let context_ref = unsafe { context.as_ref() }?;
    if context_ref.cbCertEncoded == 0 || context_ref.pbCertEncoded.is_null() {
        return None;
    }
    Some(unsafe {
        std::slice::from_raw_parts(context_ref.pbCertEncoded, context_ref.cbCertEncoded as usize)
    }
    .to_vec())
}

/// Разбирает сертификат из DER.
pub(super) fn certificate_from_der(der: &[u8]) -> Result<CertContext, SignerError> {
    let api = api()?;
    let length = u32::try_from(der.len()).map_err(|_| {
        SignerError::Signing(tr!(
            "сертификат слишком велик для CryptoAPI",
            "the certificate is too large for CryptoAPI"
        ))
    })?;
    let context = unsafe { (api.cert_create_certificate_context)(X509_ASN_ENCODING, der.as_ptr(), length) };
    if context.is_null() {
        return Err(SignerError::Signing(tr!(
            "не удалось разобрать сертификат (код КриптоПро 0x{:08X})",
            "could not parse the certificate (CryptoPro code 0x{:08X})",
            last_error(api)
        )));
    }
    Ok(CertContext::new(context))
}

/// Сертификаты личного хранилища с источником по носителю ключа.
pub(super) fn list_personal_certificates(
    tokens: &[super::token::DetectedToken],
) -> Result<Vec<crate::signer::CertInfo>, SignerError> {
    let api = api()?;
    let store = open_personal_store().ok_or_else(|| {
        store_error(tr!(
            "не удалось открыть личное хранилище",
            "could not open the personal store"
        ))
    })?;
    let mut certificates = Vec::new();
    let mut previous: CertContextPtr = ptr::null();
    loop {
        // CertEnumCertificatesInStore освобождает предыдущий контекст.
        let current = unsafe { (api.cert_enum_certificates_in_store)(store.handle(), previous) };
        if current.is_null() {
            break;
        }
        let source = certificate_container(current)
            .and_then(|container| super::token::match_token(&container, tokens))
            .map(|token| super::token::token_source(&token.model))
            .unwrap_or_else(|| {
                tr!("Linux · Личное хранилище", "Linux · Personal store")
            });
        if let Some(certificate) = read_certificate(current, &source) {
            certificates.push(certificate);
        }
        previous = current;
    }
    Ok(certificates)
}

// ---------------------------------------------------------------------------
// Даты
// ---------------------------------------------------------------------------

pub(super) fn filetime_is_expired(high: u32, low: u32) -> bool {
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

pub(super) fn filetime_to_date(high: u32, low: u32) -> String {
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
