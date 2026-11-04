#![deny(unsafe_code)]
//! Параметры подписи PDF по сертификату подписанта.

/// OID хэш-алгоритмов, которые поддерживает встроенная подпись PDF.
pub const HALG_GOST_2012_256: &str = "1.2.643.7.1.1.2.2";
pub const HALG_GOST_2012_512: &str = "1.2.643.7.1.1.2.3";
pub const HALG_GOST_2001: &str = "1.2.643.2.2.9";

/// Алгоритм хэша для подписи по OID открытого ключа сертификата.
///
/// Возвращает пару «CADESCOM_HASH_ALGORITHM / OID алгоритма дайджеста»: подпись формирует
/// CAdESCOM по хэш-значению, а сертификат определяет, какой хэш нужен. Оставлено для
/// CAdESCOM-пути; встроенная подпись PDF подписывает диапазон через CSP
/// ([`crate::signer::csp_native::windows::sign_pdf_range`]).
pub fn hash_for_public_key(public_key_oid: &[u8]) -> Result<(i32, &'static str), String> {
    // Значения перечисления CAdESCOM/CAPICOM: 1 = Стрибог-2012-256, 2 = Стрибог-2012-512.
    const HASH_GOST_2012_256: i32 = 1;
    const HASH_GOST_2012_512: i32 = 2;
    match public_key_oid {
        b"1.2.643.7.1.1.1.1" => Ok((HASH_GOST_2012_256, HALG_GOST_2012_256)),
        b"1.2.643.7.1.1.1.2" => Ok((HASH_GOST_2012_512, HALG_GOST_2012_512)),
        b"1.2.643.2.2.19" => Ok((HASH_GOST_2012_256, HALG_GOST_2001)),
        other => Err(format!(
            "алгоритм открытого ключа {} не поддерживается для встроенной подписи PDF",
            String::from_utf8_lossy(other)
        )),
    }
}

/// Длина дайджеста по OID.
pub fn digest_length(algorithm_oid: &str) -> usize {
    match algorithm_oid {
        HALG_GOST_2012_512 => 64,
        _ => 32,
    }
}