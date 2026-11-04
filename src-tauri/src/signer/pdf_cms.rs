#![deny(unsafe_code)]
//! Проверка CEK / работы с ключами и шифрование/расшифрование (платформенно-независимая часть).

use crate::signer::SignerError;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::{Decode, Encode};

/// Достаёт CMS SignedData из `/Contents` подписи PDF.
///
/// В поле пишется `ContentInfo ::= SEQUENCE { contentType id-signedData, content [0] EXPLICIT SignedData }`,
/// после ASN.1-длины идут нули-заполнители: DER-декодер читает ровно объявленную длину.
pub fn decode_signature(contents: &[u8]) -> Result<Vec<u8>, SignerError> {
    // Пропускаем нулевой заполнитель в начале, если CMS вдруг начинается не с первого байта.
    let start = contents
        .iter()
        .position(|byte| *byte != 0)
        .ok_or_else(|| SignerError::Pdf("поле /Contents пусто".to_owned()))?;
    let der = &contents[start..];
    let content_info = ContentInfo::from_der(der)
        .map_err(|error| SignerError::Pdf(format!("не удалось разобрать CMS подписи: {error}")))?;
    if content_info.content_type.to_string() != "1.2.840.113549.1.7.2" {
        return Err(SignerError::Pdf(
            "поле /Contents подписи содержит не SignedData".to_owned(),
        ));
    }
    let signed_data: SignedData = content_info
        .content
        .decode_as()
        .map_err(|error| SignerError::Pdf(format!("не удалось разобрать SignedData: {error}")))?;
    Ok(signed_data.to_der().map_err(|error| {
        SignerError::Pdf(format!("не удалось перекодировать SignedData: {error}"))
    })?)
}