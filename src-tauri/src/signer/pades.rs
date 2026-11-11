#![deny(unsafe_code)]
//! Встроенная подпись PDF (PAdES-BES) с видимой отметкой об ЭП.
//!
//! Криптографию выполняет CryptoPro через Windows CryptoAPI, а этот
//! модуль ведёт последовательность: подготовка поля `/Sig` → подпись диапазона → вписывание CMS.

use crate::signer::csp_native;
use crate::signer::csp_native::windows::digest;
use crate::signer::pdf_layer::{self, PreparedDocument};
use crate::signer::{PageRotation, PdfSignaturePayload, PdfStampSpec, SignResult, SignerError};
use crate::tr;

fn signing_error(message: impl Into<String>) -> SignerError {
    SignerError::Signing(message.into())
}

fn new_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{nanos:x}")
}

/// Восстанавливает подготовленный PDF по пути из результата подготовки.
pub fn restore(prepared_path: &str) -> Result<PreparedDocument, SignerError> {
    let path = std::path::PathBuf::from(prepared_path);
    let bytes = std::fs::read(&path).map_err(|error| {
        signing_error(tr!(
            "не удалось прочитать подготовленный PDF: {error}",
            "could not read the prepared PDF: {error}"
        ))
    })?;
    let (offsets_at, contents_at, contents_end) = pdf_layer::locate(&bytes)?;
    Ok(PreparedDocument {
        path: Some(path),
        page_count: 0,
        digest_algorithm: String::new(),
        bytes,
        offsets_at,
        contents_at,
        contents_end,
    })
}

/// Готовит PDF: в последнюю версию добавляется поле `/Sig` с отметкой.
pub fn prepare(
    input_path: &str,
    certificate_id: &str,
    stamp: &PdfStampSpec,
    page_rotations: &[PageRotation],
) -> Result<PreparedDocument, SignerError> {
    let public_key_oid = csp_native::windows::pdf_certificate_public_key_oid(certificate_id)?;
    let (_, algorithm) = digest::hash_for_public_key(&public_key_oid).map_err(signing_error)?;
    pdf_layer::prepare(
        std::path::Path::new(input_path),
        stamp,
        page_rotations,
        certificate_id,
        algorithm,
        &new_id(),
    )
}

/// Подписывает диапазон PDF сертификатом: CMS CAdES-BES (DER).
///
/// Подписывается содержимое диапазона `/ByteRange`: байты до `<` в `/Contents` и всё после
/// `>` — ровно то, что Acrobat и КриптоАРМ вычисляют для проверки подписи (ISO 32000-1, 7.6.2).
pub fn sign_prepared(
    prepared: &PreparedDocument,
    certificate_id: &str,
) -> Result<PdfSignaturePayload, SignerError> {
    let (document, contents_at, contents_end) = pdf_layer::with_byte_range(&prepared.bytes)?;
    let content = pdf_layer::signed_content(&document, contents_at, contents_end)?;
    let cms = csp_native::windows::sign_pdf_range(certificate_id, &content)?;
    Ok(PdfSignaturePayload {
        cms,
        contents_at: prepared.contents_at,
    })
}

/// Вписывает готовую CMS в `/Contents` и записывает подписанный PDF.
pub fn finish_signed(
    prepared: &PreparedDocument,
    payload: &PdfSignaturePayload,
    output_path: &str,
) -> Result<SignResult, SignerError> {
    pdf_layer::finish(prepared, payload, std::path::Path::new(output_path))
}

/// Один подписант одного PDF: подготовка, подпись и встраивание.
pub fn sign_document(
    input_path: &str,
    output_path: &str,
    certificate_id: &str,
    stamp: &PdfStampSpec,
    page_rotations: &[PageRotation],
) -> Result<SignResult, SignerError> {
    let prepared = prepare(input_path, certificate_id, stamp, page_rotations)?;
    let payload = sign_prepared(&prepared, certificate_id)?;
    finish_signed(&prepared, &payload, output_path)
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;
    use crate::signer::native::{self, NativeSigner};
    use crate::signer::{CertInfo, SignRequest, Signer, VerifyRequest};
    use lopdf::{Dictionary, Document, Object};
    use std::path::{Path, PathBuf};

    fn required_env(name: &str) -> String {
        std::env::var(name).ok().filter(|s| !s.is_empty())
            .unwrap_or_else(|| panic!("required environment variable missing: {name}"))
    }

    fn selected_certificate<'a>(certificates: &'a [CertInfo], serial: &str) -> Result<&'a CertInfo, &'static str> {
        let mut selected = certificates.iter().filter(|cert| cert.serial_number.eq_ignore_ascii_case(serial));
        let certificate = selected.next().ok_or("selected certificate not found")?;
        if selected.next().is_some() {
            return Err("serial must select exactly one certificate");
        }
        // CAdESCOM accepts both byte orders and ignores issuer: fail before any key access.
        let ambiguous = certificates.iter().filter(|cert| {
            let candidate = cert.serial_number.as_bytes();
            cert.serial_number.eq_ignore_ascii_case(serial)
                || (candidate.len() == serial.len() && candidate.len() % 2 == 0
                    && candidate.chunks_exact(2).rev().flatten().zip(serial.bytes())
                        .all(|(a, b)| a.eq_ignore_ascii_case(&b)))
        }).count() != 1;
        if ambiguous {
            return Err("CAdES serial selection is ambiguous across byte orders");
        }
        if !certificate.has_private_key {
            return Err("selected certificate has no private key");
        }
        Ok(certificate)
    }

    struct StagingCleanup(PathBuf);

    impl Drop for StagingCleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn explicit_certificate_selection_rejects_reversed_serial_collision() {
        let cert = |serial: &str| CertInfo {
            id: format!("test:{serial}"), subject: String::new(), issuer: String::new(),
            expires_at: String::new(), expired: false, has_private_key: true,
            source: "synthetic".into(), serial_number: serial.into(),
            not_before: String::new(), not_after: String::new(), owner_name: String::new(),
        };
        let certificates = vec![cert("1234"), cert("3412")];
        assert!(selected_certificate(&certificates, "1234").is_err());
        assert!(selected_certificate(&certificates[..1], "1234").is_ok());
        let palindrome = vec![cert("ABAB")];
        assert!(selected_certificate(&palindrome, "ABAB").is_ok());
        let duplicates = vec![cert("1234"), cert("1234")];
        assert!(selected_certificate(&duplicates, "1234").is_err());
    }

    #[test]
    fn explicit_certificate_selection_accepts_hex_case() {
        let certificate = CertInfo {
            id: "test-issuer:00AB12CD".into(),
            serial_number: "00AB12CD".into(),
            subject: String::new(), issuer: "test-issuer".into(),
            expires_at: String::new(), expired: false, has_private_key: true,
            source: "synthetic".into(), not_before: String::new(),
            not_after: String::new(), owner_name: String::new(),
        };
        let certificates = [certificate];
        let selected = selected_certificate(&certificates, "00ab12cd").unwrap();
        assert_eq!(selected.id, "test-issuer:00AB12CD");
        assert!(selected_certificate(&certificates, "CD12AB00").is_err());
    }

    #[test]
    fn external_staging_is_removed_on_unwind() {
        let path = std::env::temp_dir().join(format!("cryptolite-runner-cleanup-{}", new_id()));
        std::fs::write(&path, b"synthetic staging").unwrap();
        let result = std::panic::catch_unwind(|| {
            let _cleanup = StagingCleanup(path.clone());
            panic!("external signing cancelled");
        });
        let leaked = path.exists();
        if leaked {
            std::fs::remove_file(&path).unwrap();
        }
        assert!(result.is_err());
        assert!(!leaked, "external signing failure leaked staging");
    }

    fn dictionary<'a>(doc: &'a Document, value: &'a Object) -> &'a Dictionary {
        doc.dereference(value).expect("PDF reference").1.as_dict().expect("PDF dictionary")
    }

    // Independent of pdf_layer::trim_der: validate the definite ASN.1 length from the final file.
    fn cms_der(contents: &[u8]) -> &[u8] {
        assert!(contents.len() >= 2 && contents[0] == 0x30, "CMS must be a SEQUENCE");
        let (header, length) = if contents[1] < 0x80 {
            (2, usize::from(contents[1]))
        } else {
            let count = usize::from(contents[1] & 0x7f);
            assert!(count > 0 && count <= std::mem::size_of::<usize>(), "invalid DER length");
            assert!(contents.len() >= 2 + count, "truncated DER header");
            let length = contents[2..2 + count].iter().try_fold(0usize, |n, &b| {
                n.checked_mul(256)?.checked_add(usize::from(b))
            }).expect("DER length overflow");
            (2 + count, length)
        };
        let end = header.checked_add(length).expect("DER length overflow");
        contents.get(..end).expect("truncated DER content")
    }

    fn verify_route(route: &str, pdf: &Path, directory: &Path) {
        let bytes = std::fs::read(pdf).expect("read signed PDF");
        let doc = Document::load_mem(&bytes).expect("parse signed PDF");
        let form = dictionary(&doc, doc.catalog().unwrap().get(b"AcroForm").unwrap());
        let fields = doc.dereference(form.get(b"Fields").unwrap()).unwrap().1.as_array().unwrap();
        let field = dictionary(&doc, fields.last().expect("signature field"));
        let signature = dictionary(&doc, field.get(b"V").unwrap());
        let range = doc.dereference(signature.get(b"ByteRange").unwrap()).unwrap().1.as_array().unwrap();
        assert_eq!(range.len(), 4);
        let range: Vec<usize> = range.iter().map(|v|
            usize::try_from(v.as_i64().expect("integer ByteRange")).expect("nonnegative ByteRange")
        ).collect();
        assert_eq!(range[0], 0);
        assert!(range[1] > 0 && range[3] > 0, "fixture must have two nonempty signed segments");
        assert_eq!(range[2].checked_add(range[3]), Some(bytes.len()));
        assert!(range[2] > range[1]);
        assert_eq!(bytes[range[1]], b'<');
        assert_eq!(bytes[range[2] - 1], b'>');
        let content = [&bytes[..range[1]], &bytes[range[2]..]].concat();
        let contents = signature.get(b"Contents").unwrap().as_str().unwrap();
        let cms = cms_der(contents);
        let content_path = directory.join(format!("{route}-content.bin"));
        let signature_path = directory.join(format!("{route}-signature.der"));
        std::fs::write(&content_path, &content).expect("write extracted content");
        std::fs::write(&signature_path, cms).expect("write extracted CMS");
        let request = |path: &Path| VerifyRequest {
            signature_path: signature_path.to_string_lossy().into_owned(),
            content_path: Some(path.to_string_lossy().into_owned()),
            detached: true, base64: false, check_crl: false,
        };
        let verified = native::verify_signature(request(&content_path))
            .unwrap_or_else(|_| panic!("{route}: verification failed"));
        assert!(verified.valid, "{route}: invalid signature");
        let trusted = verified.signers.iter().all(|signer| signer.chain_trusted);
        println!("{route}: mathematical verification passed; all signer chains trusted={trusted}");
        for (segment, index) in [("prefix", 0), ("suffix", range[1])] {
            let mut tampered = content.clone();
            tampered[index] ^= 1;
            let path = directory.join(format!("{route}-tampered-{segment}.bin"));
            std::fs::write(&path, tampered).expect("write negative control");
            assert!(!matches!(native::verify_signature(request(&path)), Ok(result) if result.valid),
                "{route}: {segment} tamper accepted");
            println!("{route}: {segment} tamper rejected");
        }
    }

    #[test]
    #[ignore = "requires an explicitly selected CryptoPro test certificate"]
    fn real_pdf_signing() {
        let serial = required_env("CRYPTOLITE_TEST_CERT_SERIAL");
        let input = PathBuf::from(required_env("CRYPTOLITE_TEST_PDF"));
        let output = PathBuf::from(required_env("CRYPTOLITE_TEST_OUTPUT_DIR"));
        assert!(input.is_absolute() && input.is_file(), "PDF must be an absolute existing file");
        assert!(output.is_dir(), "output directory must already exist");
        let certificates = NativeSigner.list_certs()
            .unwrap_or_else(|_| panic!("certificate enumeration failed"));
        let certificate = selected_certificate(&certificates, &serial)
            .unwrap_or_else(|message| panic!("{message}"));
        let original = std::fs::read(&input).expect("read original PDF");
        let directory = output.join(format!("cryptolite-verify-{}", new_id()));
        std::fs::create_dir(&directory).expect("create unique verification directory");
        let stamp = PdfStampSpec {
            page: 0, left_mm: 20.0, top_mm: 20.0, width_mm: 80.0, height_mm: 35.0,
            position: String::new(),
        };
        let direct = directory.join("direct.pdf");
        sign_document(&input.to_string_lossy(), &direct.to_string_lossy(), &certificate.id, &stamp, &[])
            .unwrap_or_else(|_| panic!("direct: signing failed"));
        verify_route("direct", &direct, &directory);

        let prepared = prepare(&input.to_string_lossy(), &certificate.id, &stamp, &[])
            .unwrap_or_else(|_| panic!("external: preparation failed"));
        let exported = pdf_layer::export_prepared(prepared).expect("export preparation");
        let cleanup = StagingCleanup(PathBuf::from(&exported.prepared_path));
        let content_path = directory.join("external-content.bin");
        let cms_path = directory.join("external-signature.der");
        std::fs::write(&content_path, &exported.signed_bytes).expect("write external signing input");
        NativeSigner.sign_file(SignRequest {
            standard: "cades-bes".into(),
            input_path: content_path.to_string_lossy().into_owned(),
            output_path: cms_path.to_string_lossy().into_owned(),
            certificate_ids: vec![certificate.id.clone()], detached: true, base64: false,
            tsp_server: None,
        }).unwrap_or_else(|_| panic!("external: CAdES signing failed"));
        let payload = PdfSignaturePayload {
            cms: std::fs::read(&cms_path).expect("read external CMS"),
            contents_at: exported.contents_at,
        };
        let restored = restore(&exported.prepared_path).expect("restore external preparation");
        let external = directory.join("external.pdf");
        finish_signed(&restored, &payload, &external.to_string_lossy()).expect("finish external PDF");
        drop(restored);
        drop(cleanup);
        assert!(!Path::new(&exported.prepared_path).exists(), "staging file leaked");
        verify_route("external", &external, &directory);
        assert!(std::fs::read(&input).expect("reread source") == original, "source PDF changed");
        println!("results: {}", directory.display());
    }
}
