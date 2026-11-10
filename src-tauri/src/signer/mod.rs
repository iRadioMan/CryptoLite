#![deny(unsafe_code)]
mod csp_native;
mod embed_font;
mod error;
mod model;
pub mod native;
mod output;
pub mod pades;
#[allow(dead_code)]
pub mod pdf_layer;
pub use error::SignerError;
pub use model::{
    AppSettings, CertInfo, CspStatus, DecryptRequest, DecryptResult, EncryptRequest, EncryptResult,
    PdfSignFinishRequest, PdfSignPrepareRequest, PdfSignPrepareResult, PdfSignRequest,
    PdfSignaturePayload, PdfStampSpec, PageRotation, SignBatchItemResult, SignRequest, SignResult,
    VerifyRequest, VerifyResult, VerifySignerInfo,
};

pub trait Signer: Send + Sync {
    fn csp_status(&self) -> CspStatus;
    fn list_certs(&self) -> Result<Vec<CertInfo>, SignerError>;
    fn sign_file(&self, request: SignRequest) -> Result<SignResult, SignerError>;
}
