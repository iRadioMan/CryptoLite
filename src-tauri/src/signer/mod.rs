#![deny(unsafe_code)]
mod csp_native;
mod error;
mod model;
pub mod native;
pub use error::SignerError;
pub use model::{
    AppSettings, CertInfo, CspStatus, SignBatchItemResult, SignRequest, SignResult, VerifyRequest,
    VerifyResult, VerifySignerInfo,
};

pub trait Signer: Send + Sync {
    fn csp_status(&self) -> CspStatus;
    fn list_certs(&self) -> Result<Vec<CertInfo>, SignerError>;
    fn sign_file(&self, request: SignRequest) -> Result<SignResult, SignerError>;
}
