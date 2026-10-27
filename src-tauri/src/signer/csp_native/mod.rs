#![deny(unsafe_code)]

#[cfg(target_os = "windows")]
pub mod cadescom;
#[cfg(target_os = "windows")]
pub mod windows;
