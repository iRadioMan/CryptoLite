#![deny(unsafe_code)]

pub mod digest;

#[cfg(target_os = "windows")]
pub mod cadescom;
#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub use windows as platform;
#[cfg(target_os = "linux")]
pub use linux as platform;
