#![deny(unsafe_code)]

mod commands;
mod distro;
mod i18n;
mod signer;

/// WebKitGTK: JIT JavaScriptCore генерирует округление через SSE4.1 (`roundsd`).
///
/// На процессорах без SSE4.1 (например, AMD Llano) WebProcess падает с SIGILL, и
/// окно, где идёт разбор PDF, замирает навсегда («Открытие PDF…»). Интерпретатор
/// JavaScriptCore корректен, поэтому JIT отключается только для таких процессоров.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn disable_jit_without_sse4() {
    use std::arch::is_x86_feature_detected;

    if is_x86_feature_detected!("sse4.1")
        && is_x86_feature_detected!("sse4.2")
        && is_x86_feature_detected!("ssse3")
    {
        return;
    }
    tracing::warn!(
        "процессор без SSE4.1: JIT JavaScriptCore отключён (JSC_useJIT=0), веб-интерфейс работает медленнее"
    );
    std::env::set_var("JSC_useJIT", "0");
}

pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter("cryptolite=info")
        .init();
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    disable_jit_without_sse4();
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .invoke_handler(tauri::generate_handler![
            commands::csp_status,
            distro::environment_info,
            commands::set_language,
            commands::load_settings,
            commands::save_settings,
            commands::list_certs,
            commands::list_tokens,
            commands::sign_file,
            commands::sign_files,
            commands::sign_pdf,
            commands::sign_pdf_prepare,
            commands::sign_pdf_finish,
            commands::remove_temp_pdf,
            commands::filter_file_paths,
            commands::verify_signature,
            commands::verify_pdf,
            commands::encrypt_file,
            commands::decrypt_file
        ])
        .run(tauri::generate_context!())
        .expect("failed to run CryptoLite");
}
