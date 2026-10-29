#![deny(unsafe_code)]

mod commands;
mod signer;

pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter("cryptolite=info")
        .init();
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            commands::csp_status,
            commands::load_settings,
            commands::save_settings,
            commands::list_certs,
            commands::sign_file,
            commands::sign_files,
            commands::verify_signature,
            commands::encrypt_file,
            commands::decrypt_file
        ])
        .run(tauri::generate_context!())
        .expect("failed to run CryptoLite");
}
