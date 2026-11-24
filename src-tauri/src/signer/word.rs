#![deny(unsafe_code)]
//! Преобразование Word-документа в PDF через COM-объект Microsoft Word.
//!
//! Скрипт PowerShell передаётся в UTF-16LE Base64 (`-EncodedCommand`), пути — только
//! через переменные окружения, поэтому в командной строке нет подстановки кавычек.

use crate::signer::document::truncated;
use crate::tr;
use base64::Engine as _;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;

/// Консольное окно PowerShell не должно появляться поверх GUI-приложения.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// 17 — `wdFormatPDF`, `AutomationSecurity = 3` отключает макросы открытого документа.
const WORD_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
$word = $null
$doc = $null
try {
  $word = New-Object -ComObject Word.Application
  $word.Visible = $false
  $word.DisplayAlerts = 0
  $word.AutomationSecurity = 3
  $doc = $word.Documents.Open($env:CRYPTOLITE_INPUT, $false, $true, $false)
  try {
    $doc.ExportAsFixedFormat($env:CRYPTOLITE_OUTPUT, 17, $false)
  } catch {
    Remove-Item -LiteralPath $env:CRYPTOLITE_OUTPUT -ErrorAction SilentlyContinue
    $doc.SaveAs2($env:CRYPTOLITE_OUTPUT, 17)
  }
} catch {
  [Console]::Error.WriteLine($_.Exception.ToString())
  exit 1
} finally {
  if ($doc -ne $null) { try { $doc.Close($false) } catch {} }
  if ($word -ne $null) { try { $word.Quit() } catch {} }
}
"#;

pub fn convert(input: &Path, output: &Path) -> Result<(), String> {
    let utf16: Vec<u8> = WORD_SCRIPT
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
    let result = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-STA",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
        ])
        .arg(encoded)
        .env("CRYPTOLITE_INPUT", input)
        .env("CRYPTOLITE_OUTPUT", output)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|error| {
            tr!(
                "Не удалось запустить PowerShell: {error}",
                "Could not start PowerShell: {error}"
            )
        })?;
    if result.status.success()
        && output.is_file()
        && output.metadata().map(|m| m.len() > 0).unwrap_or(false)
    {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&result.stderr);
    let stdout = String::from_utf8_lossy(&result.stdout);
    let raw = if stderr.trim().is_empty() {
        stdout.into_owned()
    } else {
        stderr.into_owned()
    };
    let details = truncated(&raw);
    Err(tr!(
        "Не удалось преобразовать документ через Microsoft Word: {details}",
        "Could not convert the document with Microsoft Word: {details}"
    ))
}
