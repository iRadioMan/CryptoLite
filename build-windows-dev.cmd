@echo off
rem ---------------------------------------------------------------------------
rem КриптоЛайт: dev-сборка на Windows (Vite dev-сервер + tauri dev).
rem Запуск: build-windows-dev.cmd (двойной щелчок или из консоли).
rem ---------------------------------------------------------------------------
setlocal
cd /d "%~dp0"

where node >nul 2>nul
if errorlevel 1 (echo [ошибка] Node.js не найден в PATH. Установите Node.js 20.19 или новее. & exit /b 1)

node -e "process.exit(Number(process.versions.node.split('.')[0]) < 20 ? 1 : 0)"
if errorlevel 1 (echo [ошибка] Требуется Node.js 20.19 или новее. Текущая версия: & node -v & exit /b 1)

where cargo >nul 2>nul
if errorlevel 1 (echo [ошибка] Rust не найден в PATH. Установите toolchain: https://rustup.rs & exit /b 1)

where npm >nul 2>nul
if errorlevel 1 (echo [ошибка] npm не найден в PATH. & exit /b 1)

if not exist node_modules (echo [сборка] npm ci & call npm ci)
if errorlevel 1 (echo [ошибка] npm ci завершился с ошибкой. & exit /b 1)

echo [сборка] npm run tauri dev
call npm run tauri dev
if errorlevel 1 (echo [ошибка] tauri dev завершился с ошибкой. & exit /b 1)

endlocal
exit /b 0
