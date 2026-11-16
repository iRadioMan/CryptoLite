#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# КриптоЛайт: release-сборка на Linux — .deb и портативный AppImage.
# Результат: src-tauri/target/release/bundle/{deb,appimage}
# Запуск: ./build-linux-release.sh
# ---------------------------------------------------------------------------
set -euo pipefail
cd "$(dirname "$0")"

fail() { echo "[ошибка] $*" >&2; exit 1; }

command -v node >/dev/null 2>&1 || fail "Node.js не найден в PATH. Установите Node.js 20.19 или новее."
node -e 'process.exit(Number(process.versions.node.split(".")[0]) < 20 ? 1 : 0)' \
  || fail "Требуется Node.js 20.19 или новее. Текущая версия: $(node -v)"
command -v npm >/dev/null 2>&1 || fail "npm не найден в PATH."
command -v cargo >/dev/null 2>&1 || fail "Rust не найден в PATH. Установите toolchain: https://rustup.rs"
command -v pkg-config >/dev/null 2>&1 || fail "pkg-config не найден. Debian/Ubuntu/Astra: sudo apt-get install -y pkg-config"

missing=()
for package in webkit2gtk-4.1 gtk+-3.0; do
  pkg-config --exists "$package" || missing+=("$package")
done
if ((${#missing[@]})); then
  fail "не найдены ${missing[*]}. Debian/Ubuntu/Astra: sudo apt-get install -y libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev"
fi

if [[ ! -d node_modules ]]; then
  echo "[сборка] npm ci"
  npm ci
fi

# AppImage собирается через appimagetool: без FUSE он запускается в режиме распаковки.
if [[ ! -e /dev/fuse ]]; then
  echo "[сборка] /dev/fuse недоступен: AppImage собирается через APPIMAGE_EXTRACT_AND_RUN=1"
  export APPIMAGE_EXTRACT_AND_RUN=1
fi

echo "[сборка] npm run tauri build -- --bundles deb,appimage"
npm run tauri build -- --bundles deb,appimage

echo
echo "[готово]"
ls -lh src-tauri/target/release/bundle/deb/*.deb src-tauri/target/release/bundle/appimage/*.AppImage
