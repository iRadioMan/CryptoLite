# CryptoLite — handoff

## Последняя сессия: поворот страниц в разметке штампа (2026-11-10)

- UI: в правой части `.stamp-pager` две квадратные кнопки 28×28 (`rotate-left`/`rotate-right`), `margin-left:auto` у `.stamp-rotate-group`, подписи ru/en в `main.ts`. Кнопки поворачивают только текущую страницу и заблокированы, пока она отрисовывается (`rendering`).
- Предпросмотр: `StampEditor` через `v-model:rotations` хранит абсолютный угол изменённых страниц; `getViewport({ rotation })` получает `(page.rotate + пользовательский поворот) % 360`, исходный `/Rotate` запоминается в `baseRotations`, при возврате к нему запись удаляется. `renderToken` отбрасывает устаревшие отрисовки, а поворот из обработчика передаётся в `render(rotationOverride)` — props обновляются только следующим рендером родителя.
- Области переносятся вместе с содержимым (`rotateStampRect`, мм вокруг центра видимой страницы, стороны меняются местами), поэтому штамп остаётся на том же месте документа, если страницу повернули после разметки.
- Backend: `PdfSignRequest`/`PdfSignPrepareRequest.pageRotations: [{ page, rotation }]` (`#[serde(default)]`, абсолютные 0/90/180/270). `pdf_layer::prepare_bytes` проверяет кратность 90°, пишет `/Rotate` в словари страниц той же инкрементальной ревизии (включая страницы без отметки, перекрывая унаследованное значение) и считает `box_in_page`/`appearance_transform` по целевому углу — компенсация из прошлой сессии не менялась. Углы абсолютные, поэтому повторные проходы multi-signer не накапливают поворот.
- Тесты: `page_rotations_persist_for_unstamped_pages` (3 страницы: 0→90, 1→270, отметка на 2-й — сценарий «повернуть, переключить, повернуть, переключить, поставить штамп»), `stamp_uses_requested_rotation`, `invalid_page_rotation_is_rejected`, `repeated_preparation_keeps_rotations_absolute`; `cargo test --lib signer::pdf_layer::tests` — 24 passed. `vue-tsc --noEmit` и `vite build` проходят.
- Предпросмотр проверен в Edge 157 (headless-Chromium окружения — Chrome 127 — не тянет pdf.js 6.5: worker использует `Uint8Array.toHex`/`Float16Array`): страница с `/Rotate 90` после +90° рисуется перевёрнутой на 180°; у второй страницы 0→270 холст сменился 760×1075 → 760×537; область на повёрнутой странице после обратного поворота получила ожидаемые мм, после возврата на первую страницу поворот сохранился. Живое приложение и Acrobat не проверялись — нужен личный сертификат КриптоПро.

## Предыдущая сессия: штамп на страницах с поворотом `/Rotate` (2026-11-09)

- Причина дефекта на `D:\Загрузки\Отчет.pdf` (`/Rotate 270`): содержимое формы отметки (`/AP /N`) писалось в координатах страницы без компенсации поворота. Просмотрщик поворачивает аннотации вместе со страницей, поэтому текст вставал на 90° против часовой стрелки, а layout получал стороны рамки в координатах страницы (при 90/270 оси переставлены) — блок съезжал и обрезался рамкой. `Rect` ставился верно: `box_in_page` совпадает с pdf.js `PageViewport` (`convertToPdfPoint(100, 200) = (395, 741)` на странице 595×841 при 270).
- Новая `pdf_layer::appearance_transform(rotation, width, height)` — PDF-матрица `[a b c d e f]` по сторонам `Rect`. Поток формы начинается с `q … cm`, содержимое строится в координатах видимой стороны (`layout_width`/`layout_height` переставлены при 90/270, включая белую подложку и рамку) и закрывается `Q`. `/BBox`, `Rect` и `/Matrix` не изменены; при `/Rotate 0` матрица единичная, `layout_* == width/height`.
- Тест `stamp_appearance_is_upright_on_rotated_pages` (0/90/180/270): сверяет `/BBox` с `Rect`, первую строку потока с `appearance_transform`, попадание углов области отметки в нарисованный прямоугольник через инверсию `box_in_page` (helper `display_point`, совпадает с pdf.js) и горизонтальность базиса текста; для 270 дополнительно закрепляет `Rect [439.094 558.535 538.307 785.307]`. На прежнем коде падал (в потоке не было `cm`).
- Машинная проверка на реальных файлах (временный тест, после проверки удалён): `Отчет.pdf` — `/Rotate` сохранён 270, `Rect [439.09 … 784.31]`, поток `q 0.0000 -1.0000 1.0000 0.0000 0.0000 226.7717 cm`, углы ложатся в нарисованный прямоугольник с точностью 0.0001 pt; документ без поворота (`ответ на протокол №2 по БДД…`) — `q 1.0000 0.0000 0.0000 1.0000 0.0000 0.0000 cm`, отклонение 6e-6 pt, штамп не изменился.
- Проверки: `cargo test --locked --manifest-path src-tauri/Cargo.toml --lib` — 28 passed, 1 ignored. `signer::output::tests::keeps_free_name_and_suffixes_taken_names` иногда падает при параллельном запуске (`TempDir` из pid+наносекунд совпадает у двух тестов), к правке отношения не имеет — по отдельности проходит. В живом приложении и Acrobat не проверялось: нужен личный сертификат КриптоПро.
- Если встретится просмотрщик, который не поворачивает appearance аннотации, компенсацию переносят в `/Matrix` формы (`/BBox` в координатах видимой стороны, поток без `cm`).
- `cargo fmt --all` по-прежнему неприменим: `csp_native`, `embed_font.rs`, `pades.rs` и `pdf_layer.rs` расходятся с rustfmt. Новый код написан в стиле rustfmt.

## Предыдущая сессия: локализация сообщений backend языком интерфейса (2026-11-08)

- Новый модуль `src-tauri/src/i18n.rs`: `Language::{Ru, En}` в `AtomicU8`, `from_tag` (строго `ru`/`en`), `set`, `current` и макрос `tr!("RU", "EN", args…)`. Макрос подставляет литерал в `format!` на месте вызова, поэтому работают неявные захваты (`{error}`, `{code:08X}`). До первого вызова `set_language` язык русский.
- Tauri-команда `set_language(language: String)` (зарегистрирована в `lib.rs` перед `load_settings`) переключает `i18n::set` для известных тегов и молча игнорирует `system`/неизвестные; `save_settings` синхронизирует язык после валидации. `system` разрешает frontend через существующий `applySettings`.
- `SignerError` переведён с `thiserror` на ручной `Display` через `tr!` (зависимость `thiserror` удалена из `Cargo.toml`, `Cargo.lock` обновлён): префиксы ошибок следуют языку в момент отображения.
- Все пользовательские сообщения `commands.rs`, `signer/native.rs`, `signer/csp_native/windows/mod.rs`, `signer/csp_native/cadescom.rs`, `signer/csp_native/windows/digest/mod.rs`, `signer/output.rs`, `signer/pades.rs`, `signer/pdf_layer.rs` переведены на `tr!`. `windows::write_result` вместо `action: &str` + `is_decryption` принимает `ResultFileKind::{Encryption, Decryption}`, поэтому «шифрования»/«расшифрования» больше не склеивается в рантайме.
- Намеренно оставлены на русском видимая отметка об ЭП и её `/Reason` в `pdf_layer.rs` (`Документ подписан электронной подписью`, `ДОКУМЕНТ ПОДПИСАН`, `ЭЛЕКТРОННОЙ ПОДПИСЬЮ`, `Сертификат {}`, `Владелец {}`, `Действителен с {} по {}`) — это содержимое документа по ГОСТ Р 7.0.97-2025, а не сообщение интерфейса. `signer/pdf_cms.rs` в `signer/mod.rs` не объявлен и не компилируется, поэтому не тронут.
- Frontend (`src/App.vue`): `setBackendLanguage()` и `refreshCspStatus()`; вызов при старте в `onMounted`, после каждого `applySettings()` в `initializeSettings` и в новом `watch(locale, …)`. Смена языка в «Настройках» или кнопкой в сайдбаре сразу переключает backend и перезапрашивает сообщение CSP. Уже показанные результаты прошлых операций (отчёт подписи, готовый результат проверки, ошибка выбора сертификата) задним числом не переводятся — их заменяет следующая операция.
- Тесты: `cargo test --lib` — 23 passed, 1 ignored (`real_pdf_signing`). Новые `i18n::tests::language_tags_are_strict` и `i18n::tests::messages_follow_current_language` (один и тот же `SignerError` рендерится по-русски и по-английски). `npm run build` (`vue-tsc --noEmit` + Vite) проходит.
- Сквозная проверка backend без кликов по UI: временный тест вызывал `set_language`, затем `NativeSigner.csp_status()` и `verify_signature` на мусорном `.sig` — тексты менялись (`Could not open CryptoPro CSP providers…` / `Не удалось открыть провайдеры…`, `The signature of signer #1 failed…` / `Подпись подписанта №1 не прошла…`); тест после проверки удалён. Ветка «CSP обнаружен» проверена только компиляцией: КриптоПро CSP в окружении нет. Собранный `target/debug/cryptolite.exe` запускается.
- `cargo fmt --all` в репозитории применять по-прежнему нельзя: `csp_native`, `pades.rs`, `pdf_layer.rs` расходятся с rustfmt. Новый код написан сразу в стиле rustfmt, лишних расхождений не добавляет; dead-code warnings остались прежние.

## Предыдущая сессия: белая подложка штампа и автоподбор кегля (2026-11-07)

- Поток формы отметки (`/AP /N`, `pdf_layer::appearance_content`) начинается с белой заливки всего `BBox`: текст документа под штампом больше не просвечивает.
- Кегли строк подбираются единым масштабом `fit_scale`: минимум из ограничения по ширине (`width − 2·4.5 pt`, самая широкая строка) и по высоте (`ascent + межстрочные интервалы 1.2·кегль + descent` в пределах `height − 2·3 pt`), сверху ограничен `1.0`. Номинальные кегли ГОСТ (`FONT_SCALE = 1.4`) только уменьшаются, но не растут.
- Построчное горизонтальное сжатие `0.55..1.0` и `break` по вертикали удалены: ни одна строка не теряется, пропорции глифов не искажаются. Строки с `Tf < 0.01` не выводятся (защита от вырожденных прямоугольников).
- Проверки: `cargo test --locked --manifest-path src-tauri/Cargo.toml --lib` — 18 passed, 1 ignored (`real_pdf_signing` требует явно выбранный сертификат КриптоПро); добавлены `appearance_content_fills_white_and_fits_all_lines` и `prepared_appearance_is_white_and_auto_scaled`.
- `cargo fmt --all` в репозитории по-прежнему применять нельзя: `csp_native`, `embed_font.rs`, `pades.rs` и `pdf_layer.rs` расходятся с rustfmt (73 расхождения были и до правки). Новый код написан сразу в стиле rustfmt — расхождений не добавляет.

## Предыдущая сессия: формат PAdES-BES и удаление временных PDF (2026-11-05)

- Приведён в порядок формат встроенной подписи PDF: `/Filter /CryptoPro PDF`, `/SubFilter /ETSI.CAdES.detached`, `/Contents` резервируется байтами, `/ByteRange` пишется сырым массивом, корректная сериализация имён и строк, xref подсекциями. Подпись открывается и проходит проверку в Acrobat.
- Подпись хэшируется и вставляется в один и тот же буфер: `with_byte_range` + `assemble_document` пишут одинаковые `/ByteRange`, `trim_der` обрезает CMS по заголовку.
- Починен multi-signer по PDF: `/Annots` пишется прямо в страницу, промежуточные `*.signing-N.pdf` создаются в системном temp и удаляются с проверкой канонического пути. Добавлен множитель шрифта отметки `FONT_SCALE = 1.4`, сжатие `FontFile2`.
- Версия поднята до 0.2.1 (npm, Cargo, Tauri, подписи в UI). Проверки: `npm run build`. Подробности — в разделе «Формат PAdES-BES» ниже.

## Предыдущая сессия: настройки и «О программе»

- Созданы полноценные страницы «Настройки» и «О программе» на русском и английском. На About отображаются версия приложения, версия CSP из `CryptGetProvParam(PP_VERSION)` (если CSP её возвращает), тип провайдера, доступность CAdESCOM, технологический стек и Apache-2.0/оговорка об отсутствии аффилиации.
- Настройки сохраняются в Windows в `HKCU\Software\CryptoLite`, значением `Settings` (JSON); при первом запуске переносится legacy `settings.json` из каталога приложения. На Linux остаётся `settings.json` в Tauri `app_config_dir`. Поля: язык (RU/EN/системный), тема (светлая/тёмная/системная), анимации, стандарт/кодировка/вид подписи/расширение, сертификаты по умолчанию, последний каталог, опция запоминания последних параметров и TSP URL. PIN и приватные ключи не хранятся.
- Настройки автоматически применяются к форме подписания и сохраняются с debounce; сертификаты по умолчанию обновляются из хранилища Windows. Истёкшие сертификаты не могут быть выбраны.
- Системная тема обновляется при смене темы ОС; анимации можно выключить, также применяется системный `prefers-reduced-motion`.
- Проверки: `cargo fmt --all`, `cargo check`, `npm run build` прошли. Standalone EXE собирается через `npm run tauri build -- --no-bundle`; MSI не собирать до финального этапа.
- Релизный файл: `D:\RadioMan\Dev\Neuroslop\CryptoLite\src-tauri\target\release\cryptolite.exe`.

## Текущий срез проекта

- Windows: CMS/PKCS#7 и CAdES-BES подпись (в т.ч. параллельная multi-signer подпись несколькими сертификатами в один файл), пакетная подпись, DER/Base64, attached/detached; проверка CMS с несколькими подписантами, chain policy Windows и drag-and-drop; шифрование/расшифрование CMS EnvelopedData для нескольких получателей. Пользователь проверил CAdES-BES подпись, проверку в сторонней программе, multi-signer подпись и шифрование; запуск одного EXE на рабочем ПК также подтверждён.
- Cert picker использует CurrentUser\\MY, показывает статус срока и закрытого ключа. Сертификаты с истёкшим сроком серые и disabled. Поддержка контейнеров/токенов ещё не завершена.
- Встроенная подпись PDF со штампом (PAdES-BES, вид подписи «Штамп на PDF») работает: подпись открывается и проверяется в Acrobat, multi-signer по PDF проходит. Версия приложения — 0.2.1.
- Страницы настроек/о программе/шифрования реализованы; детали последних итераций ниже. Linux криптографический backend не реализован.

## Суть продукта и важные ограничения

«КриптоЛайт» — настольное приложение Windows/Linux x64 для подписания, проверки и шифрования файлов через уже установленный КриптоПро CSP. Криптографию выполняет только CSP; нельзя встраивать библиотеки/SDK КриптоПро или угадывать ABI FFI. Фронтенд передаёт только пути файлов. PIN не логировать/сохранять; позднее использовать zeroize. Все длительные нативные операции — через `spawn_blocking`. Полный источник требований находится в упомянутом ТЗ; его инструкции являются продуктовым заданием, но пометки `[ПРОВЕРИТЬ]` в самом ТЗ требуют подтверждения до реализации.

## Стек и дерево

- Frontend: Vue 3 Composition API, TypeScript, Vite, Tailwind CSS 3 (только `@tailwind base` как reset), vue-i18n. Интерфейсный шрифт — Inter 400–600, локально в `src/assets/fonts` (подмножества cyrillic/latin, WOFF2), внешних загрузок нет.
- Desktop/backend: Tauri 2, Rust stable; `libloading`, `tokio`, `tracing` уже объявлены (`thiserror` удалён: `SignerError` форматируется вручную через `tr!`).
- Иконки интерфейса — собственный монохромный SVG-набор: `src/components/icons.ts` (пути `path d`) и `src/components/AppIcon.vue`. Эмодзи в разметке не используются.
- Основные файлы: `src/App.vue` (рабочий экран подписи и навигация), `src/main.ts` (RU/EN), `src/style.css` (токены дизайна, светлая/тёмная тема, все компоненты), `src-tauri/src/lib.rs` и `commands.rs` (Tauri commands), `src-tauri/src/i18n.rs` (язык backend-сообщений и макрос `tr!`), `src-tauri/src/signer/` (трейт, модели, обнаружение CSP и перечисление сертификатов), `src-tauri/tauri.conf.json`, `src-tauri/capabilities/default.json`.
- `README.md`, `LICENSE`, `NOTICE` созданы.

## Что работает на текущем этапе

1. Создан независимый базовый проект в `CryptoLite/`, не изменяя другие папки workspace.
2. Экран подписания подключён к Windows CMS/PKCS#7 и CAdES-BES; доступны DER/Base64, attached/detached, `.sig`/`.p7s`, параллельная multi-signer подпись несколькими сертификатами, пакетная обработка, итоговый отчёт, системные file dialogs и drag/drop.
3. Реализованы проверка CMS с несколькими подписантами и отдельной оценкой Windows chain policy. Сетевой retrieval и проверка отзыва не включены. Пользователь проверил CAdES-BES подпись, multi-signer подпись и их проверку в сторонней программе.
4. Реализованы шифрование/расшифрование CMS EnvelopedData для нескольких получателей (`.enc`, совместимо с КриптоАРМ) с пакетной обработкой и отчётом.
5. Настройки RU/EN/system, theme light/dark/system, animations, default signing options/certificates, last output folder, remember-last и TSP URL сохраняются в системном каталоге конфигурации. About показывает статус CSP/CAdESCOM, версию CSP при доступности, стек и лицензионную оговорку.
6. Windows `list_certs` перечисляет сертификаты CurrentUser\\MY, возвращает срок действия и состояние связи с ключом. Просроченные сертификаты disabled. Токены/контейнеры не включены; Linux криптографический backend остаётся незавершённым.
7. Встроенная подпись PDF (PAdES-BES) со штампом: окно предпросмотра и разметка, встраиваемый шрифт DejaVu, инкрементальное обновление xref, multi-signer по PDF с промежуточными файлами в системном temp. Итоговая подпись проверяется в Acrobat (см. раздел 2026-11-05).

## Проверка / как запустить

Доступны `rustc 1.99.1`, `cargo 1.99.1`, `node 26.12.0`, `npm 11.20.0`. После разрешения доступа к реестрам созданы `package-lock.json` и `src-tauri/Cargo.lock`. `npm run build` проходит: `vue-tsc --noEmit` + Vite production bundle. `cargo check` и `cargo build --release` проходят для `x86_64-pc-windows-msvc`; только dead-code warnings на будущие ветки `SignerError`. Release EXE пересобран (`src-tauri/target/release/cryptolite.exe`). MSI bundling ранее не завершился: Tauri скачивает WiX toolset с GitHub, DNS хоста был недоступен. `npm install` сообщил 7 vulnerabilities (2 moderate, 5 high); пока не запускать `npm audit fix --force` без разбора breaking changes. Linux-сборка и GUI не проверены. CryptoPro CSP и x64 CAdESCOM установлены; runtime probe проверен через csptest, API подписи в приложении ещё не вызван.

## Известные незакрытые детали

- Подтвердить конкретные актуальные версии зависимостей и собрать приложение. `CSP` detector не должен объявлять availability до проверки нужных символов/вызова API.
- В drag/drop брать Tauri file paths через документированный API; текущая реализация читает экспериментальное `File.path`, проверь поддержку в Tauri 2.
- Сертификатный выбор сейчас работает для Windows CurrentUser\MY; для Linux и токенов ещё нет реализации. Проверить, что CERT_KEY_PROV_INFO_PROP_ID означает только привязку ключа, а не подтверждённую доступность/работоспособность ключа, и формулировать UI соответствующе.
- Основные экраны ещё требуют доведения локализации RU/EN; settings/about переведены. Системная тема, отключение анимаций и `prefers-reduced-motion` подключены.
- Проверить безопасность capability: разрешить только нужные команды и системные file dialogs.
- Cargo/npm lockfiles уже есть; проверяй их при обновлении. Windows CSP discovery/выбор сертификата используют системный CryptoAPI. CAdES-BES подключён через CAdESCOM и проверен пользователем.
- Добавить/проверить полную Apache-2.0 лицензию (текущий LICENSE содержит operative terms, но не полный appendix/exemplar).
- Для Rust 2024/unsafe isolation при интеграции определить границы: `#![deny(unsafe_code)]` уже задано в lib, signer и его модулях. Проверять ограничения из ТЗ.
- PAdES: убрать остатки первого варианта (хэширование через CSP: `sign_pdf_range`, `digest`, неиспользуемые константы CAdESCOM) и неиспользуемую `temp` в `commands.rs`; проверить подпись штампом в КриптоАРМ и на PDF с формами/аннотациями и большими вложениями.

## Рекомендуемая последовательность

1. Подключить CAdES-T к сохранённому TSP URL и проверить штамп времени/валидацию; адрес пока только хранится в настройках.
2. ~~Реализовать CMS EnvelopedData~~ — сделано (шифрование для нескольких получателей и расшифрование своим ключом; «подписать, затем зашифровать» ещё нет).
3. ~~Реализовать параллельные multi-signer подписи~~ — сделано для CMS/PKCS#7 (несколько сертификатов в один файл). Осталось multi-signer для CAdES (через CAdESCOM `CPSigners`).
4. Добавить перечисление контейнеров и сертификатов Рутокен/JaCarta через CSP, обработку недоступного токена и безопасный PIN flow по ТЗ.
5. Реализовать конфликты имён («перезаписать/суффикс/применить ко всем»), batch UX для других операций, сценарий «подписать, затем зашифровать» и проверку вложенной подписи при расшифровке.
6. Реализовать Linux CSP discovery/sign/verify/encrypt/decrypt через поддерживаемый интерфейс CryptoPro или обоснованную CLI-обёртку и проверить поддерживаемые дистрибутивы.
7. Довести локализацию основных экранов, CSP license status (если доступен API), совместимость CryptoARM/`cryptcp`, лицензионную проверку зависимостей и README.
8. Пройти приёмочную матрицу Windows/Linux; MSI/пакеты установки создавать только в самом конце.

## Источники, проверенные для начального каркаса

- Tauri v2 официальный create-project: https://v2.tauri.app/start/create-project/
- Tauri v2 dialog plugin и разрешения: https://v2.tauri.app/plugin/dialog/
- Релизы Tauri (версии на дату начала): https://v2.tauri.app/release/
- Microsoft `CryptAcquireContextW` (флаги/контекст): https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontextw
- CryptoPro provider types 75/80/81 (документация CryptoPro): https://docs.cryptopro.ru/cpkey/cert/articles2/rest/signserver/structs/csppolicy.html
- CAdES COM component on Windows and `cadescom.dll` install requirement: https://docs.cryptopro.ru/cades/usage/cades-com-usage

Документация CryptoPro CAdES подтверждает COM-объект `CAdESCOM.Store`, включая `CADESCOM_CONTAINER_STORE` (100) для сертификатов с контейнеров, и `CAdESCOM.CadesSignedData.SignCades` с типами CAdES-BES=1, CAdES-T=5, PKCS7=65535. Установка доступного CAdESCOM подтверждена, но COM-интеграция подписи/перечисления контейнеров ещё не реализована.

### Проверка списка внутри приложения (2026-10-20)

Запущено Tauri-приложение из `npm run tauri dev`. В UI открыто окно выбора сертификата; после загрузки в нём отображены 2 сертификата, ровно как в CurrentUser\\MY. Один — Crypto-Pro GOST 2012. Это подтверждает выполнение `list_certs` через само приложение. Прежний запуск release EXE показал страницу `localhost refused to connect`, так как dev server не был запущен; release bundle следует пересобрать, когда frontend будет готов.

`vite.config.ts` обновлён: watcher игнорирует `src-tauri/target/**`, потому что первоначальный `tauri dev` завершился на `EBUSY` при отслеживании временного Cargo EXE. Повторный запуск прошёл; сначала собрался Rust backend, затем запустилось окно Tauri. В `src/App.vue` подпись источника изменена на точное `Windows · Личное хранилище`, чтобы не обещать неподключённую поддержку токенов. `npm run build` успешно прошёл. Следующий функциональный этап: контейнеры CryptoPro и первая операция подписи.
### Исправление release exe и оформления (2026-10-20)

- Причина `Hmm… Can't reach that page`: предыдущий `src-tauri/target/release/cryptolite.exe` был получен командой `cargo build --release`, а не Tauri build. Он открывался с `http://localhost:1420` и не содержал готовый frontend. Правильная команда: `npm run tauri build -- --no-bundle`; она сначала вызывает `npm run build`, затем создаёт самостоятельный exe со статикой. Bundling MSI намеренно пропущен.
- Причина визуально сломанной верстки: в `src/style.css` отсутствовали базовые CSS правила для сетки приложения и основных компонентов; оставались в основном стили темы и модального окна. Базовые светлые/тёмные стили и адаптивная раскладка восстановлены. Screenshot release окна визуально проверен: sidebar, topbar, карточки и controls отрисованы; приложение использует сохранённую тёмную тему.
- Новый release exe запущен и проверен: URI `http://tauri.localhost/`, ошибок страницы нет. Модальное окно из release-версии через `list_certs` показывает два сертификата из Windows Personal. 
- Сборка прошла: `npm run build`; `npm run tauri build -- --no-bundle`. Новый бинарник: `D:\RadioMan\Dev\Neuroslop\CryptoLite\src-tauri\target\release\cryptolite.exe`. Для дальнейшего обновления распространяемого exe использовать Tauri build, не `cargo build` напрямую.
### Первый срез подписи CMS/PKCS#7 (2026-10-20)

- Добавлены `SignRequest`/`SignResult`, Tauri-команда `sign_file` с `spawn_blocking`, реализация Windows через системный `CryptSignMessage` из `crypt32.dll`. В работу передаются пути документов; backend сам читает исходный файл и формирует подпись.
- Выбирается сертификат из текущего Windows Personal по идентификатору issuer+serial, ранее показанному в диалоге. Hash OID выбирается по OID открытого ключа сертификата: ГОСТ 2012-256/512 и ГОСТ-2001. Не поддержанный OID завершает операцию ошибкой.
- Режим по умолчанию изменён на CMS/PKCS#7, так как это первый реализованный формат. В UI кнопка доступна только для этого режима, ровно одного выбранного файла и ровно одного сертификата. Поддерживаются attached/detached, DER/Base64, `.sig`/`.p7s`. Выходной путь выбирается пользователем; создание идёт с `create_new`, существующий файл не перезаписывается.
- Остальные параметры интерфейса (CAdES-BES/T, multi-signer, batch) пока визуально остаются в выборе, но действие подписания для них заблокировано с пояснением. Реальные криптографические подписи на пользовательском ключе не создавались в этой сессии; нужен ручной пробный запуск после выбора тестового файла и сертификата.
- Проверки: `cargo fmt --all`, `cargo check`, `npm run build` прошли. `npm run tauri build -- --no-bundle` создал standalone exe и он визуально проверен; выпуск MSI не запускался по просьбе пользователя. Новый путь: `D:\RadioMan\Dev\Neuroslop\CryptoLite\src-tauri\target\release\cryptolite.exe`.
- Ограничения/проверки перед дальнейшим расширением: тестировать валидность CMS через `cryptcp -verify`/CryptoARM на безопасном тестовом файле; удостовериться в совместимости CryptoAPI `CryptSignMessage` с CryptoPro GOST на этом сертификате, особенно отложить результат до теста пользователем. Реализовать CAdESCOM через документированный COM, enumeration `CADESCOM_CONTAINER_STORE`, политику конфликтов имён и multi-file отчет.
- Для системного выбора результирующего файла capability включает dialog:allow-save. Финальный exe пересобран и запущен после этого изменения; стартовый режим в окне — CMS/PKCS#7, видимый статус подтверждает CSP и доступность CMS. Реальную подпись на пользовательском ключе не запускали.

### Пакетное подписание и отчёт об окончании операции (2026-10-20)

- Пользователь подтвердил, что CMS/PKCS#7 подпись, сделанная приложением, прошла проверку в двух сторонних программах.
- Добавлена команда Tauri `sign_files`: принимает список запросов и обрабатывает их последовательно в `spawn_blocking`. Ошибка отдельного файла превращается в элемент отчёта и не прекращает обработку следующих файлов.
- Кнопка подписания доступна при выборе одного или нескольких документов и ровно одного сертификата (CMS/PKCS#7). Для файлов формируются пути результата с выбранным расширением `.sig`/`.p7s` в каталоге, заданном пользователем, или рядом с оригиналом. Системный save-диалог убран, чтобы пакетный сценарий не требовал выбирать имя каждого результата вручную. Backend сохраняет прежнее поведение `create_new`: существующие файлы не перезаписываются, конфликт показывается как ошибка этого документа.
- После выполнения показывается modal-отчёт с количеством успешных/ошибочных документов и строкой по каждому файлу (имя, путь результата или ошибка). MSI не создавался.
- Проверки этого этапа: `cargo fmt --all`, `cargo check`, `npm run build` и `npm run tauri build -- --no-bundle` завершились успешно. Последний standalone exe: `D:\RadioMan\Dev\Neuroslop\CryptoLite\src-tauri\target\release\cryptolite.exe`. Реальные подписи в этой сессии повторно не создавались; ранее пользователь подтвердил их валидность двумя программами.
- Следующие разумные этапы по ТЗ: подключить CAdESCOM согласно установленному SDK, реализовать CAdES-BES и отдельное timestamp/T; затем verify сторонних подписей, encrypt/decrypt; расширить UX конфликтов имён и локализацию. Сверяться с ограничениями ТЗ и не создавать MSI до финального этапа.

### Первый срез проверки CMS/PKCS#7 (2026-10-20)

- Реализована команда `verify_signature` с выполнением в `spawn_blocking` и Windows CryptoAPI: `CryptVerifyMessageSignature` для attached и `CryptVerifyDetachedMessageSignature` для detached. Верификатор умеет читать DER и декодировать Base64/PEM. В attached ветке сначала определяется размер embedded payload, затем CryptoAPI вызывается с буфером, чтобы не принять только успешный parse за проверку подписи.
- В UI ожил экран «Проверка»: выбор `.sig`/`.p7s`, выбор attached/detached, DER/Base64/PEM; для detached требуется оригинал. Отображаются криптографический результат и все сертификаты подписантов (владелец, издатель, срок).
- Проверка выявляет криптографическую целостность каждой CMS подписи и отдельно строит системную цепочку Windows локально/из кэша через CertGetCertificateChain + CERT_CHAIN_POLICY_BASE. Сетевые retrievals и проверка отзыва (CRL/OCSP) не включены; эта граница отображается в результатах. Timestamps ещё не проверяются. Перебор SignerInfo выполняется по индексу до `CRYPT_E_NO_SIGNER`, с ограничителем 127 подписантов. Неверная/повреждённая подпись отображается как не подтверждённая с индексом и кодом Windows.
- Поддержка пока только Windows (Linux команда возвращает понятную ошибку; действующая интеграция CSP там не подключена). Конкретные сторонние и пользовательские подписи для нового экрана в этой сессии не прогонялись.
- Сверены API по официальным Microsoft docs: `CryptVerifyMessageSignature` нельзя использовать для detached, для него вызван `CryptVerifyDetachedMessageSignature`; функция проверки attached допускает многократный вызов по индексу signer. См. https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptverifymessagesignature и https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptverifydetachedmessagesignature.
- Проверки: `cargo fmt --all`, `cargo check`, `npm run build`, `npm run tauri build -- --no-bundle` завершились успешно. Release exe: `D:\RadioMan\Dev\Neuroslop\CryptoLite\src-tauri\target\release\cryptolite.exe`. MSI не создавался.
- Следующие шаги: прогнать экран на CMS signature из уже успешного пользовательского сценария для DER и Base64, проверить attached и tampered document; добавить chain/status and timestamp validation; далее CAdESCOM/CAdES-BES/T.

### Перечисление параллельных CMS подписантов (2026-10-20)

- Проверка теперь последовательно вызывает CryptoAPI для каждого signer index и собирает все сертификаты, пока API не вернёт `CRYPT_E_NO_SIGNER`. Attached и detached ветки обрабатывают индекс отдельно. При ошибке любого подписанта итоговый статус invalid, частичный список проверенных ранее подписантов сохраняется.
- Проверки прошли повторно: `cargo fmt --all`, `cargo check`, `npm run build`, `npm run tauri build -- --no-bundle`. Обновлённый EXE в `D:\RadioMan\Dev\Neuroslop\CryptoLite\src-tauri\target\release\cryptolite.exe`.

### Исправление drag-and-drop и статуса цепочки (2026-10-20)

- Причина неработающего drop: UI пытался получить путь из нестандартного `File.path`, который WebView не обязан предоставлять. Переключено на официальный `getCurrentWebview().onDragDropEvent`, обрабатываются native `drop` пути; добавлена очистка listener при unmount, показ overlay при наведении файлов. Для подписания drop добавляет выбранные пути в список. На экране проверки drop файла `.sig`/`.p7s` задаёт подпись, второй файл — документ для detached.
- В `tauri.conf.json` для главного окна явно выставлено `dragDropEnabled: true`.
- Для каждого подписанта теперь отображается статус Windows chain policy. Построение цепочки ограничено локальным хранилищем/кэшем без внешних сетевых retrievals; отзыв сертификата не проверяется. Успех криптографической проверки не смешивается с цепочным доверием.
- После последней правки сборки `npm run build` и `npm run tauri build -- --no-bundle` прошли; Rust форматирование и `cargo check` также проходят. Текущий EXE: `D:\RadioMan\Dev\Neuroslop\CryptoLite\src-tauri\target\release\cryptolite.exe`. Пользователь вручную подтвердил работу drag/drop и Windows chain status в собранном приложении. MSI не создавать до финального этапа.
- Пользователь проверил собранную версию: drag-and-drop работает; Windows показывает доверие к цепочке сертификатов. Пользователь также подтвердил, что CMS подписи других документов и их проверка проходят.

## Продолжение после ручной проверки (2026-10-20)

- Установленный `C:\Program Files\Common Files\Crypto Pro\Shared\cadescom.dll` найден (x64 версия, ранее проверенная как 2.0.12794.0). Официальные CAdESCOM docs уточняют, что `CAdESCOM.CadesSignedData.SignCades` принимает `CAPICOM_ENCODE_BINARY=1` или Base64=0, CAdES_BES=1 и CAdES_T=5; `Store` допускает `CADESCOM_CONTAINER_STORE=100` для сертификатов с контейнеров. Перед включением этого пути важно корректно связать CryptoAPI выбранный сертификат с объектом CAdESCOM и передавать бинарный content без преобразования текста.
- Проверенные источники: https://docs.cryptopro.ru/cades/reference/cadescom/cadescom_interface/icpsigneddata2signcades, https://docs.cryptopro.ru/cades/reference/cadescom/cadescom_enum/cadescom_cades_type, https://docs.cryptopro.ru/cades/reference/cadescom/cadescom_class/store.
- Следующая реализация: COM automation через установленную `cadescom.dll`, сначала один signer CAdES-BES, с точным выбором сертификата и binary content; затем реальная проверка пользовательской подписью и compatibility. TSP address/settings и CAdES-T после успешного BES. Не выставлять CAdES как доступный раньше реальной совместимости проверки.

### Подключение CAdES-BES (2026-10-20)

- Реализован Windows COM-адаптер `src-tauri/src/signer/csp_native/cadescom.rs`: создаёт CAdESCOM.Store в CurrentUser, находит выбранный сертификат по серийному номеру, проверяет наличие закрытого ключа, подписывает исходные байты методом `CadesSignedData.SignCades` с типом CAdES-BES=1. Binary-файлы кодируются в Base64 только для передачи в COM с `ContentEncoding=BASE64_TO_BINARY`, результат сохраняется как DER или Base64; существующий файл не перезаписывается.
- Статус CAdES теперь подтверждается фактической COM-активацией `CAdESCOM.CadesSignedData`, а не только наличием DLL. Выбор режима подключён в UI к пакетной команде `sign_files`; CMS путь остаётся прежним. CAdES-T пока отключён.
- Проверки: `cargo fmt --all`, `cargo check`, `npm run build`, `npm run tauri build -- --no-bundle` прошли. Прямой PowerShell COM smoke-check `New-Object -ComObject CAdESCOM.CadesSignedData` успешен. Сборка: `D:\RadioMan\Dev\Neuroslop\CryptoLite\src-tauri\target\release\cryptolite.exe`.
- Реальную подпись и проверку CAdES в этом runner выполнить не удалось: его CurrentUser\\Personal пуст (0 сертификатов с закрытым ключом), хотя COM объект доступен. Приложение в обычной пользовательской сессии ранее показывало 2 сертификата. Следующий шаг — выбрать CAdES-BES в собранном приложении, подписать небольшой тестовый файл detached DER, проверить сторонним CryptoARM/cryptcp и затем экраном «Проверка»; подтвердить результат вручную.
- MSI по просьбе пользователя не создавался. Известные предупреждения сборки — неиспользуемые варианты `SignerError` и невозможность hard-link для инкрементального кэша в sandbox; ошибок сборки нет.

### Исправление CAdES-BES: доступ к сертификату (2026-10-20)

- Пользователь сообщил ошибку `Ошибка вызова CAdESCOM.Item: Member not found (0x80020003)` при подписании.
- Причина: COM интерфейс CAdESCOM `ICertificates.Item` опубликован как индексируемое свойство, но адаптер вызывал его через `IDispatch` с флагом `DISPATCH_METHOD`. Переключено на `DISPATCH_PROPERTYGET` с аргументом индекса, как требует COM Automation.
- Подтверждение по официальной документации CryptoPro: `Certificates.Item` описан как свойство коллекции и возвращает сертификат с заданным индексом: https://docs.cryptopro.ru/cades/reference/cadescom/cadescom_class/certificates.
- `cargo fmt --all` и `cargo check` прошли после исправления. Выполняется новая Tauri release сборка. Реальную подпись проверить сможет пользователь с сертификатом; тестовая сессия агента не имеет приватного сертификата.

### Исправление обнаружения ключа CAdESCOM (2026-10-20)

- Пользователь сообщил, что CAdES-BES нашёл выбранный сертификат, но отверг его по `HasPrivateKey`, тогда как CryptoAPI CMS с тем же сертификатом подписывает.
- Добавлена попытка `CPCertificate.FindPrivateKey()` при ложном `HasPrivateKey`. Документация CryptoPro указывает, что этот метод ищет соответствующий закрытый ключ и устанавливает ссылку на него: https://docs.cryptopro.ru/cades/reference/cadescom/cadescom_interface/icpcertificatefindprivatekey. Если поиск не проходит, UI получает HRESULT/описание ошибки CryptoPro.
- `cargo fmt --all` и `cargo check` прошли; выполняется release build. Ограничение: runner по-прежнему не имеет пользовательского ключа, поэтому определить успешность поиска на сертификате пользователя можно только при проверке обновлённого EXE.

### Исправление назначения сертификата CPSigner (2026-10-20)

- Пользователь сообщил `Не удалось установить CAdESCOM.Certificate: Member not found (0x80020003)` при назначении сертификата CPSigner.
- Документация и VBScript пример CryptoPro подтверждают свойство `CPSigner.Certificate`, которому назначается объект CPCertificate: https://docs.cryptopro.ru/cades/reference/cadescom/cadescom_class/cpsigner и https://docs.cryptopro.ru/cades/reference/cadescom/cadescom-samples/cadescomsamplesigndata.
- В COM setter для объектных значений добавлен fallback: сначала PROPERTYPUTREF, затем PROPERTYPUT. Разные Automation серверы могут по-разному публиковать interface-valued property, оба варианта теперь поддержаны.
- `cargo fmt --all`, `cargo check` прошли. Идёт release build. Реальный тест с ключом доступен пользователю.

### Просроченные сертификаты и увеличение шрифта (2026-10-20)

- `CertInfo` теперь получает `expired`, вычисленный сравнением NotAfter FILETIME с текущим SystemTime. UI серым стилем помечает сертификат с истёкшим сроком, отключает checkbox, убирает такие сертификаты из выбора при обновлении списка и перед подтверждением выбора. `canSign` дополнительно требует выбранный, известный и действующий сертификат.
- Типографика CSS масштабирована примерно на 15% (минимальные размеры повышены минимум на 1 px); размеры компоновки не масштабировались целиком.
- `cargo fmt --all`, `cargo check`, `npm run build` прошли. Собирается standalone release EXE без bundle/MSI.

### Исправление зависания интерфейса (2026-10-20)

- После реализации автосохранения настроек приложение могло зависнуть из-за цикла реактивных обновлений: глубокий watcher настроек применял их и пересоздавал массив выбранных сертификатов, а watcher выбранных сертификатов снова записывал равноценный массив в настройки, повторно запуская глубокий watcher.
- Синхронизация выбранных сертификатов теперь сравнивает состав списка и изменяет настройки только при фактическом отличии. Также удалён дублирующий вызов обновления сертификатов при старте.
- Проверки: `cargo fmt --all`, `cargo check`, `npm run build` прошли; standalone release EXE собран.
- Обновлённый EXE: `D:\RadioMan\Dev\Neuroslop\CryptoLite\src-tauri\target\release\cryptolite.exe`.

### Исправление сохранения настроек и выбора сертификата (2026-10-20)

- Исправлена запись настроек поверх существующего `settings.json`: на Windows при невозможности переименовать временный файл удаляется предыдущая версия и выполняется повторная замена; ошибки записи по-прежнему передаются в индикатор состояния настроек.
- Сертификаты по умолчанию в разделе настроек теперь отображаются компактным списком выбранных имён с кнопкой открытия общего модального окна выбора сертификатов. Изменения в модалке хранятся как черновик и применяются только по кнопке «Выбрать»; отмена не меняет настройки. Просроченные сертификаты отключены.
- Проверки: `cargo fmt --all`, `cargo check`, `npm run build` и standalone release-сборка прошли. MSI не создавался.
- Обновлённый EXE: `D:\RadioMan\Dev\Neuroslop\CryptoLite\src-tauri\target\release\cryptolite.exe`.

### Надёжное сохранение пользовательских настроек в Windows (2026-10-20)

- Пользователь сообщил, что JSON-файл настроек не переживает повторный запуск. Чтобы использовать гарантированно постоянное хранилище текущего пользователя и не зависеть от разрешения/пути каталога приложения, Windows теперь читает/пишет JSON в `HKCU\Software\CryptoLite`, параметр `Settings` (не HKLM, админ-права не нужны). Существующий JSON-файл автоматически переносится в реестр при первом запуске новой версии.
- Добавлен flush настроек при запросе закрытия окна: сохранение ожидается до фактического закрытия, поэтому debounce не теряет последнее изменение при быстром выходе.
- Linux продолжает использовать JSON в `app_config_dir`.
- Проверки: `cargo fmt --all`, `cargo check`, `npm run build`, standalone release-сборка прошли. Реальную проверку повторного запуска с пользовательским профилем ещё должен выполнить пользователь.
- EXE: `D:\RadioMan\Dev\Neuroslop\CryptoLite\src-tauri\target\release\cryptolite.exe`.

### Починка закрытия окна после flush сохранения (2026-10-20)

- Пользователь сообщил, что окно зависает открытым при закрытии через крестик. Причина — повторный вызов `close()` из обработчика `onCloseRequested`, который снова проходил через тот же перехват.
- Теперь закрытие перехватывается однократно, ожидает сохранения настроек и затем вызывает `destroy()` для фактического завершения окна, обходя повторный close-request. Добавлена защита от повторного клика во время сохранения.
- `npm run build` и standalone release сборка прошли. EXE обновлён по прежнему пути.

### Исправление снимка настроек для автосохранения (2026-10-20)

- Пользователь прислал ошибку `DataCloneError` при закрытии. Причина — `structuredClone` получал Vue reactive Proxy из `appSettings`; такие объекты не клонируются встроенным structured clone алгоритмом браузера.
- Добавлен `snapshotSettings()`: создаёт обычный объект с копией массива сертификатов. Используется и debounce-автосохранением, и flush перед закрытием.
- `npm run build` и standalone release-сборка прошли. Обновлённый EXE по стандартному пути.

### Исправление не закрывающегося окна при сохранении (2026-10-20)

- Пользователь подтвердил, что версия с `destroy()` всё ещё зависала при закрытии, хотя настройки сохранялись. Переведён обработчик на неблокирующий шаблон: он отменяет исходный close-request, запускает flush, возвращается сразу; после завершения сохранения разрешает обычное закрытие и вызывает `close()` на следующем цикле event loop. Повторные клики во время flush не запускают новые сохранения.
- `npm run build` и standalone release сборка прошли.

### Удаление перехвата закрытия окна (2026-10-20)

- После двух исправлений пользователь всё ещё не мог закрыть окно через крестик, хотя настройки сохранялись. Удалён весь `onCloseRequested` обработчик и программные вызовы `close()`/`destroy()` из его контекста, чтобы вернуть штатное закрытие Tauri.
- Сохранение теперь отправляется сразу при каждом изменении настроек и выполняется последовательно в очереди; сохранение больше не зависит от перехвата закрытия или debounce-таймера.
- `npm run build` и standalone release сборка прошли. Требуется пользовательская проверка крестика и сохранения после перезапуска.

### Шифрование и расшифрование CMS EnvelopedData (2026-10-29)

- Реализован экран «Шифрование» (placeholder заменён): переключатель операций «Зашифровать / Расшифровать», выбор кодировки DER/Base64, папка сохранения, выбор нескольких сертификатов-получателей (multi-select через общий модальный выбор сертификатов, режим `encryption`), список файлов с чекбоксами, пакетная обработка и итоговый modal-отчёт (успешные/ошибочные). Drag-and-drop направляет файлы на экран шифрования.
- Backend: добавлены модели `EncryptRequest`/`EncryptResult`/`DecryptRequest`/`DecryptResult`, варианты ошибок `Encryption`/`Decryption`, Tauri-команды `encrypt_file`/`decrypt_file` (обе через `spawn_blocking`). Реализация Windows в `signer/csp_native/windows.rs` использует системный `CryptEncryptMessage` (crypt32.dll) для шифрования в CMS EnvelopedData для нескольких получателей и `CryptDecryptMessage` для расшифрования своим закрытым ключом из личного хранилища CurrentUser\MY. Существующий файл результата не перезаписывается (`create_new`).
- Алгоритм шифрования содержимого выбирается по открытому ключу получателей: для ГОСТ 2012 (OID `1.2.643.7.1.1.1.x`) используется «Кузнечик» (`1.2.643.7.1.1.5.1`), иначе «Магма»/ГОСТ 28147-89 (`1.2.643.2.2.21`). IV CryptoAPI генерирует автоматически.
- Файлы результатов: шифрование добавляет расширение `.enc` (совместимо с КриптоАРМ); при расшифровании убирается `.enc`/`.p7m`/`.p7e`.
- Проверки: `cargo fmt --all`, `cargo check`, `cargo build --release`, `npm run build` прошли (только pre-existing dead-code warnings на будущие варианты `SignerError`). Реальное шифрование/расшифрование на пользовательском ключе не запускалось — в runner отсутствует приватный сертификат; нужна ручная проверка пользователем (совместимость с CryptoARM/`cryptcp` для EnvelopedData ГОСТ).
- Ограничения: «подписать, затем зашифровать» (вложенная CMS) ещё не реализовано; проверка вложенной подписи при расшифровке не выполняется; CAdES-T/TSP остаётся на будущее. Сборка MSI не выполнялась.

### Multi-signer подпись и правки интерфейса (2026-10-29)

- `SignRequest.certificate_id` заменён на `certificate_ids: Vec<String>`. CMS/PKCS#7 подписывает одним общим файлом сразу несколько выбранных сертификатов.
- Итоговая реализация multi-signer — низкоуровневый CryptoAPI: `CryptMsgOpenToEncode(CMSG_SIGNED)` с массивом `CMSG_SIGNER_ENCODE_INFO` (по одному на сертификат). Для каждого подписанта: `CERT_KEY_PROV_INFO_PROP_ID` → `CryptAcquireContextW` (контейнер/провайдер/тип из свойства) → определение `dwKeySpec` через `CryptGetUserKey` (сначала `AT_SIGNATURE`, затем `AT_KEYEXCHANGE`). Сертификаты подписантов вкладываются в сообщение через `cCertEncoded`/`rgCertEncoded` (иначе верификатор падает с `CRYPT_E_NOT_FOUND`).
- Тупиковые пути, которые были проверены и отклонены (зафиксировано для истории): `CryptSignMessage` создаёт только ОДНУ подпись (`pSigningCert` единственный; `cMsgCert`/`rgpMsgCert` лишь вкладывают сертификаты, а не добавляют подписантов); `CERT_KEY_CONTEXT_PROP_ID` у сертификатов КриптоПро не заполнен (`CRYPT_E_NOT_FOUND`); принудительный `dwKeySpec=AT_SIGNATURE` даёт `NTE_BAD_KEYSET`; `CMSG_CTRL_ADD_CMS_SIGNER_INFO` (merge одиночных подписей) даёт `E_INVALIDARG` из-за несовместимости версий PKCS#7 v1.5 / CMS v3.
- CAdES-BES по-прежнему подписывает ровно одним сертификатом (CAdESCOM `SignCades`); при выборе нескольких выдаётся пояснение «выберите CMS/PKCS#7».
- UI: кнопка подписания активна при одном или нескольких сертификатах для CMS; в окне выбора сертификатов добавлена кнопка «Сбросить» (снимает все отметки `pickerDraftCertIds`).
- Интерфейс: убраны блок «Локальный профиль / Безопасная обработка» из сайдбара и надпись «Локальная обработка» из шапки; окно увеличено до 1280×860 (мин. 1080×720), общая вертикальная прокрутка убрана (`body`/`.app-shell` `overflow:hidden`, прокрутка внутри `.content-view`), горизонтальный скролл запрещён (`overflow-x:hidden`), убран `min-width` у `body`.
- Проверки: `cargo fmt --all`, `cargo check`, `cargo build --release`, `npm run build`, `npm run tauri build -- --no-bundle` прошли. Пользователь подтвердил: multi-signer подпись двумя сертификатами проходит проверку и в приложении, и в сторонней утилите (видны оба подписанта).

### Выбранные сертификаты вверху списка (2026-10-30)

- В модальном окне `certificate-modal` (`src/App.vue`) отмеченные галочкой сертификаты (`pickerDraftCertIds`) теперь всегда отображаются в начале списка. Порядок реализован в `filteredCertificates`: сначала отфильтрованные по поиску отмеченные сертификаты, затем остальные; исходный порядок внутри каждой группы сохраняется. Список переупорядочивается сразу при установке/снятии галочки и работает во всех режимах окна (подпись, получатели шифрования, сертификаты по умолчанию), а поиск по-прежнему фильтрует обе группы.
- Проверки: `npm run build` и `npm run tauri build -- --no-bundle` прошли (только прежние dead-code warnings). EXE: `D:\Dev\CryptoLite\src-tauri\target\release\cryptolite.exe`. Сборка через npm требует `%USERPROFILE%\.cargo\bin` в `PATH` — в текущей оболочке `cargo` не находился.

### Подтверждение операции при нескольких сертификатах (2026-10-30)

- При нажатии «Подписать» (если выбрано 2+ сертификата подписи) и «Зашифровать» (если выбрано 2+ получателя) показывается модальное окно подтверждения с текстом «Выбрано более 1 сертификата для подписи/шифрования. Вы действительно хотите подтвердить операцию?», списком выбранных сертификатов и кнопками «Да» / «Нет».
- Реализация: `askMultiCertificateConfirmation(mode, ids)` возвращает `Promise<boolean>`; `signSelectedDocument` и `runCrypto` ожидают ответ до запуска операции и при «Нет» завершаются без вызова backend. Состояние в `multiCertConfirmMode`/`multiCertConfirmNames`, единая точка закрытия `settleMultiCertConfirm`. Расшифрование не затрагивается (сертификаты там не выбираются).
- Закрытие только кнопками «Да»/«Нет»; клик по фону диалог не закрывает, чтобы операция не запустилась случайно.
- Стили кнопок диалога исправлены: обе кнопки используют класс `sign-button` (синяя, как основная кнопка операции); убраны смешанные `outline-button`-стили и тёмные переопределения, лишний `margin-top` от `.alert-modal button` снят.
- Кнопка «Да» сделана намеренно приглушённой (класс `primary-dark`: тёмный синевато-серый вместо ярко-синего, аналог для тёмной темы), чтобы пользователь не нажимал её машинально; «Нет» остаётся штатной синей `sign-button`.
- Список выбранных сертификатов в диалоге получил интервалы: увеличены внешний/внутренний отступы блока, у элементов `li` — вертикальные паддинги `5px` и разделители между строками, перенос длинных имён (`overflow-wrap`).
- Добавлены ключи `multiCertConfirm.*` в RU/EN (`src/main.ts`) и стили `.confirm-modal` в `src/style.css` (светлая/тёмная тема).
- Проверки: `npm run build` и `npm run tauri build -- --no-bundle` прошли. Ручной прогон диалога в собранном приложении не выполнялся (в runner нет приватных сертификатов).

### Встроенная подпись PDF (PAdES-BES) со штампом, 2026-11-03

- Новый вид подписи «Штамп на PDF» (пункт в списке рядом с «Присоединённая»/«Отсоединённая»). Стандарт фиксирован CAdES-BES: PAdES — это та же CMS CAdES-BES, встроенная в поле /Sig PDF, отдельного пункта в интерфейсе нет.
- UI: окно предпросмотра PDF (pdfjs-dist), нарисованный прямоугольник на каждого подписанта, сохранение разметки по документу, много-подписная подпись: N сертификатов → N проходов, каждый следующий подписывает результат предыдущего, промежуточные файлы *.signing-N.pdf удаляются, итог — *_signed.pdf.
- Структура (signer/pdf_layer.rs, без unsafe): /AcroForm с SigFlags 3, виджет /Sig с /AP, /Contents фиксированной длины, /ByteRange-заглушка той же ширины. Длина файла при вставке CMS не меняется, поэтому подписанные смещения остаются верными.
- Криптография: **CAdESCOM SignHash/SetHashValue не подписывает готовый хэш** (Automation-объект HashedData не принимает значение, Value пуст; перебраны форматы hex/0x-hex/base64 и значения Algorithm 0–4, 0x10–0x17 — не помогло). Подпись сделана через CSP: хэш диапазона CryptCreateHash(CALG_GR3411_2012_256) + CryptHashData + CMS CryptMsgOpenToEncode с CMSG_DETACHED_FLAG и SignHash-состоянием — тот же порядок, что в примере КриптоПро SimplifiedSignHashCades.cpp (cades.h найден в C:\Program Files (x86)\Crypto Pro\SDK).
- Проверено на реальном сертификате: CMS CAdES-BES 3888 байт, полный цикл «структура → подпись → вставка CMS» проходит, /ByteRange заполняется реальными смещениями, длина файла сохраняется. Проверка в Acrobat/КриптоАРМ — следующий шаг.
- Ограничения: PDF с паролем отклоняется; форма подписи и отметка используют встроенный DejaVu (см. ниже); lopdf используется для чтения/перезаписи документа.
- Проверки: cargo test --lib (2 теста структуры), 
pm run build, 
pm run tauri build -- --no-bundle — успешно.


#### Исправления по итогам ручной проверки (2026-11-03)

- Тип подписи сохраняется в настройках (`AppSettings.defaultSignatureType`: `attached`/`detached`/`stamp`), `defaultDetached` оставлен для совместимости старых профилей.
- У подписанта ровно одна область: пока она не нарисована, повторное перетаскивание отклоняется; подпись доступна только при точном совпадении числа областей и подписантов.
- Исправлено «не удалось найти диапазон подписи в PDF»: диапазон заполнялся при подготовке, и `finish` не находил заглушку. Теперь `/ByteRange` пишется один раз — в `finish`, после вставки CMS.
- Разметка штампов не переносится между открытиями окна: она сбрасывается при открытии.

#### Исправление проверки в Acrobat и кодировки штампа (2026-11-03)

- Причина ошибки Acrobat «SigDict /ByteRange value»: диапазон выравнивался пробелами до фиксированной ширины («[0 347      16733 …]»), а Reader разбирает массив строго. Теперь `/ByteRange` пишется без выравнивания: `[0 A B C]`, где `A` — смещение `<` в `/Contents`, `B` — сразу после `>`.
- Исправлена граница подписи: раньше подписывался только префикс до `/Contents`, теперь подписывается ровно содержимое диапазона — префикс до `<` и хвост после `>` (см. `signed_content` / `signed_content_for_final`), причём с уже подставленным `/ByteRange`.
- Отметка об ЭП теперь набирается встроенным DejaVu Sans Condensed (`assets/fonts`, лицензия Bitstream Vera/DejaVu, см. `LICENSE-DejaVu.txt`). Шрифт встраивается как Type0/Identity-H с `ToUnicode`, текст кириллицы пишется UTF-16BE. Файл увеличивается примерно на 650 КБ.
- Проверено на реальном сертификате: `range=[0 17064 33450 695158]` совпадает с фактическими смещениями, `/FontFile2` и кириллица присутствуют в готовом PDF.

#### Паника «slice index starts at … but ends at …» (2026-11-03)

- Причина: в словаре /Sig /ByteRange может стоять после /Contents, а сборка итогового файла копировала срез staged[offsets_at + заглушка .. contents_at], предполагая обратный порядок. На реальных PDF (4.4 МБ) это давало панику.
- Сборка переписана: файл проходится слева направо, на каждой позиции выбирается ближайшая правка (/ByteRange или значение /Contents), поэтому порядок объектов в словаре не важен.
- locate теперь принимает и заглушку, и уже заполненный диапазон (второй и последующие проходы multi-signer).
- signed_slices/signed_content возвращают Result и проверяют границы: вместо паники — понятная ошибка.
- Проверено на реальном PDF 4.4 МБ: range=[0 3706209 3722595 687003], скобки совпадают; цепочка из двух подписантов проходит. Все 7 тестов (включая реальные) — зелёные.

### Формат PAdES-BES: подпись наконец открывается в Acrobat, 2026-11-05

- Итог: файл со штампом проходит проверку в Acrobat («подпись действительна»); подписанные байты и вставленная CMS совпадают у всех проходов multi-signer, цепочка из нескольких подписантов снова собирается.
- Формат `/Sig` приведён к тому, что пишет КриптоПро PDF и проверяет Acrobat: `/Filter /CryptoPro PDF` (было `/Adobe.PPKLite`), `/SubFilter /ETSI.CAdES.detached` (было `/adbe.pkcs7.detached`) — проверяющая сторона понимает его как PAdES/CAdES, а не как обычную PKCS#7.
- `/Contents` теперь резервируется как реальные байты (`vec![0u8; reserved_contents_bytes()]`), а не строка из `'0'`: сериализатор hex сам превращает каждый байт в `00`, длина поля — 2× резерва. CMS перед hex-преобразованием обрезается по DER-заголовку (`trim_der`), иначе нулевой запас после подписи попадал бы в поле подписи.
- Подпись хэшируется и вставляется в один и тот же буфер: `with_byte_range` + `assemble_document` пишут одинаковые `/ByteRange`, `trim_der` обрезает CMS по заголовку.
- Сериализатор объектов переписан под Acrobat: пробел перед значением ставится только перед числом/ссылкой/bool/null (получается `/Contents<…>`, а не `/Contents <…>`); имена кодируются как `#XX` для всего, что вне печатного ASCII или является разделителем; hex-строки пишутся по байтам; литеральные строки экранируют `(`, `)`, `\` и `\r`. `/ByteRange` пишется как сырой массив фиксированной ширины (`[0 A B C]` с добивкой пробелами), а не строкой.
- Инкрементальное обновление исправлено: смещения объектов теперь запоминаются в момент записи (`Allocator.offsets`), а не ищутся по файлу повторно; `xref` пишется подсекциями подряд идущих номеров, `/Size` = максимальный номер объекта по документу + 1. Это починило повторные проходы multi-signer.
- Встраиваемая шрифтовая программа (`FontFile2`) сжимается (`/Filter /FlateDecode`, около 650 КБ → заметно меньше), метрики `FontDescriptor`/`DW` переводятся в единицы PDF (1000 на кегль). `/W` собирается плоским массивом `CID [w] CID [w]`, как требует спецификация, — раньше каждый CID был отдельным вложенным массивом. `/FontDescriptor` и `/DescendantFonts` теперь ссылаются на объекты шрифта корректно (`FontFile2` и `FontDescriptor` дописываются в словари).
- Размер шрифта отметки задаётся одним множителем `FONT_SCALE = 1.4` в `pdf_layer.rs`; строки кодируются передачей размеров (`encode_lines_with_sizes`), первая строка отступает от верхней рамки на `4.0 + размер`, а не на жёсткие 11 pt. Причина: при прежних размерах текст штампа выглядел слишком мелким и не помещался в рамку.
- Multi-signer: страница больше не ссылается на `/Annots` через пустой промежуточный объект-массив — существующие аннотации и новый виджет пишутся прямо в массив страницы (`existing_array` + `push(widget)`). Промежуточный объект ломал повторные проходы: виджет предыдущего подписанта оставался в отдельном объекте, и второй проход подписывал документ уже с другой страницей.
- Временные PDF при multi-signer: промежуточные `*.signing-N.pdf` теперь создаются в системном temp (`tempDir()` через `@tauri-apps/api/path`), а не рядом с исходником. `remove_temp_pdf` канонизирует путь и сравнивает его с канонизированным системным temp, а фронтенд больше не глушит ошибку удаления (`try/catch` убран) — утечка промежуточных файлов устранена.
- Версия приложения поднята до 0.2.1 синхронно в `package.json`, `package-lock.json`, `Cargo.toml`, `Cargo.lock`, `tauri.conf.json` и в подписях на экранах сайдбара/About/placeholder (`src/App.vue`).
- Тесты: `byte_range_keeps_file_length` переписан под новый сериализатор — фикстура имитирует объект `/Sig` из `prepare` (`/ByteRange`-заглушка сразу перед `/Contents`), проверяются длина файла, положение CMS, добивка диапазона пробелами и повторный `locate` уже заполненного диапазона. `cargo fmt --all`, `cargo test --lib` (3 теста) и `npm run build` проходят; `cargo fmt --all` применён к накопившимся неформатированным файлам (`pdf_layer.rs`, `embed_font.rs`, `windows/mod.rs`, `digest/mod.rs`).
- Осталось: предупреждения `cargo check` — неиспользуемые функции хэширования и CAdESCOM-хелперы от первого варианта PAdES (`sign_pdf_range` больше не нужен, `encode_lines` оставлен для тестов), неиспользуемая переменная `temp` в `commands.rs` после исправления удаления, dead-code на будущие варианты `SignerError`. Проверка штампа в КриптоАРМ и на больших документах ещё не выполнялась.

### Минималистичный редизайн интерфейса, 2026-11-07

- Причина: визуальная перегрузка — 17 размеров шрифта (10…32 px, 18 объявлений ≤11 px), 187 hex-цветов, 11 значений `border-radius`, 8 высот контролов, 20 из 24 пар «текст/фон» ниже WCAG AA (худшая 2.06:1), 114 ad-hoc правил `.dark .selector`, ≈30 эмодзи-иконок, название страницы дублировалось трижды (сайдбар → крошки → `h1`), шрифт `Inter` был объявлен, но не подключён (реально работал Segoe UI), 0 атрибутов `aria-*`.
- `src/style.css` переписан целиком на токены: `:root` + `:root.dark` (палитра, `--fs-12/14/16/20/24` с межстрочными, шкала отступов 4/8/12/16/24, радиусы 6/10/12/999, высоты 28/32/36/40/48). Тёмная тема задаётся только токенами — правил `.dark <селектор>` больше нет. Шрифтовые веса — только 400/600. Tailwind оставлен только как `@tailwind base` (reset), утилитарные классы в разметке не используются.
- Inter подключён локально: `@font-face` с `src/assets/fonts/inter-cyrillic.woff2` (18 748 байт) и `inter-latin.woff2` (48 256 байт), `font-weight: 400 600`, `font-display: swap`, `unicode-range` для каждого подмножества. Vite копирует оба файла в `dist/assets`.
- Новые файлы: `src/components/icons.ts` (`ICON_PATHS`, тип `IconName`, viewBox 24×24, stroke 1.5) и `src/components/AppIcon.vue` (`<AppIcon name size />`, `aria-hidden`). Эмодзи-глифы (🖋️ 🔒 ✔️ ⚙️ ℹ️ 📜 📤 📁 👤 🔆 ✳ ◇ ✍️ ↗ ⌕ × ‹ ›) заменены иконками во всех экранах, в модалках и в `StampEditor.vue` (пагинация `chevron-left`/`chevron-right`, удаление зоны `x`).
- Сайдбар: убраны топбар с крошками, eyebrow-подписи, `.csp-card`; статус CSP — одна строка с точкой состояния, переключатели темы и языка перенесены вниз сайдбара (кнопки с `aria-label`/`title`, иконка sun↔moon по теме).
- Каждый экран: один `h1` на страницу, плоские карточки (`--surface`, 1px `--border`, радиус 10), без поясняющих абзацев в шапках карточек. Основная кнопка операции закреплена в `.action-bar` (`position: sticky`, `bottom: 0`) и видна без прокрутки при 1024×768.
- Доступность: `:focus-visible` → 2 px акцентный outline (у `select`/текстовых `input` — акцентная рамка + 3 px `--ring`; чекбоксы сохраняют outline), `aria-current="page"` у активного пункта навигации, `role="dialog"/"alertdialog"` + `aria-modal` + `aria-labelledby` у всех модалок, `aria-label` у иконочных кнопок и поиска, `aria-live="polite"` у состояния сохранения настроек, drop-зона стала `<button>` (Enter/Space открывает диалог), исправлен невалидный `alt="{{ … }}"` → `:alt`.
- Контраст (расчёт по токенам): `--text-3 #656d79` на `--bg #f7f8fa` — 4.92:1; на `--surface-hover #f2f4f7` — 4.74:1; `--text-2 #4b5563` на `--surface #ffffff` — 7.56:1; `--accent-text #1d4ed8` на `--accent-soft #eef3ff` — 6.03:1; белый на `--accent #2f6df1` — 4.59:1; тёмная тема: `--text-3 #9aa2ae` на `--bg #14171c` — 6.97:1, на `--surface-hover #242a33` — 5.61:1, `--accent-text #8fb3ff` на `--accent-soft #1b2536` — 7.37:1. Все пары ≥ 4.5:1.
- Поведение экранов не менялось. Единственное видимое добавление: `signingMessage` теперь выводится красной строкой над `.action-bar` (раньше заполнялся, но не отображался) — в т.ч. ошибки режима «Штамп на PDF»; мёртвое состояние `cryptoMessage` удалено.
- Диалог подтверждения при 2+ сертификатах: «Нет» — вторичная кнопка (`outline-button`), «Да» — основная синяя (`sign-button`); прежний приглушённый `primary-dark` больше не используется.
- i18n (`src/main.ts`): добавлены корневые ключи `selectionSummary` («Выбрано {selected} из {total}») и `a11y.*` (`close`, `removeFile`, `themeLight`, `themeDark`, `toEnglish`, `toRussian`), в `stampEditor` — `prevPage`/`nextPage`. Удалены ключи, которые перестала использовать новая разметка (`workspace`, `preferences`, `subtitle`, `placeholder`, `signPage.eyebrow|paramsHelp|docsHelp|supportedFormats|chooseFiles|addMoreDocs|selectedOf|ofDocs|documents|changeForList|readyToSign`, `verifyPage.filesHelp`, `encryptPage.modeHelp|filesHelp|orChoose|addMore|selectedOf|ofFiles|files|changeForList|chooseFiles|encryptToEnc|decryptSupported|readyEncrypt|readyDecrypt`, `certPicker.listRefresh`, `signReport.help`, `cryptoReport.help`, `stampEditor.help`, `settings.appearanceHelp|signingHelp|certsHelp|tspHelp`, `about.technologiesHelp`) и уже мёртвые до правок (`signPage.filesStayLocal|signProtected|privateKeyStays|cadesTLater|cadesSdkRequired`, `verifyPage.checkLocal|checkLocalHelp`, `encryptPage.filesStayLocal|dataProtection|dataProtectionHelp`, `multiCertConfirm.certsCount`, `cadesMissing`, `signingUnavailable`, `empty`, `selected`, `noFiles`, `settings.refresh|loading|refreshHint|expired|validUntil|loadError`, `about.licenseIntro`). RU и EN содержат одинаковый набор ключей (193).
- `index.html`: `theme-color` → `#f7f8fa`.
- Проверки: `npm run build` (`vue-tsc --noEmit` + vite) проходит; в `src/style.css` только `font-size:var(--fs-12|14|16|20|24)`, веса 400/600, нет подстроки `.dark `, hex-литералы только в блоках токенов плюс белая «бумага» PDF (`#fff`), кнопка удаления зоны (`#ffffffdd`, `#b42318`). Прогон интерфейса в Chromium (WebView2-совместимый движок, `vite dev`) с инъекцией состояния через `#app.__vue_app__._instance.setupState`: `document.fonts.check('14px Inter')` → `true`, используются ровно 5 размеров шрифта, светлая и тёмная темы, RU и EN, навигация, drop-зона/список файлов («Выбрано 1 из 1»), пикер сертификатов (просроченные серые и disabled), результат проверки с доверенной и недоверенной цепочкой, отчёт подписания в тёмной теме, диалог подтверждения, drag-overlay, редактор штампа на тестовом PDF (зоны, подписи 12 px, пагинация), фокус-обводки при Tab и закреплённая кнопка при 1024×768. Полностью нативные сценарии (реальная подпись/проверка/шифрование в собранном приложении) в этом прогоне не выполнялись: `cargo` не в `PATH`, сертификатов CSP в окружении нет; `npm run tauri dev` не запускался.

### Унификация записи файлов результата, 2026-11-07

- Причина: результат писался в четырёх местах с разным поведением при занятом имени — `pdf_layer::finish` и расшифрование подбирали `имя (n).ext`, а CMS-подпись (`csp_native::cadescom::sign_inner`, `windows::sign_cms`) и шифрование падали с ошибкой «файл существует».
- Новый модуль `src-tauri/src/signer/output.rs` — единственная точка записи финальных результатов: `write_unique(desired, bytes)` открывает файл через `File::create_new` (атомарно, без перезаписи), при `AlreadyExists` перебирает `имя (1).ext` … `имя (9999).ext` (суффикс перед расширением), пишет `write_all` + `sync_all` и при ошибке записи удаляет созданный файл. Возвращает фактический путь.
- Имя с суффиксом собирается из `OsString` (`file_stem`/`extension`), поэтому не-UTF-8 имена больше не портятся через `to_string_lossy` (в прежних `create_unique`/`suffixed_path` они ломались или теряли имя).
- Переведены на помощник: `pdf_layer::finish` (локальный `create_unique` удалён), `cadescom::sign_inner` (тип ошибки остался `String`), `windows::sign_cms`, `windows::write_result` (шифрование и расшифрование; `suffixed_path` удалена). Неиспользуемые `use std::io::Write` / `ErrorKind` убраны. Staging-файлы (`pdf_layer::prepare`, `export_prepared`, `save_settings`) намеренно не переведены — у них другой жизненный цикл.
- Изменение поведения: шифрование при занятом `name.enc` теперь создаёт `name (1).enc` вместо ошибки; для всех результатов выполняется `sync_all`, а не только для PDF.
- Отчёты показывают фактический путь: `sign_files` в `commands.rs` берёт `result.output_path` (раньше — запрошенный), встроенная подпись PDF в `src/App.vue` — `currentInput` (фактический путь последнего подписанта).
- Тесты: новый `output::tests` (3 теста — свободное имя/суффиксы, `archive.tar (1).gz` и `report (1)`, отсутствующий каталог) проходит; весь набор — `cargo test`, 21 passed / 1 ignored (`real_pdf_signing`: нужен сертификат КриптоПро), включая `pdf_layer::tests::exported_preparation_survives_until_finish`, который теперь идёт через `write_unique`. Новых предупреждений о неиспользуемых импортах нет (остались прежние dead-code на будущие ветки).
- `npm run build` (`vue-tsc --noEmit` + vite) проходит.
- Осталось: сквозная проверка в живом приложении (CMS дважды → `sample.txt (1).sig`, штамп дважды → `doc_signed (1).pdf`, шифрование дважды → `sample.txt (1).enc`, расшифрование при существующем `sample.txt` → `sample (1).txt`) не выполнялась: КриптоПро CSP и личного сертификата в окружении агента нет. Проверку выполняет пользователь на тестовом стенде.
