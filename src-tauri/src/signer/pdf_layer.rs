#![deny(unsafe_code)]
//! Встроенная подпись PDF (PAdES-BES) с видимой отметкой об ЭП.
//!
//! Порядок берётся у КриптоПро PDF / КриптоАРМ (эталонный подписанный документ):
//!
//! - Исходный файл **не перезаписывается**: к нему дописывается инкрементальное обновление
//!   (ISO 32000-1, 7.5.6): новые объекты и xref того же типа со ссылкой `/Prev`.
//!   Все исходные байты, включая хвост после `%%EOF`, сохраняются.
//! - Поле подписи — виджет `/Sig` в `/AcroForm /Fields` со ссылкой `/V` на словарь `/Sig`
//!   и внешним видом `/AP` (рисуется встроенным шрифтом, а не стандартным Helvetica, из-за
//!   которой кириллица превращалась в «кракозябры»).
//! - `/SubFilter` — `ETSI.CAdES.detached`; `/Contents` фиксированной длины заполняется
//!   шестнадцатеричной CMS, `/ByteRange` — `[0 A B C]`.
//!
//! Подписываемые байты (ISO 32000-1, 7.6.2): всё до `<` в `/Contents` и всё после `>`;
//! CMS при этом сама помечена как `id-data` и содержит подписанные атрибуты (CMS v3).
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use lopdf::{Dictionary, Document, IncrementalDocument, Object, Stream, StringFormat};

use crate::signer::embed_font;
use crate::signer::{CertInfo, PageRotation, PdfSignaturePayload, PdfSignPrepareResult, PdfStampSpec, SignResult, SignerError};
use crate::tr;

/// Ширина `/ByteRange`-заглушки. Настоящие смещения пишутся в это поле через пробелы
/// (как у КриптоПро PDF: `[ 0 64180 166598 14908]`), поэтому длина файла при подписи не меняется.
const OFFSETS: &[u8] = b"[0 9999999999 9999999999 9999999999]";

/// Множитель размера шрифта
const FONT_SCALE: f64 = 2.0;

/// Боковые поля текста внутри рамки штампа, pt.
const STAMP_PADDING_X: f64 = 4.5;

/// Верхнее и нижнее поля текста внутри рамки штампа, pt.
const STAMP_PADDING_Y: f64 = 3.0;

/// Межстрочный интервал в долях кегля.
const STAMP_LEADING: f64 = 1.2;

/// Предел символов в строке ФИО владельца: длинное имя переносится по пробелам.
const OWNER_NAME_LINE_LIMIT: usize = 45;

/// Подготовленный PDF и позиции его полей подписи.
pub struct PreparedDocument {
    pub path: Option<PathBuf>,
    pub bytes: Vec<u8>,
    pub digest_algorithm: String,
    pub page_count: usize,
    /// Позиция значения `/ByteRange` (сразу после `[`).
    pub offsets_at: usize,
    /// Позиция `<` в `/Contents<…>`.
    pub contents_at: usize,
    /// Позиция `>` в `/Contents<…>`.
    pub contents_end: usize,
}

/// Удаление файлов документов
impl Drop for PreparedDocument {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn signing_error(message: impl Into<String>) -> SignerError {
    SignerError::Pdf(message.into())
}

/// Подготавливает PDF: дописывает поле `/Sig` с отметкой к последней версии документа.
pub fn prepare(
    source: &Path,
    stamp: &PdfStampSpec,
    page_rotations: &[PageRotation],
    certificate_id: &str,
    _digest_algorithm: &str,
    _new_id: &str,
) -> Result<PreparedDocument, SignerError> {
    if !source.is_file() {
        return Err(signing_error(tr!(
            "документ {} не найден",
            "document {} not found",
            source.display()
        )));
    }
    let signer = certificate_info(certificate_id)?;
    let source_bytes = std::fs::read(source).map_err(|error| {
        signing_error(tr!(
            "не удалось прочитать документ: {error}",
            "could not read the document: {error}"
        ))
    })?;
    let (bytes, page_count) = prepare_bytes(source_bytes, stamp, &signer, page_rotations)?;
    let (offsets_at, contents_at, contents_end) = locate(&bytes)?;
    let path = staging_path(source);
    if let Err(error) = std::fs::write(&path, &bytes) {
        let _ = std::fs::remove_file(&path);
        return Err(signing_error(tr!(
            "не удалось записать временный файл: {error}",
            "could not write the temporary file: {error}"
        )));
    }
    Ok(PreparedDocument {
        path: Some(path),
        bytes,
        digest_algorithm: _digest_algorithm.to_owned(),
        page_count,
        offsets_at,
        contents_at,
        contents_end,
    })
}

fn prepare_bytes(
    source_bytes: Vec<u8>,
    stamp: &PdfStampSpec,
    signer: &CertInfo,
    page_rotations: &[PageRotation],
) -> Result<(Vec<u8>, usize), SignerError> {
    let document = Document::load_mem(&source_bytes).map_err(|error| {
        signing_error(tr!(
            "не удалось прочитать PDF: {error}",
            "could not read the PDF: {error}"
        ))
    })?;
    if document.is_encrypted() {
        return Err(signing_error(tr!(
            "PDF защищён паролем: встроенная подпись такого документа пока не поддерживается",
            "the PDF is password-protected: embedded signing of such documents is not supported yet"
        )));
    }
    if document.xref_start == 0 || document.xref_recovery.is_some() {
        return Err(signing_error(tr!(
            "PDF требует восстановления таблицы ссылок; инкрементальная подпись отменена",
            "the PDF requires cross-reference recovery; incremental signing was cancelled"
        )));
    }
    let catalog_id = document
        .trailer
        .get(b"Root")
        .and_then(Object::as_reference)
        .map_err(|error| {
            signing_error(tr!(
                "не найден каталог PDF: {error}",
                "PDF catalog not found: {error}"
            ))
        })?;
    let catalog = document
        .get_dictionary(catalog_id)
        .map_err(|error| {
            signing_error(tr!(
                "не удалось прочитать каталог PDF: {error}",
                "could not read the PDF catalog: {error}"
            ))
        })?
        .clone();
    let pages_id = catalog
        .get(b"Pages")
        .and_then(Object::as_reference)
        .map_err(|error| {
            signing_error(tr!(
                "не найдено дерево страниц PDF: {error}",
                "PDF page tree not found: {error}"
            ))
        })?;
    let page_id = page_object_id(&document, pages_id, stamp.page)?;
    let (page_x, page_y, page_width, page_height) = page_box(&document, pages_id, page_id)?;
    // Повороты из запроса применяются в этой же ревизии: страница получает абсолютный
    // /Rotate, поэтому повторная подпись того же PDF не накапливает угол.
    let mut rotation_targets = BTreeMap::new();
    for entry in page_rotations {
        let target_id = page_object_id(&document, pages_id, entry.page)?;
        rotation_targets.insert(target_id, normalized_rotation(entry.rotation)?);
    }
    let current_rotation = page_rotation(&document, pages_id, page_id);
    let rotation = rotation_targets
        .get(&page_id)
        .copied()
        .unwrap_or(current_rotation);
    // Словари остальных повёрнутых страниц готовятся до того, как документ перейдёт
    // в инкрементальную ревизию: новые версии переопределяют только `/Rotate`.
    let mut rotated_pages = Vec::new();
    for (&target_id, &target_rotation) in &rotation_targets {
        if target_id == page_id || page_rotation(&document, pages_id, target_id) == target_rotation {
            continue;
        }
        let mut rotated_page = document
            .get_dictionary(target_id)
            .map_err(|error| {
                signing_error(tr!(
                    "не удалось прочитать страницу PDF: {error}",
                    "could not read the PDF page: {error}"
                ))
            })?
            .clone();
        rotated_page.set(b"Rotate".to_vec(), Object::Integer(target_rotation));
        rotated_pages.push((target_id, rotated_page));
    }
    let (x0, y0, x1, y1) = box_in_page(stamp, page_width, page_height, rotation)?;
    let (x0, y0, x1, y1) = (x0 + page_x, y0 + page_y, x1 + page_x, y1 + page_y);
    let width = x1 - x0;
    let height = y1 - y0;
    // Стороны отмеченного прямоугольника на видимой стороне страницы: при 90/270
    // оси страницы переставлены относительно того, как отметку рисует пользователь.
    let (layout_width, layout_height) = if matches!(rotation, 90 | 270) {
        (height, width)
    } else {
        (width, height)
    };


    // Отметка набирается встроенным DejaVu Sans Condensed: кириллица и латиница
    // отображаются одинаково на любой системе.
    let texts = stamp_lines(stamp, signer);
    let lines: Vec<&str> = texts.iter().map(|(text, _)| text.as_str()).collect();
    let sizes: Vec<f64> = texts.iter().map(|(_, size)| *size).collect();
    let (encoded, cid_to_code) = embed_font::encode_lines_with_sizes(&lines, &sizes);
    // Существующие поля AcroForm нужны заранее: по ним подбирается уникальное имя.
    let acroform = match catalog.get(b"AcroForm") {
        Ok(Object::Reference(id)) => document.get_dictionary(*id).cloned().unwrap_or_default(),
        Ok(Object::Dictionary(dictionary)) => dictionary.clone(),
        _ => Dictionary::new(),
    };
    let mut fields = match acroform.get(b"Fields") {
        Ok(Object::Array(items)) => items.clone(),
        // /Fields может быть косвенной ссылкой на массив
        Ok(Object::Reference(id)) => document
            .get_object(*id)
            .and_then(Object::as_array)
            .cloned()
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    let field_name = unique_field_name(&document, &fields);
    let page = document
        .get_dictionary(page_id)
        .map_err(|error| {
            signing_error(tr!(
                "не удалось прочитать страницу PDF: {error}",
                "could not read the PDF page: {error}"
            ))
        })?
        .clone();
    let mut annots = existing_array(&document, &page, b"Annots")?;
    let mut new_page = page;
    let page_count = document.get_pages().len();
    let mut incremental = IncrementalDocument::create_from(source_bytes, document);
    // A hybrid revision's auxiliary stream belongs to /Prev, not the new revision.
    incremental.new_document.trailer.remove(b"XRefStm");
    let new_document = &mut incremental.new_document;
    let font_id = new_document.new_object_id();
    let font_file_id = new_document.new_object_id();
    let descriptor_id = new_document.new_object_id();
    let cid_font_id = new_document.new_object_id();
    let to_unicode_id = new_document.new_object_id();
    let appearance_id = new_document.new_object_id();
    let signature_id = new_document.new_object_id();
    let widget_id = new_document.new_object_id();
    let existing_acroform_id = match catalog.get(b"AcroForm") {
        Ok(Object::Reference(id)) => Some(*id),
        _ => None,
    };
    let acroform_id = existing_acroform_id.unwrap_or_else(|| new_document.new_object_id());

    let objects = embed_font::font_objects(&cid_to_code);
    new_document.set_object(font_file_id, objects.font_file);
    let mut descriptor = match objects.descriptor {
        Object::Dictionary(d) => d,
        _ => Dictionary::new(),
    };
    descriptor.set(b"FontFile2".to_vec(), Object::Reference(font_file_id));
    new_document.set_object(descriptor_id, Object::Dictionary(descriptor));

    let mut cid_font = match objects.cid_font {
        Object::Dictionary(d) => d,
        _ => Dictionary::new(),
    };
    cid_font.set(b"FontDescriptor".to_vec(), Object::Reference(descriptor_id));
    new_document.set_object(cid_font_id, Object::Dictionary(cid_font));
    new_document.set_object(to_unicode_id, objects.to_unicode);
    
    let font_dict = match objects.font {
        lopdf::Object::Dictionary(mut dict) => {
            dict.set(b"DescendantFonts".to_vec(), lopdf::Object::Array(vec![lopdf::Object::Reference(cid_font_id)]));
            dict.set(b"ToUnicode".to_vec(), lopdf::Object::Reference(to_unicode_id));
            dict
        }
        _ => lopdf::Dictionary::new(),
    };
    new_document.set_object(font_id, Object::Dictionary(font_dict));
    // Appearance аннотации просмотрщик поворачивает вместе со страницей, поэтому поток
    // компенсирует /Rotate: содержимое рисуется в координатах видимой стороны страницы.
    let [a, b, c, d, e, f] = appearance_transform(rotation, width, height);
    let mut content =
        format!("q {a:.4} {b:.4} {c:.4} {d:.4} {e:.4} {f:.4} cm\n").into_bytes();
    content.extend_from_slice(&appearance_content(&encoded, layout_width, layout_height));
    content.extend_from_slice(b"Q\n");
    let appearance = Stream::new(
        Dictionary::from_iter([
            (b"Type".to_vec(), Object::Name(b"XObject".to_vec())),
            (b"Subtype".to_vec(), Object::Name(b"Form".to_vec())),
            (
                b"BBox".to_vec(),
                Object::Array(vec![
                    Object::Integer(0),
                    Object::Integer(0),
                    Object::Real(width as f32),
                    Object::Real(height as f32),
                ]),
            ),
            (
                b"Resources".to_vec(),
                Object::Dictionary(Dictionary::from_iter([(
                    b"Font".to_vec(),
                    Object::Dictionary(Dictionary::from_iter([(
                        b"F0".to_vec(),
                        Object::Reference(font_id),
                    )])),
                )])),
            ),
            (b"FormType".to_vec(), Object::Integer(1)),
        ]),
        content,
    );
    new_document.set_object(appearance_id, Object::Stream(appearance));


    let signature = Dictionary::from_iter([
        (b"Type".to_vec(), Object::Name(b"Sig".to_vec())),
        (
            b"Filter".to_vec(),
            Object::Name(b"CryptoPro PDF".to_vec()),
        ),
        (
            b"SubFilter".to_vec(),
            Object::Name(b"ETSI.CAdES.detached".to_vec()),
        ),
        // Зарезервировано под CMS фиксированной длины; заполняется после записи файла.
        (
            b"Contents".to_vec(),
            Object::String(vec![0u8; reserved_contents_bytes()], StringFormat::Hexadecimal).into(),
        ),
        // Диапазон фиксированной ширины: заполняется на месте, длина файла не меняется.
        (
            b"ByteRange".to_vec(),
            Object::Array(vec![0.into(), 9_999_999_999i64.into(), 9_999_999_999i64.into(), 9_999_999_999i64.into()]),
        ),
        (b"M".to_vec(), pdf_date_string()),
        (
            b"Reason".to_vec(),
            text_string("Документ подписан электронной подписью"),
        ),
        (
            b"Name".to_vec(),
            Object::String(field_name.clone().into_bytes(), StringFormat::Literal).into(),
        ),
        (
            b"Location".to_vec(),
            Object::String(b"RU".to_vec(), StringFormat::Literal).into(),
        ),
        (b"ContactInfo".to_vec(), text_string(&signer.owner_name)),
    ]);
    new_document.set_object(signature_id, Object::Dictionary(signature));

    // Ссылки на существующие объекты в новых словарях обязательны: слайды/страница
    // остаются на месте, инкрементальное обновление их не трогает.
    let widget = Dictionary::from_iter([
        (b"Type".to_vec(), Object::Name(b"Annot".to_vec())),
        (b"Subtype".to_vec(), Object::Name(b"Widget".to_vec())),
        (b"FT".to_vec(), Object::Name(b"Sig".to_vec())),
        (
            b"T".to_vec(),
            Object::String(field_name.clone().into_bytes(), StringFormat::Literal).into(),
        ),
        (
            b"Rect".to_vec(),
            Object::Array(vec![
                Object::Real(x0 as f32),
                Object::Real(y0 as f32),
                Object::Real(x1 as f32),
                Object::Real(y1 as f32),
            ]),
        ),
        // Печатная отметка: аннотация не должна выводиться на экране отдельным блоком,
        // поэтому флаги — Print (4) + Locked (128), как у КриптоПро PDF.
        (b"F".to_vec(), Object::Integer(132)),
        (b"P".to_vec(), Object::Reference(page_id).into()),
        (b"V".to_vec(), Object::Reference(signature_id).into()),
        (
            b"AP".to_vec(),
            Object::Dictionary(Dictionary::from_iter([(
                b"N".to_vec(),
                Object::Reference(appearance_id).into(),
            )])),
        ),
    ]);
    new_document.set_object(widget_id, Object::Dictionary(widget));

    // Обновлённые версии страницы и каталога: старые объекты остаются в подписанных байтах
    // без изменений, новые версии переопределяют `/Annots` и `/AcroForm`.
    annots.push(Object::Reference(widget_id));
    new_page.set(b"Annots".to_vec(), Object::Array(annots));
    if rotation != current_rotation {
        new_page.set(b"Rotate".to_vec(), Object::Integer(rotation));
    }
    new_document.set_object(page_id, Object::Dictionary(new_page));
    fields.push(Object::Reference(widget_id));
    let mut new_acroform = acroform;
    new_acroform.set(b"Fields".to_vec(), Object::Array(fields));
    new_acroform.set(b"SigFlags".to_vec(), Object::Integer(3));
    new_document.set_object(acroform_id, Object::Dictionary(new_acroform));
    // Каталог переписываем только когда AcroForm ещё не был косвенным объектом:
    // иначе каталог остаётся байт-в-байт прежним, как у КриптоПро.
    if existing_acroform_id.is_none() {
        let mut new_catalog = catalog;
        new_catalog.set(b"AcroForm".to_vec(), Object::Reference(acroform_id));
        new_document.set_object(catalog_id, Object::Dictionary(new_catalog));
    }
    // Страницы без отметки поворачиваются отдельными словарями: содержимое и аннотации
    // не трогаются, поэтому старые подписи остаются валидными.
    for (target_id, rotated_page) in rotated_pages {
        new_document.set_object(target_id, Object::Dictionary(rotated_page));
    }

    let mut bytes = Vec::new();
    incremental.save_to(&mut bytes).map_err(|error| {
        signing_error(tr!(
            "не удалось записать ревизию PDF: {error}",
            "could not write the PDF revision: {error}"
        ))
    })?;
    Ok((bytes, page_count))
}

/// Сколько байт резервируется под CMS. CAdES-BES по ГОСТ с цепочкой 2–3 сертификатов
/// занимает 4–6 КБ; для ГОСТ 2012-512 подписи длиннее, поэтому резерв больше.
fn reserved_contents_bytes() -> usize {
    16 * 1024
}

/// Абсолютные позиции `/ByteRange`, `<` и `>` поля подписи.
///
/// В документе бывает несколько `/Contents` (например, содержимое страницы), поэтому поле
/// ищется по последнему `/Contents<` и соседнему `/ByteRange` нашего writer.
pub fn locate(bytes: &[u8]) -> Result<(usize, usize, usize), SignerError> {
    let contents_at = locate_contents(bytes).ok_or_else(|| {
        signing_error(tr!(
            "не удалось найти поле подписи в подготовленном PDF",
            "could not find the signature field in the prepared PDF"
        ))
    })?;
    let mut contents_end = contents_at + 1;
    while contents_end < bytes.len() && bytes[contents_end] != b'>' {
        if !bytes[contents_end].is_ascii_hexdigit() {
            return Err(signing_error(tr!(
                "повреждено поле /Contents подписи PDF",
                "the PDF signature /Contents field is corrupted"
            )));
        }
        contents_end += 1;
    }
    if contents_end >= bytes.len() {
        return Err(signing_error(tr!(
            "не закрыто поле /Contents подписи PDF",
            "the PDF signature /Contents field is not closed"
        )));
    }
    let marker = b"/ByteRange";
    let before = contents_at.saturating_sub(1024)..contents_at;
    let after_end = (contents_end + 1024).min(bytes.len());
    let offsets_at = search_back(bytes, before, marker)
        .or_else(|| {
            find_subsequence(&bytes[contents_end..after_end], marker).map(|p| contents_end + p)
        })
        .map(|at| at + marker.len())
        .ok_or_else(|| {
            signing_error(tr!(
                "не удалось найти диапазон подписи в PDF",
                "could not find the signature byte range in the PDF"
            ))
        })?;
    Ok((offsets_at, contents_at, contents_end))
}

/// Позиция `<` последнего `/Contents<` (граница подписываемого префикса).
fn locate_contents(bytes: &[u8]) -> Option<usize> {
    let needle = b"/Contents<";
    let mut found = None;
    let mut start = 0;
    while let Some(position) = find_subsequence(&bytes[start..], needle) {
        found = Some(start + position + needle.len() - 1);
        start += position + needle.len();
    }
    found
}

/// Подписываемые байты по ISO 32000-1, 7.6.2: всё до `<` в `/Contents` и всё после `>`.
pub fn signed_slices(
    bytes: &[u8],
    contents_at: usize,
    contents_end: usize,
) -> Result<(&[u8], &[u8]), SignerError> {
    if contents_end >= bytes.len() || contents_at == 0 || contents_at > contents_end {
        return Err(signing_error(tr!(
            "поле подписи вне документа: <{} .. {}>, файл {} байт",
            "signature field is outside the document: <{} .. {}>, file is {} bytes",
            contents_at,
            contents_end,
            bytes.len()
        )));
    }
    Ok((&bytes[..contents_at], &bytes[contents_end + 1..]))
}

/// Склеивает подписываемые байты в один буфер: CSP хэширует непрерывный поток.
pub fn signed_content(
    bytes: &[u8],
    contents_at: usize,
    contents_end: usize,
) -> Result<Vec<u8>, SignerError> {
    let (head, tail) = signed_slices(bytes, contents_at, contents_end)?;
    let mut content = Vec::with_capacity(head.len() + tail.len());
    content.extend_from_slice(head);
    content.extend_from_slice(tail);
    Ok(content)
}

/// Поле AcroForm с подписью: словарь поля и его объект, если поле косвенное.
struct SignatureField {
    id: Option<lopdf::ObjectId>,
    dictionary: Dictionary,
}

/// Встроенная подпись PDF: словарь `/V` поля AcroForm с типом `/FT /Sig`.
pub struct EmbeddedSignature {
    pub field_name: String,
    /// Номер страницы с отметкой, считая с нуля.
    pub page: Option<usize>,
    /// Прямоугольник отметки в мм от левого верхнего угла видимой стороны страницы.
    pub rect_mm: Option<(f64, f64, f64, f64)>,
    pub sub_filter: String,
    pub signed_at: String,
    /// Диапазоны `/ByteRange` покрывают файл целиком, кроме поля `/Contents`.
    pub covers_document: bool,
    /// Подписанные байты: склейка диапазонов `/ByteRange`.
    pub content: Option<Vec<u8>>,
    /// CMS из `/Contents` без нулевого запаса.
    pub cms: Option<Vec<u8>>,
    /// Почему подпись нельзя проверить: повреждён словарь, диапазон или CMS.
    pub problem: Option<String>,
}

/// Перечисляет подписи документа в порядке полей AcroForm.
pub fn embedded_signatures(bytes: &[u8]) -> Result<Vec<EmbeddedSignature>, SignerError> {
    let document = Document::load_mem(bytes).map_err(|error| {
        signing_error(tr!(
            "не удалось прочитать PDF: {error}",
            "could not read the PDF: {error}"
        ))
    })?;
    if document.is_encrypted() {
        return Err(signing_error(tr!(
            "PDF защищён паролем: проверка встроенных подписей такого документа пока не поддерживается",
            "the PDF is password-protected: verification of embedded signatures is not supported yet"
        )));
    }
    let catalog_id = document
        .trailer
        .get(b"Root")
        .and_then(Object::as_reference)
        .map_err(|error| {
            signing_error(tr!(
                "не найден каталог PDF: {error}",
                "PDF catalog not found: {error}"
            ))
        })?;
    let catalog = document.get_dictionary(catalog_id).map_err(|error| {
        signing_error(tr!(
            "не удалось прочитать каталог PDF: {error}",
            "could not read the PDF catalog: {error}"
        ))
    })?;
    let pages_id = catalog
        .get(b"Pages")
        .and_then(Object::as_reference)
        .map_err(|error| {
            signing_error(tr!(
                "не найдено дерево страниц PDF: {error}",
                "PDF page tree not found: {error}"
            ))
        })?;
    let mut page_ids = Vec::new();
    collect_pages(&document, pages_id, &mut page_ids, 0)?;
    let mut fields = Vec::new();
    collect_signature_fields(&document, catalog, None, &mut fields, 0);
    Ok(fields
        .iter()
        .map(|field| read_signature(&document, bytes, pages_id, &page_ids, field))
        .collect())
}

/// Обходит `/AcroForm /Fields`, разворачивая `/Kids` полей и виджетов.
fn collect_signature_fields(
    document: &Document,
    catalog: &Dictionary,
    acroform_ft: Option<Vec<u8>>,
    out: &mut Vec<SignatureField>,
    depth: usize,
) {
    if depth > 64 {
        return;
    }
    let acroform = match catalog.get(b"AcroForm") {
        Ok(Object::Reference(id)) => document.get_dictionary(*id).ok().cloned(),
        Ok(Object::Dictionary(dictionary)) => Some(dictionary.clone()),
        _ => None,
    };
    let Some(acroform) = acroform else {
        return;
    };
    let fields = match acroform.get(b"Fields") {
        Ok(Object::Array(items)) => items.clone(),
        Ok(Object::Reference(id)) => document
            .get_object(*id)
            .and_then(Object::as_array)
            .cloned()
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    let inherited = acroform
        .get(b"FT")
        .ok()
        .and_then(|value| value.as_name().ok())
        .map(<[u8]>::to_vec)
        .or(acroform_ft);
    for item in &fields {
        walk_signature_field(document, item, inherited.clone(), out, depth + 1);
    }
}

fn walk_signature_field(
    document: &Document,
    item: &Object,
    inherited_ft: Option<Vec<u8>>,
    out: &mut Vec<SignatureField>,
    depth: usize,
) {
    if depth > 64 {
        return;
    }
    let (id, dictionary) = match item {
        Object::Reference(id) => match document.get_dictionary(*id) {
            Ok(dictionary) => (Some(*id), dictionary.clone()),
            Err(_) => return,
        },
        Object::Dictionary(dictionary) => (None, dictionary.clone()),
        _ => return,
    };
    let field_type = dictionary
        .get(b"FT")
        .ok()
        .and_then(|value| value.as_name().ok())
        .map(<[u8]>::to_vec)
        .or_else(|| inherited_ft.clone());
    // Терминальное поле подписи хранит и `/V`, и (обычно) `/Rect` виджета.
    if field_type.as_deref() == Some(b"Sig") && dictionary.get(b"V").is_ok() {
        out.push(SignatureField { id, dictionary });
        return;
    }
    if let Ok(kids) = dictionary.get(b"Kids").and_then(Object::as_array) {
        for kid in kids {
            walk_signature_field(document, kid, field_type.clone(), out, depth + 1);
        }
    }
}

fn read_signature(
    document: &Document,
    bytes: &[u8],
    pages_id: lopdf::ObjectId,
    page_ids: &[lopdf::ObjectId],
    field: &SignatureField,
) -> EmbeddedSignature {
    let mut signature = EmbeddedSignature {
        field_name: field_name(document, field),
        page: None,
        rect_mm: None,
        sub_filter: String::new(),
        signed_at: String::new(),
        covers_document: false,
        content: None,
        cms: None,
        problem: None,
    };
    let Some(value) = resolve_dictionary(document, field.dictionary.get(b"V").ok()) else {
        signature.problem = Some(tr!(
            "поле подписи PDF не содержит подпись",
            "the PDF signature field has no signature"
        ));
        return signature;
    };
    signature.sub_filter = value
        .get(b"SubFilter")
        .and_then(Object::as_name)
        .map(|name| String::from_utf8_lossy(name).into_owned())
        .unwrap_or_default();
    signature.signed_at = value
        .get(b"M")
        .ok()
        .and_then(string_bytes)
        .map(|raw| format_pdf_date(&raw))
        .unwrap_or_default();
    match value.get(b"Contents").ok().and_then(string_bytes) {
        Some(contents) => match trim_der(&contents) {
            Ok(der) => signature.cms = Some(der.to_vec()),
            Err(error) => signature.problem = Some(error.to_string()),
        },
        None => {
            signature.problem = Some(tr!(
                "в подписи PDF нет поля /Contents",
                "the PDF signature has no /Contents field"
            ))
        }
    }
    match value.get(b"ByteRange").ok().and_then(byte_ranges) {
        Some(ranges) => {
            signature.covers_document = covers_document(&ranges, bytes.len());
            match signed_ranges(bytes, &ranges) {
                Ok(content) => signature.content = Some(content),
                Err(error) => signature.problem = Some(error.to_string()),
            }
        }
        None => {
            signature.problem = Some(tr!(
                "в подписи PDF нет поля /ByteRange",
                "the PDF signature has no /ByteRange field"
            ))
        }
    }
    if let Some((page_id, rect)) = widget_placement(document, field, page_ids) {
        signature.page = page_ids.iter().position(|id| *id == page_id);
        if let (Some(rect), Ok((page_x, page_y, page_width, page_height))) =
            (rect, page_box(document, pages_id, page_id))
        {
            let rect = (
                rect.0 - page_x,
                rect.1 - page_y,
                rect.2 - page_x,
                rect.3 - page_y,
            );
            let rotation = page_rotation(document, pages_id, page_id);
            signature.rect_mm = Some(widget_box_mm(rotation, page_width, page_height, rect));
        }
    }
    signature
}

fn field_name(document: &Document, field: &SignatureField) -> String {
    let mut parts = Vec::new();
    let mut dictionary = Some(field.dictionary.clone());
    let mut depth = 0;
    // Полное имя поля складывается из /T всех родителей.
    while let Some(current) = dictionary {
        if depth > 16 {
            break;
        }
        if let Some(name) = current.get(b"T").ok().and_then(string_bytes) {
            parts.push(String::from_utf8_lossy(&name).into_owned());
        }
        dictionary = current
            .get(b"Parent")
            .and_then(Object::as_reference)
            .ok()
            .and_then(|id| document.get_dictionary(id).ok().cloned());
        depth += 1;
    }
    parts.reverse();
    if parts.is_empty() {
        tr!("без имени", "unnamed").to_owned()
    } else {
        parts.join(".")
    }
}

/// Страница и прямоугольник виджета: `/P` поля, виджета в `/Kids` или ссылка в `/Annots`.
fn widget_placement(
    document: &Document,
    field: &SignatureField,
    page_ids: &[lopdf::ObjectId],
) -> Option<(lopdf::ObjectId, Option<(f64, f64, f64, f64)>)> {
    let rect_of = |dictionary: &Dictionary| {
        dictionary
            .get(b"Rect")
            .ok()
            .and_then(object_box)
    };
    if let Some(page) = field
        .dictionary
        .get(b"P")
        .and_then(Object::as_reference)
        .ok()
    {
        return Some((page, rect_of(&field.dictionary)));
    }
    if let Ok(kids) = field.dictionary.get(b"Kids").and_then(Object::as_array) {
        for kid in kids {
            let Some(kid) = resolve_dictionary(document, Some(kid)) else {
                continue;
            };
            if let Some(page) = kid.get(b"P").and_then(Object::as_reference).ok() {
                return Some((page, rect_of(&kid)));
            }
        }
    }
    let target = field.id?;
    for page_id in page_ids {
        let Ok(page) = document.get_dictionary(*page_id) else {
            continue;
        };
        let annots = match page.get(b"Annots") {
            Ok(Object::Array(items)) => items.clone(),
            Ok(Object::Reference(id)) => document
                .get_object(*id)
                .and_then(Object::as_array)
                .cloned()
                .unwrap_or_default(),
            _ => continue,
        };
        if annots
            .iter()
            .any(|item| item.as_reference().ok() == Some(target))
        {
            return Some((*page_id, rect_of(&field.dictionary)));
        }
    }
    None
}

fn resolve_dictionary(document: &Document, value: Option<&Object>) -> Option<Dictionary> {
    match value? {
        Object::Dictionary(dictionary) => Some(dictionary.clone()),
        Object::Reference(id) => document.get_dictionary(*id).ok().cloned(),
        _ => None,
    }
}

fn string_bytes(value: &Object) -> Option<Vec<u8>> {
    match value {
        Object::String(bytes, _) => Some(bytes.clone()),
        _ => None,
    }
}

/// `/Rect` в `(x0, y0, x1, y1)` с сохранением исходного порядка углов.
fn object_box(value: &Object) -> Option<(f64, f64, f64, f64)> {
    let items = value.as_array().ok()?;
    if items.len() < 4 {
        return None;
    }
    let number = |item: &Object| match item {
        Object::Integer(value) => Some(*value as f64),
        Object::Real(value) => Some(f64::from(*value)),
        _ => None,
    };
    Some((
        number(&items[0])?,
        number(&items[1])?,
        number(&items[2])?,
        number(&items[3])?,
    ))
}

/// `/ByteRange` — пары «смещение, длина».
fn byte_ranges(value: &Object) -> Option<Vec<(usize, usize)>> {
    let items = value.as_array().ok()?;
    if items.len() < 4 || items.len() % 2 != 0 {
        return None;
    }
    let numbers = items
        .iter()
        .map(|item| {
            item.as_i64()
                .ok()
                .and_then(|number| usize::try_from(number).ok())
        })
        .collect::<Option<Vec<_>>>()?;
    Some(
        numbers
            .chunks_exact(2)
            .map(|pair| (pair[0], pair[1]))
            .collect(),
    )
}

/// Подпись покрывает весь файл: два диапазона, от начала и до конца, с одной дырой.
fn covers_document(ranges: &[(usize, usize)], length: usize) -> bool {
    if ranges.len() != 2 {
        return false;
    }
    let (start, first) = ranges[0];
    let (second_start, second) = ranges[1];
    start == 0
        && first > 0
        && second_start > first
        && second_start
            .checked_add(second)
            .is_some_and(|end| end == length)
}

fn signed_ranges(bytes: &[u8], ranges: &[(usize, usize)]) -> Result<Vec<u8>, SignerError> {
    let mut content = Vec::new();
    for (start, length) in ranges {
        let end = start.checked_add(*length).ok_or_else(|| {
            signing_error(tr!(
                "диапазон подписи PDF переполнен: {start}+{length}",
                "the PDF signature byte range overflows: {start}+{length}"
            ))
        })?;
        let slice = bytes.get(*start..end).ok_or_else(|| {
            signing_error(tr!(
                "диапазон подписи выходит за пределы PDF: {start}+{length} из {} байт",
                "the signature byte range is outside the PDF: {start}+{length} of {} bytes",
                bytes.len()
            ))
        })?;
        content.extend_from_slice(slice);
    }
    Ok(content)
}

/// Прямоугольник виджета (pt, координаты страницы) → мм видимой стороны страницы.
///
/// Обратное преобразование к [`box_in_page`]: точки страницы переводятся в систему
/// видимой стороны (`/CropBox` после `/Rotate`), ось Y направлена вниз.
fn widget_box_mm(
    rotation: i64,
    page_width: f64,
    page_height: f64,
    rect: (f64, f64, f64, f64),
) -> (f64, f64, f64, f64) {
    let (x0, y0, x1, y1) = rect;
    let x = x0.min(x1);
    let y = y0.min(y1);
    let width = (x1 - x0).abs();
    let height = (y1 - y0).abs();
    let (left, top, visible_width, visible_height) = match rotation {
        90 => (y, x, height, width),
        180 => (page_width - x - width, y, width, height),
        270 => (
            page_height - y - height,
            page_width - x - width,
            height,
            width,
        ),
        _ => (x, page_height - y - height, width, height),
    };
    let mm = |value: f64| value * 25.4 / 72.0;
    (
        mm(left),
        mm(top),
        mm(visible_width),
        mm(visible_height),
    )
}

/// `D:YYYYMMDDHHmmSS±hh'mm'` из `/M` → `DD.MM.YYYY HH:MM:SS`.
fn format_pdf_date(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw).trim().to_owned();
    let digits = text.trim_start_matches("D:").trim();
    let digits = digits
        .chars()
        .take(14)
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    if digits.len() < 8 {
        return text;
    }
    let part = |range: std::ops::Range<usize>| digits[range].to_string();
    let date = format!("{}.{}.{}", part(6..8), part(4..6), part(0..4));
    if digits.len() >= 14 {
        format!("{date} {}:{}:{}", part(8..10), part(10..12), part(12..14))
    } else {
        date
    }
}

/// Записывает `/ByteRange` и CMS в подготовленный файл. Длина файла не меняется:
/// диапазон и содержимое занимают ровно те места, что и заглушки.
pub fn assemble_document(
    staged: &[u8],
    contents_at: usize,
    contents_end: usize,
    cms: &[u8],
) -> Result<Vec<u8>, SignerError> {
    let (offsets_at, located_at, located_end) = locate(staged)?;
    if located_at != contents_at || located_end != contents_end {
        return Err(signing_error(tr!(
            "подпись относится к другому положению поля PDF",
            "the signature belongs to a different PDF field position"
        )));
    }
    if cms.is_empty() {
        return Err(signing_error(tr!(
            "пустая CMS подписи PDF",
            "the PDF signature CMS is empty"
        )));
    }
    let cms = trim_der(cms)?;
    let capacity = contents_end.saturating_sub(contents_at + 1);
    if cms.len() * 2 > capacity {
        return Err(signing_error(tr!(
            "подпись не помещается в зарезервированное поле PDF: {} > {} байт",
            "the signature does not fit the reserved PDF field: {} > {} bytes",
            cms.len(),
            capacity / 2
        )));
    }
    let mut output = staged.to_vec();
    write_byte_range(&mut output, offsets_at, contents_at, contents_end)?;
    // CMS — hex, остаток поля нулями, как у КриптоПро PDF и Acrobat.
    let hex: Vec<u8> = cms
        .iter()
        .flat_map(|byte| format!("{byte:02X}").into_bytes())
        .collect();
    output[contents_at + 1..contents_at + 1 + hex.len()].copy_from_slice(&hex);
    let rest = contents_at + 1 + hex.len()..contents_end;
    output[rest].fill(b'0');
    Ok(output)
}


/// Вписывает CMS в `/Contents` и записывает подписанный PDF (существующий файл не перезаписывается).
pub fn finish(
    prepared: &PreparedDocument,
    payload: &PdfSignaturePayload,
    output_path: &Path,
) -> Result<SignResult, SignerError> {
    let (_, contents_at, contents_end) = locate(&prepared.bytes)?;
    if payload.contents_at != contents_at {
        return Err(signing_error(tr!(
            "подпись относится к другому положению поля PDF",
            "the signature belongs to a different PDF field position"
        )));
    }
    let bytes = assemble_document(&prepared.bytes, contents_at, contents_end, &payload.cms)?;

    let final_path = super::output::write_unique(output_path, &bytes).map_err(|error| {
        signing_error(tr!(
            "не удалось записать подписанный PDF ({}): {error}",
            "could not write the signed PDF ({}): {error}",
            output_path.display()
        ))
    })?;
    // Временный файл удалит Drop у PreparedDocument.
    Ok(SignResult {
        output_path: final_path.display().to_string(),
        bytes_written: bytes.len(),
    })
}

/// Текст в PDF-строке: юникод как UTF-16BE с BOM, чтобы кириллица не зависела от кодировки.
fn text_string(text: &str) -> Object {
    let mut bytes = vec![0xFEu8, 0xFF];
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_be_bytes());
    }
    Object::String(bytes, StringFormat::Literal)
}

/// Свободное имя поля подписи: Signature1, Signature2, … среди уже существующих полей.
fn unique_field_name(document: &Document, fields: &[Object]) -> String {
    let used: std::collections::HashSet<Vec<u8>> = fields
        .iter()
        .filter_map(|field| {
            let dict = match field {
                Object::Reference(id) => document.get_dictionary(*id).ok()?,
                Object::Dictionary(d) => d,
                _ => return None,
            };
            dict.get(b"T").ok()?.as_str().ok().map(|s| s.to_vec())
        })
        .collect();
    (1..)
        .map(|n| format!("Signature{n}"))
        .find(|name| !used.contains(name.as_bytes()))
        .unwrap()
}

fn certificate_info(certificate_id: &str) -> Result<CertInfo, SignerError> {
    use crate::signer::Signer as _;
    crate::signer::native::NativeSigner
        .list_certs()?
        .into_iter()
        .find(|certificate| certificate.id == certificate_id)
        .ok_or_else(|| {
            signing_error(tr!(
                "выбранный сертификат больше не найден в Windows Personal",
                "the selected certificate is no longer present in the Windows Personal store"
            ))
        })
}

fn staging_path(source: &Path) -> PathBuf {
    let name = source
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "document.pdf".to_owned());
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("cryptolite-{}-{nanos}-{name}", std::process::id()))
}

/// Обрезает хвост после DER-структуры CMS (буфер мог прийти с нулевым запасом).
fn trim_der(cms: &[u8]) -> Result<&[u8], SignerError> {
    if cms.len() < 2 || cms[0] != 0x30 {
        return Err(signing_error(tr!(
            "CMS не начинается с DER SEQUENCE",
            "the CMS does not start with a DER SEQUENCE"
        )));
    }
    let (header, len) = match cms[1] {
        n if n < 0x80 => (2, n as usize),
        0x80 => return Ok(cms), // BER с неопределённой длиной: обрезать нельзя
        n => {
            let k = (n & 0x7F) as usize;
            if k > 4 || cms.len() < 2 + k {
                return Err(signing_error(tr!(
                    "некорректная длина CMS",
                    "invalid CMS length"
                )));
            }
            let len = cms[2..2 + k].iter().fold(0usize, |a, &b| (a << 8) | b as usize);
            (2 + k, len)
        }
    };
    let total = header + len;
    if total > cms.len() {
        return Err(signing_error(tr!(
            "CMS короче, чем заявлено в заголовке",
            "the CMS is shorter than declared in its header"
        )));
    }
    Ok(&cms[..total])
}

/// Вписывает финальный /ByteRange в буфер (длина файла не меняется).
fn write_byte_range(
    out: &mut [u8],
    offsets_at: usize,
    contents_at: usize,
    contents_end: usize,
) -> Result<(), SignerError> {
    let br_len = OFFSETS.len();
    if out.get(offsets_at) != Some(&b'[') || out.get(offsets_at + br_len - 1) != Some(&b']') {
        return Err(signing_error(tr!(
            "заглушка /ByteRange не на своём месте",
            "the /ByteRange placeholder is not in place"
        )));
    }
    let tail_start = contents_end + 1;
    let text = format!("[0 {} {} {}", contents_at, tail_start, out.len() - tail_start);
    if text.len() >= br_len {
        return Err(signing_error(tr!(
            "диапазон подписи не помещается в заглушку",
            "the signature byte range does not fit the placeholder"
        )));
    }
    let mut field = text.into_bytes();
    field.resize(br_len - 1, b' ');
    field.push(b']');
    out[offsets_at..offsets_at + br_len].copy_from_slice(&field);
    Ok(())
}

/// Копия подготовленного PDF с записанным /ByteRange: её и нужно хэшировать.
pub fn with_byte_range(staged: &[u8]) -> Result<(Vec<u8>, usize, usize), SignerError> {
    let (offsets_at, contents_at, contents_end) = locate(staged)?;
    let mut out = staged.to_vec();
    write_byte_range(&mut out, offsets_at, contents_at, contents_end)?;
    Ok((out, contents_at, contents_end))
}
/// Передаёт staging-файл внешнему подписанту; finish восстанавливает владение файлом.
pub fn export_prepared(mut prepared: PreparedDocument) -> Result<PdfSignPrepareResult, SignerError> {
    let (bytes, contents_at, contents_end) = with_byte_range(&prepared.bytes)?;
    let signed_bytes = signed_content(&bytes, contents_at, contents_end)?;
    let path = prepared.path.take().ok_or_else(|| {
        signing_error(tr!(
            "не найден временный файл подготовленного PDF",
            "prepared PDF temporary file not found"
        ))
    })?;
    Ok(PdfSignPrepareResult {
        prepared_path: path.display().to_string(),
        signed_bytes,
        contents_at,
        page_count: prepared.page_count,
    })
}


fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}


fn search_back(haystack: &[u8], range: std::ops::Range<usize>, needle: &[u8]) -> Option<usize> {
    let start = range.start.min(haystack.len());
    let end = range.end.min(haystack.len());
    if start >= end {
        return None;
    }
    haystack[start..end]
        .windows(needle.len())
        .rposition(|window| window == needle)
        .map(|position| start + position)
}

/// Существующий массив ссылок (`/Annots`) страницы, включая унаследованный от `/Pages`.
fn existing_array(
    document: &Document,
    page: &Dictionary,
    key: &[u8],
) -> Result<Vec<Object>, SignerError> {
    let value = match page.get(key) {
        Ok(Object::Array(items)) => return Ok(items.clone()),
        Ok(Object::Reference(id)) => document
            .get_object(*id)
            .and_then(Object::as_array)
            .cloned()
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    Ok(value)
}

fn page_object_id(
    document: &Document,
    pages_id: lopdf::ObjectId,
    index: usize,
) -> Result<lopdf::ObjectId, SignerError> {
    let mut pages = Vec::new();
    collect_pages(document, pages_id, &mut pages, 0)?;
    pages.get(index).copied().ok_or_else(|| {
        signing_error(tr!(
            "в PDF нет страницы {} (всего {})",
            "the PDF has no page {} ({} total)",
            index + 1,
            pages.len()
        ))
    })
}

/// Обход дерева страниц `/Pages` с учётом того, что часть дочерних узлов может быть
/// внутри потоков объектов.
fn collect_pages(
    document: &Document,
    node: lopdf::ObjectId,
    pages: &mut Vec<lopdf::ObjectId>,
    depth: usize,
) -> Result<(), SignerError> {
    if depth > 64 {
        return Err(signing_error(tr!(
            "дерево страниц PDF вложено слишком глубоко",
            "the PDF page tree is nested too deeply"
        )));
    }
    let dictionary = document.get_dictionary(node).map_err(|error| {
        signing_error(tr!(
            "не удалось прочитать страницу PDF: {error}",
            "could not read the PDF page: {error}"
        ))
    })?;
    let kind = dictionary
        .get(b"Type")
        .and_then(Object::as_name)
        .unwrap_or_default();
    if kind == b"Pages" {
        let kids = dictionary
            .get(b"Kids")
            .and_then(Object::as_array)
            .map_err(|error| {
                signing_error(tr!(
                    "нет /Kids в дереве страниц: {error}",
                    "no /Kids in the page tree: {error}"
                ))
            })?;
        for kid in kids {
            if let Ok(kid) = kid.as_reference() {
                collect_pages(document, kid, pages, depth + 1)?;
            }
        }
    } else {
        pages.push(node);
    }
    Ok(())
}

fn inheritable(
    document: &Document,
    page: &Dictionary,
    pages_id: lopdf::ObjectId,
    key: &[u8],
) -> Option<Object> {
    if let Ok(value) = page.get(key) {
        return Some(value.clone());
    }
    let mut node = pages_id;
    for _ in 0..16 {
        let dictionary = document.get_dictionary(node).ok()?;
        if let Ok(value) = dictionary.get(key) {
            return Some(value.clone());
        }
        node = dictionary.get(b"Parent").ok()?.as_reference().ok()?;
    }
    None
}

/// Приводит `/MediaBox`/`/CropBox` к `(x0, y0, x1, y1)` независимо от порядка углов.
fn normalized_box(value: Object, name: &str) -> Result<(f64, f64, f64, f64), SignerError> {
    let invalid = || {
        signing_error(tr!(
            "некорректный {name} страницы PDF",
            "invalid PDF page {name}"
        ))
    };
    let arrays = value.as_array().map_err(|_| invalid())?;
    let values = arrays
        .iter()
        .map(|value| value.as_float().map(f64::from))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid())?;
    if values.len() != 4 {
        return Err(invalid());
    }
    Ok((
        values[0].min(values[2]),
        values[1].min(values[3]),
        values[0].max(values[2]),
        values[1].max(values[3]),
    ))
}

/// Видимая область страницы: `(x0, y0, ширина, высота)` из `/CropBox` ∩ `/MediaBox`.
fn page_box(
    document: &Document,
    pages_id: lopdf::ObjectId,
    page_id: lopdf::ObjectId,
) -> Result<(f64, f64, f64, f64), SignerError> {
    let page = document.get_dictionary(page_id).map_err(|error| {
        signing_error(tr!(
            "не удалось прочитать страницу PDF: {error}",
            "could not read the PDF page: {error}"
        ))
    })?;
    let media_value = inheritable(document, page, pages_id, b"MediaBox")
        .or_else(|| inheritable(document, page, pages_id, b"CropBox"))
        .ok_or_else(|| {
            signing_error(tr!(
                "в странице PDF нет MediaBox",
                "the PDF page has no MediaBox"
            ))
        })?;
    let (media_x0, media_y0, media_x1, media_y1) = normalized_box(media_value, "MediaBox")?;
    // Битый CropBox игнорируется, как и в просмотрщиках: остаётся MediaBox.
    let Some((crop_x0, crop_y0, crop_x1, crop_y1)) =
        inheritable(document, page, pages_id, b"CropBox")
            .and_then(|value| normalized_box(value, "CropBox").ok())
    else {
        return Ok((media_x0, media_y0, media_x1 - media_x0, media_y1 - media_y0));
    };
    let (x0, y0) = (media_x0.max(crop_x0), media_y0.max(crop_y0));
    let (x1, y1) = (media_x1.min(crop_x1), media_y1.min(crop_y1));
    if x1 <= x0 || y1 <= y0 {
        return Err(signing_error(tr!(
            "видимая область страницы PDF пуста (CropBox не пересекает MediaBox)",
            "the PDF page's visible area is empty (CropBox does not intersect MediaBox)"
        )));
    }
    Ok((x0, y0, x1 - x0, y1 - y0))
}

fn page_rotation(document: &Document, pages_id: lopdf::ObjectId, page_id: lopdf::ObjectId) -> i64 {
    match document
        .get_dictionary(page_id)
        .ok()
        .and_then(|page| inheritable(document, page, pages_id, b"Rotate"))
        .and_then(|value| value.as_i64().ok())
        .unwrap_or(0)
        .rem_euclid(360)
    {
        rotation @ (90 | 180 | 270) => rotation,
        _ => 0,
    }
}

/// Проверяет угол из запроса и приводит его к 0/90/180/270.
fn normalized_rotation(rotation: i64) -> Result<i64, SignerError> {
    if rotation.rem_euclid(90) != 0 {
        return Err(signing_error(tr!(
            "поворот страницы PDF должен быть кратен 90°: {rotation}",
            "the PDF page rotation must be a multiple of 90°: {rotation}"
        )));
    }
    Ok(rotation.rem_euclid(360))
}

fn mm_to_points(mm: f64) -> f64 {
    mm * 72.0 / 25.4
}

/// Переводит прямоугольник (мм от левого верхнего угла видимой области страницы) в координаты PDF.
///
/// `page_width`/`page_height` — размер видимой области (`/CropBox`), на который вызывающий код
/// уже накладывает её начало координат. Видимая сторона страницы может быть повёрнута на
/// 0/90/180/270, поэтому координаты считаются в системе «после поворота» и переводятся обратно.
fn box_in_page(
    stamp: &PdfStampSpec,
    page_width: f64,
    page_height: f64,
    rotation: i64,
) -> Result<(f64, f64, f64, f64), SignerError> {
    let swapped = rotation == 90 || rotation == 270;
    let (display_width, display_height) = if swapped {
        (page_height, page_width)
    } else {
        (page_width, page_height)
    };
    let left = mm_to_points(stamp.left_mm);
    let top = mm_to_points(stamp.top_mm);
    let width = mm_to_points(stamp.width_mm);
    let height = mm_to_points(stamp.height_mm);
    if width <= 0.0 || height <= 0.0 {
        return Err(signing_error(tr!(
            "область отметки пуста: нарисуйте прямоугольник штампа",
            "the signature mark area is empty: draw a stamp rectangle"
        )));
    }
    if left < -0.5
        || top < -0.5
        || left + width > display_width + 0.5
        || top + height > display_height + 0.5
    {
        return Err(signing_error(tr!(
            "область отметки выходит за пределы страницы PDF",
            "the signature mark area is outside the PDF page"
        )));
    }
    if rotation == 0 {
        let bottom = display_height - (top + height);
        return Ok((left, bottom, left + width, display_height - top));
    }
    // Видимая точка (u, v) на повёрнутой странице → система координат страницы.
    let to_page = |u: f64, v: f64| -> (f64, f64) {
        match rotation {
            90 => (v, u),
            270 => (page_width - v, page_height - u),
            180 => (page_width - u, v),
            _ => (u, page_height - v),
        }
    };
    let corners = [
        to_page(left, top),
        to_page(left + width, top),
        to_page(left, top + height),
        to_page(left + width, top + height),
    ];
    let x0 = corners.iter().map(|(x, _)| *x).fold(f64::MAX, f64::min);
    let x1 = corners.iter().map(|(x, _)| *x).fold(f64::MIN, f64::max);
    let y0 = corners.iter().map(|(_, y)| *y).fold(f64::MAX, f64::min);
    let y1 = corners.iter().map(|(_, y)| *y).fold(f64::MIN, f64::max);
    Ok((x0, y0, x1, y1))
}

/// Матрица перевода системы координат отметки (видимая сторона страницы, ось Y вверх,
/// начало — левый нижний угол рамки) в координаты страницы PDF.
///
/// `width`/`height` — стороны appearance-рамки в координатах страницы. Просмотрщик
/// поворачивает аннотации вместе со страницей, поэтому без компенсации `/Rotate` текст
/// встаёт боком, а строки центрируются по перепутанным осям.
fn appearance_transform(rotation: i64, width: f64, height: f64) -> [f64; 6] {
    match rotation {
        90 => [0.0, 1.0, -1.0, 0.0, width, 0.0],
        180 => [-1.0, 0.0, 0.0, -1.0, width, height],
        270 => [0.0, -1.0, 1.0, 0.0, 0.0, height],
        _ => [1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
    }
}

fn pdf_date_string() -> Object {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    // Дата в UTC: отметка об ЭП не зависит от часового пояса рабочей станции.
    let (year, month, day, hour, minute, second) = civil_from_epoch(now);
    Object::String(
        format!("D:{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z").into_bytes(),
        StringFormat::Literal,
    )
}

/// Дата по Unix-времени (алгоритм Хауарда Хиннанта `civil_from_days`).
fn civil_from_epoch(timestamp: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = timestamp.div_euclid(86_400);
    let seconds = timestamp.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (
        year,
        month,
        day,
        (seconds / 3600) as u32,
        ((seconds % 3600) / 60) as u32,
        (seconds % 60) as u32,
    )
}

/// Делит ФИО владельца на строки не длиннее `limit` символов, разрывая только по пробелам.
///
/// Слово длиннее `limit` не разрезается: оно занимает отдельную строку целиком.
fn wrap_owner_name(name: &str, limit: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();
    for word in name.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.chars().count() + 1 + word.chars().count() <= limit {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

/// Строки отметки по ГОСТ Р 7.0.97-2025, п. 5.23: текст и кегль.
fn stamp_lines(stamp: &PdfStampSpec, signer: &CertInfo) -> Vec<(String, f64)> {
    let mut lines: Vec<(String, f64)> = vec![
        ("ДОКУМЕНТ ПОДПИСАН".to_owned(), 6.5),
        ("ЭЛЕКТРОННОЙ ПОДПИСЬЮ".to_owned(), 6.5),
    ];
    if !stamp.position.trim().is_empty() {
        lines.push((stamp.position.trim().to_owned(), 6.0));
    }
    if !signer.serial_number.is_empty() {
        lines.push((format!("Сертификат {}", signer.serial_number), 5.5));
    }
    let mut owner_lines = wrap_owner_name(&signer.owner_name, OWNER_NAME_LINE_LIMIT);
    if owner_lines.is_empty() {
        owner_lines.push(String::new());
    }
    for (index, chunk) in owner_lines.into_iter().enumerate() {
        let text = if index == 0 { format!("Владелец {chunk}") } else { chunk };
        lines.push((text, 5.5));
    }
    if !signer.not_before.is_empty() && !signer.not_after.is_empty() {
        lines.push((
            format!("Действителен с {} по {}", signer.not_before, signer.not_after),
            5.5,
        ));
    }
    lines.into_iter().map(|(t, s)| (t, s * FONT_SCALE)).collect()
}

/// Единый масштаб кеглей, при котором блок строк полностью помещается в штамп.
/// 1.0 — номинальные кегли ГОСТ; меньшее значение — уменьшение под область.
fn fit_scale(encoded: &[embed_font::EncodedLine], width: f64, height: f64) -> f64 {
    let font = embed_font::font();
    let units = f64::from(font.units_per_em);
    let available_width = (width - 2.0 * STAMP_PADDING_X).max(0.0);
    let available_height = (height - 2.0 * STAMP_PADDING_Y).max(0.0);
    let (Some(first), Some(last)) = (encoded.first(), encoded.last()) else {
        return 1.0;
    };
    let widest = encoded
        .iter()
        .map(|line| f64::from(line.width_units) / units * line.font_size)
        .fold(0.0_f64, f64::max);
    let ascent = f64::from(font.ascent) / units;
    let descent = -f64::from(font.descent) / units;
    let gaps: f64 = encoded
        .windows(2)
        .map(|pair| pair[0].font_size * STAMP_LEADING)
        .sum();
    let block_height = ascent * first.font_size + gaps + descent * last.font_size;
    if widest <= 0.0 || block_height <= 0.0 {
        return 1.0;
    }
    (available_width / widest)
        .min(available_height / block_height)
        .clamp(0.0, 1.0)
}

/// Поток формы отметки: белая подложка, рамка и строки, вписанные в область штампа.
///
/// Текст пишется CID-кодами Identity-H встроенного DejaVu, поэтому кириллица отображается
/// на любой машине. Все строки выводятся единым масштабом `fit_scale`, поэтому ни одна
/// строка не теряется и пропорции глифов не искажаются. Блок строк центрируется
/// по вертикали внутри рамки; по горизонтали текст остаётся от левого поля.
fn appearance_content(encoded: &[embed_font::EncodedLine], width: f64, height: f64) -> Vec<u8> {
    let font = embed_font::font();
    let mut content = String::new();
    // Белая подложка: текст документа под отметкой не просвечивает.
    content.push_str(&format!(
        "q 1 1 1 rg 0 0 {:.2} {:.2} re f Q\n",
        width, height
    ));
    content.push_str(&format!(
        "q 0.55 0.55 0.55 RG 0.6 w 0.6 0.6 {:.2} {:.2} re S Q\n",
        width - 1.2,
        height - 1.2
    ));
    let scale = fit_scale(encoded, width, height);
    let ascent = f64::from(font.ascent) / f64::from(font.units_per_em);
    let descent = -f64::from(font.descent) / f64::from(font.units_per_em);
    let (Some(first), Some(last)) = (encoded.first(), encoded.last()) else {
        return content.into_bytes();
    };
    let gaps: f64 = encoded
        .windows(2)
        .map(|pair| pair[0].font_size * STAMP_LEADING)
        .sum();
    // Блок строк центрируется по вертикали: поля сверху и снизу равны.
    let block_height = (ascent * first.font_size + gaps + descent * last.font_size) * scale;
    let mut y = (height + block_height) / 2.0 - ascent * first.font_size * scale;
    for line in encoded {
        let size = line.font_size * scale;
        // Защита от недопустимого `Tf 0` в вырожденных областях.
        if size < 0.01 {
            break;
        }
        content.push_str(&format!(
            "BT /F0 {:.3} Tf 0.12 0.12 0.12 rg {:.2} {:.3} Td <{}> Tj ET\n",
            size,
            STAMP_PADDING_X,
            y,
            embed_font::cids_to_hex(line)
        ));
        y -= line.font_size * STAMP_LEADING * scale;
    }
    content.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use lopdf::dictionary;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = staging_path(Path::new("test"));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn prepared(&self) -> PreparedDocument {
            let bytes = sample_staged_pdf();
            let (offsets_at, contents_at, contents_end) = locate(&bytes).unwrap();
            let path = self.0.join("staged.pdf");
            std::fs::write(&path, &bytes).unwrap();
            PreparedDocument {
                path: Some(path), bytes, offsets_at, contents_at, contents_end,
                page_count: 1, digest_algorithm: String::new(),
            }
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn exported_preparation_survives_until_finish() {
        let dir = TestDirectory::new();
        let prepared = dir.prepared();
        let exported = export_prepared(prepared).unwrap();
        assert!(Path::new(&exported.prepared_path).is_file());
        assert_eq!(exported.page_count, 1);
        let restored = crate::signer::pades::restore(&exported.prepared_path).unwrap();
        let result = finish(&restored, &PdfSignaturePayload {
            cms: vec![0x30, 0x00], contents_at: exported.contents_at,
        }, &dir.0.join("signed.pdf")).unwrap();
        drop(restored);
        assert!(!Path::new(&exported.prepared_path).exists());
        let final_bytes = std::fs::read(result.output_path).unwrap();
        let doc = Document::load_mem(&final_bytes).unwrap();
        let field = doc.get_dictionary(signature_fields(&doc)[0].as_reference().unwrap()).unwrap();
        let sig = doc.get_dictionary(field.get(b"V").unwrap().as_reference().unwrap()).unwrap();
        let range: Vec<usize> = sig.get(b"ByteRange").unwrap().as_array().unwrap()
            .iter().map(|v| usize::try_from(v.as_i64().unwrap()).unwrap()).collect();
        assert!(range[3] > 0);
        assert_eq!(range[2] + range[3], final_bytes.len());
        assert_eq!(exported.signed_bytes, [&final_bytes[..range[1]],
            &final_bytes[range[2]..range[2] + range[3]]].concat());
    }

    #[test]
    fn failed_export_removes_staging_file() {
        let dir = TestDirectory::new();
        let mut prepared = dir.prepared();
        let path = prepared.path.clone().unwrap();
        prepared.bytes.clear();
        assert!(matches!(export_prepared(prepared), Err(SignerError::Pdf(_))));
        assert!(!path.exists());
        let mut missing = dir.prepared();
        let path = missing.path.take().unwrap();
        assert!(matches!(export_prepared(missing), Err(SignerError::Pdf(_))));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejected_payload_does_not_change_output() {
        let dir = TestDirectory::new();
        let prepared = dir.prepared();
        let output = dir.0.join("existing.pdf");
        std::fs::write(&output, b"existing output").unwrap();
        let capacity = (prepared.contents_end - prepared.contents_at - 1) / 2;
        let mut oversized = vec![0x30, 0x82];
        oversized.extend_from_slice(&((capacity + 1 - 4) as u16).to_be_bytes());
        oversized.resize(capacity + 1, 0);
        for payload in [
            PdfSignaturePayload { cms: Vec::new(), contents_at: prepared.contents_at },
            PdfSignaturePayload { cms: vec![0x30, 0x82, 0x01], contents_at: prepared.contents_at },
            PdfSignaturePayload { cms: vec![0x30, 0x03, 0x01], contents_at: prepared.contents_at },
            PdfSignaturePayload { cms: oversized, contents_at: prepared.contents_at },
            PdfSignaturePayload { cms: vec![0x30, 0x00], contents_at: prepared.contents_at + 1 },
        ] {
            assert!(matches!(finish(&prepared, &payload, &output), Err(SignerError::Pdf(_))));
            assert_eq!(std::fs::read(&output).unwrap(), b"existing output");
            assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 2);
        }
    }

    fn sample_pdf(kind: lopdf::xref::XrefType, modern: bool) -> Vec<u8> {
        let mut document = Document::with_version("1.7");
        document.reference_table.cross_reference_type = kind;
        let pages_id = document.new_object_id();
        let content_id = document.add_object(Stream::new(
            Dictionary::new(),
            b"0 0 0 RG 72 700 120 40 re S".to_vec(),
        ));
        let annotation_id = document.add_object(lopdf::dictionary! {
            "Type" => "Annot", "Subtype" => "Text",
            "Rect" => vec![0.into(), 0.into(), 10.into(), 10.into()],
            "Contents" => Object::string_literal("Existing annotation"),
        });
        let page_id = document.add_object(Object::Dictionary(Dictionary::from_iter([
            (b"Type".to_vec(), Object::Name(b"Page".to_vec())),
            (b"Parent".to_vec(), Object::Reference(pages_id).into()),
            (
                b"MediaBox".to_vec(),
                Object::Array(vec![
                    Object::Integer(0),
                    Object::Integer(0),
                    Object::Integer(595),
                    Object::Integer(842),
                ]),
            ),
            (b"Contents".to_vec(), Object::Reference(content_id).into()),
            (b"Resources".to_vec(), Object::Dictionary(Dictionary::new())),
            (b"Annots".to_vec(), Object::Array(vec![annotation_id.into()])),
        ])));
        document.set_object(
            pages_id,
            Object::Dictionary(Dictionary::from_iter([
                (b"Type".to_vec(), Object::Name(b"Pages".to_vec())),
                (
                    b"Kids".to_vec(),
                    Object::Array(vec![Object::Reference(page_id)]),
                ),
                (b"Count".to_vec(), Object::Integer(1)),
            ])),
        );
        let catalog = document.add_object(Object::Dictionary(Dictionary::from_iter([
            (b"Type".to_vec(), Object::Name(b"Catalog".to_vec())),
            (b"Pages".to_vec(), Object::Reference(pages_id).into()),
        ])));
        document
            .trailer
            .set(b"Root".to_vec(), Object::Reference(catalog));
        let mut bytes = Vec::new();
        if modern {
            let fields = document.add_object(Object::Array(Vec::new()));
            let form = document.add_object(dictionary! { "Fields" => fields });
            document.get_object_mut(catalog).unwrap().as_dict_mut().unwrap().set("AcroForm", form);
            document.save_modern(&mut bytes).unwrap();
        } else {
            document.save_to(&mut bytes).unwrap();
        }
        bytes
    }

    /// PDF из нескольких одинаковых страниц: проверки поворотов по одной странице.
    fn sample_pdf_with_pages(pages: usize) -> Vec<u8> {
        let mut document = Document::with_version("1.7");
        document.reference_table.cross_reference_type = lopdf::xref::XrefType::CrossReferenceTable;
        let pages_id = document.new_object_id();
        let content_id = document.add_object(Stream::new(
            Dictionary::new(),
            b"0 0 0 RG 72 700 120 40 re S".to_vec(),
        ));
        let mut kids = Vec::new();
        for _ in 0..pages {
            let page_id = document.add_object(Object::Dictionary(Dictionary::from_iter([
                (b"Type".to_vec(), Object::Name(b"Page".to_vec())),
                (b"Parent".to_vec(), Object::Reference(pages_id).into()),
                (
                    b"MediaBox".to_vec(),
                    Object::Array(vec![
                        Object::Integer(0),
                        Object::Integer(0),
                        Object::Integer(595),
                        Object::Integer(842),
                    ]),
                ),
                (b"Contents".to_vec(), Object::Reference(content_id).into()),
                (b"Resources".to_vec(), Object::Dictionary(Dictionary::new())),
            ])));
            kids.push(Object::Reference(page_id));
        }
        document.set_object(
            pages_id,
            Object::Dictionary(Dictionary::from_iter([
                (b"Type".to_vec(), Object::Name(b"Pages".to_vec())),
                (b"Kids".to_vec(), Object::Array(kids)),
                (b"Count".to_vec(), Object::Integer(pages as i64)),
            ])),
        );
        let catalog = document.add_object(Object::Dictionary(Dictionary::from_iter([
            (b"Type".to_vec(), Object::Name(b"Catalog".to_vec())),
            (b"Pages".to_vec(), Object::Reference(pages_id).into()),
        ])));
        document
            .trailer
            .set(b"Root".to_vec(), Object::Reference(catalog));
        let mut bytes = Vec::new();
        document.save_to(&mut bytes).unwrap();
        bytes
    }

    #[test]
    fn incremental_update_preserves_existing_form_and_generations() {
        for indirect in [false, true] {
            let mut source = Document::load_mem(&sample_pdf(lopdf::xref::XrefType::CrossReferenceTable, false)).unwrap();
            let old_page = *source.get_pages().get(&1).unwrap();
            let page = source.objects.remove(&old_page).unwrap();
            let page_id = (old_page.0, 2);
            source.set_object(page_id, page);
            let pages_id = source.catalog().unwrap().get(b"Pages").unwrap().as_reference().unwrap();
            source.get_object_mut(pages_id).unwrap().as_dict_mut().unwrap().set("Kids", vec![page_id.into()]);
            let existing = source.add_object(dictionary! {
                "FT" => "Tx", "T" => Object::string_literal("Signature1"),
                "V" => Object::string_literal("Keep this field"),
            });
            let fields = source.add_object(vec![Object::Reference(existing)]);
            let form = dictionary! { "Fields" => fields, "NeedAppearances" => true };
            let form_value = if indirect {
                Object::Reference(source.add_object(form))
            } else {
                Object::Dictionary(form)
            };
            let catalog_id = source.trailer.get(b"Root").unwrap().as_reference().unwrap();
            source.get_object_mut(catalog_id).unwrap().as_dict_mut().unwrap().set("AcroForm", form_value);
            let mut original = Vec::new();
            source.save_to(&mut original).unwrap();
            let (staged, _) = prepare_bytes(original.clone(), &test_stamp(), &test_signer(), &[]).unwrap();
            assert!(staged.starts_with(&original));
            let parsed = Document::load_mem(&staged).unwrap();
            assert_eq!(parsed.get_pages().get(&1), Some(&page_id));
            let fields = signature_fields(&parsed);
            assert_eq!(fields.len(), 2);
            assert_eq!(fields[0].as_reference().unwrap(), existing);
            assert_eq!(parsed.get_dictionary(existing).unwrap().get(b"V").unwrap().as_str().unwrap(), b"Keep this field");
            let widget = parsed.get_dictionary(fields[1].as_reference().unwrap()).unwrap();
            assert_eq!(widget.get(b"T").unwrap().as_str().unwrap(), b"Signature2");
            assert_eq!(widget.get(b"P").unwrap().as_reference().unwrap(), page_id);
            let form = parsed.dereference(parsed.catalog().unwrap().get(b"AcroForm").unwrap()).unwrap().1.as_dict().unwrap();
            assert!(form.get(b"NeedAppearances").unwrap().as_bool().unwrap());
            assert_eq!(form.get(b"SigFlags").unwrap().as_i64().unwrap(), 3);
        }
    }

    #[test]
    fn invalid_stamp_is_rejected() {
        let source = sample_pdf(lopdf::xref::XrefType::CrossReferenceTable, false);
        let mut stamp = test_stamp();
        stamp.page = 1;
        assert!(matches!(prepare_bytes(source.clone(), &stamp, &test_signer(), &[]), Err(SignerError::Pdf(_))));
        stamp.page = 0;
        stamp.width_mm = 0.0;
        assert!(matches!(prepare_bytes(source, &stamp, &test_signer(), &[]), Err(SignerError::Pdf(_))));
    }



    fn test_stamp() -> PdfStampSpec {
        PdfStampSpec {
            page: 0, left_mm: 20.0, top_mm: 20.0,
            width_mm: 80.0, height_mm: 35.0, position: String::new(),
        }
    }

    /// Прямоугольник страницы для `/CropBox` в тестах.
    fn box_array(x0: i64, y0: i64, x1: i64, y1: i64) -> Object {
        Object::Array(vec![
            Object::Integer(x0),
            Object::Integer(y0),
            Object::Integer(x1),
            Object::Integer(y1),
        ])
    }

    fn test_signer() -> CertInfo {
        CertInfo {
            id: "test".into(), subject: String::new(), issuer: String::new(),
            expires_at: "2027-01-01".into(), expired: false, has_private_key: false,
            source: "synthetic".into(), serial_number: "01".into(),
            not_before: "2026-01-01".into(), not_after: "2027-01-01".into(),
            owner_name: "Тестовый подписант".into(),
        }
    }

    fn sample_staged_pdf() -> Vec<u8> {
        prepare_bytes(
            sample_pdf(lopdf::xref::XrefType::CrossReferenceTable, false),
            &test_stamp(), &test_signer(), &[],
        ).unwrap().0
    }

    /// Строки отметки в том виде, в каком их получает `appearance_content`.
    fn stamp_encoded(stamp: &PdfStampSpec, signer: &CertInfo) -> Vec<embed_font::EncodedLine> {
        let texts = stamp_lines(stamp, signer);
        let lines: Vec<&str> = texts.iter().map(|(text, _)| text.as_str()).collect();
        let sizes: Vec<f64> = texts.iter().map(|(_, size)| *size).collect();
        embed_font::encode_lines_with_sizes(&lines, &sizes).0
    }

    /// Кегли строк, записанные в поток формы (`/F0 <size> Tf`).
    fn rendered_sizes(content: &str) -> Vec<f64> {
        content
            .split("/F0 ")
            .skip(1)
            .map(|rest| rest.split(" Tf").next().unwrap().parse().unwrap())
            .collect()
    }

    #[test]
    fn owner_name_wraps_at_spaces_only() {
        let mut signer = test_signer();
        signer.owner_name =
            "Бурцева Ольга Андреевна Заместитель начальника отдела информационных технологий".into();
        let lines: Vec<String> = stamp_lines(&test_stamp(), &signer)
            .into_iter()
            .map(|(text, _)| text)
            .collect();
        assert_eq!(lines[3], "Владелец Бурцева Ольга Андреевна Заместитель");
        assert_eq!(lines[4], "начальника отдела информационных технологий");
        assert_eq!(lines[5], "Действителен с 2026-01-01 по 2027-01-01");
        // Слово длиннее лимита остаётся целым.
        assert_eq!(wrap_owner_name("короткоеимя", 5), vec!["короткоеимя".to_owned()]);
    }

    #[test]
    fn appearance_content_fills_white_and_fits_all_lines() {
        let encoded = stamp_encoded(&test_stamp(), &test_signer());
        let (width, height) = (120.0, 40.0);
        let content = String::from_utf8(appearance_content(&encoded, width, height)).unwrap();
        // Подложка заливается первой, до рамки и текста.
        assert!(
            content.starts_with("q 1 1 1 rg 0 0 120.00 40.00 re f Q\n"),
            "{content}"
        );
        let scale = fit_scale(&encoded, width, height);
        assert!(
            scale > 0.0 && scale < 1.0,
            "кегли не уменьшены под 120×40 pt: {scale}"
        );
        let rendered = rendered_sizes(&content);
        assert_eq!(
            rendered.len(),
            encoded.len(),
            "часть строк потеряна:\n{content}"
        );
        for (size, line) in rendered.iter().zip(&encoded) {
            assert!(
                (*size - line.font_size * scale).abs() < 1e-3,
                "кегль {size} не равен {}: единый масштаб нарушен",
                line.font_size * scale
            );
        }
        // Самая широкая строка и весь блок по высоте укладываются во внутреннюю область.
        let font = embed_font::font();
        let units = f64::from(font.units_per_em);
        let widest = encoded
            .iter()
            .map(|line| f64::from(line.width_units) / units * line.font_size)
            .fold(0.0_f64, f64::max);
        let gaps: f64 = encoded
            .windows(2)
            .map(|pair| pair[0].font_size * STAMP_LEADING)
            .sum();
        let block = f64::from(font.ascent) / units * encoded[0].font_size
            + gaps
            + -f64::from(font.descent) / units * encoded[encoded.len() - 1].font_size;
        assert!(
            widest * scale <= width - 2.0 * STAMP_PADDING_X + 1e-6,
            "строка шире области: {} > {}",
            widest * scale,
            width - 2.0 * STAMP_PADDING_X
        );
        assert!(
            block * scale <= height - 2.0 * STAMP_PADDING_Y + 1e-6,
            "блок выше области: {} > {}",
            block * scale,
            height - 2.0 * STAMP_PADDING_Y
        );
        // Блок центрирован по вертикали: верхнее и нижнее поля совпадают.
        let baselines: Vec<f64> = content
            .lines()
            .filter(|line| line.contains("/F0 "))
            .map(|line| {
                line.split(" Td")
                    .next()
                    .unwrap()
                    .rsplit(' ')
                    .next()
                    .unwrap()
                    .parse()
                    .unwrap()
            })
            .collect();
        assert_eq!(baselines.len(), encoded.len(), "{content}");
        let ascent = f64::from(font.ascent) / units;
        let descent = -f64::from(font.descent) / units;
        let top_gap = height - (baselines[0] + ascent * encoded[0].font_size * scale);
        let bottom_gap =
            baselines[encoded.len() - 1] - descent * encoded[encoded.len() - 1].font_size * scale;
        assert!(
            (top_gap - bottom_gap).abs() < 1e-2,
            "блок не по центру: сверху {top_gap}, снизу {bottom_gap}"
        );
        // На большой области кегли остаются номинальными: увеличения нет.
        assert_eq!(fit_scale(&encoded, 400.0, 200.0), 1.0);
    }

    #[test]
    fn prepared_appearance_is_white_and_auto_scaled() {
        let source = sample_pdf(lopdf::xref::XrefType::CrossReferenceTable, false);
        let stamp = PdfStampSpec {
            page: 0,
            left_mm: 20.0,
            top_mm: 20.0,
            width_mm: 40.0,
            height_mm: 15.0,
            position: String::new(),
        };
        let signer = test_signer();
        let (bytes, _) = prepare_bytes(source, &stamp, &signer, &[]).unwrap();
        let document = Document::load_mem(&bytes).unwrap();
        let field = signature_fields(&document)[0].as_reference().unwrap();
        let widget = document.get_dictionary(field).unwrap();
        let appearance = widget
            .get(b"AP")
            .unwrap()
            .as_dict()
            .unwrap()
            .get(b"N")
            .unwrap()
            .as_reference()
            .unwrap();
        let stream = document
            .get_object(appearance)
            .unwrap()
            .as_stream()
            .unwrap();
        let content = String::from_utf8(stream.content.clone()).unwrap();
        assert!(
            content.contains("1 1 1 rg") && content.contains("re f"),
            "нет белой подложки:\n{content}"
        );
        let rendered = rendered_sizes(&content);
        assert_eq!(
            rendered.len(),
            stamp_lines(&stamp, &signer).len(),
            "часть строк потеряна:\n{content}"
        );
        let largest = rendered.iter().copied().fold(0.0_f64, f64::max);
        assert!(
            largest < 9.1,
            "кегль {largest} не уменьшен под область 40×15 мм:\n{content}"
        );
    }

    #[test]
    fn incremental_update_preserves_xref_kind() {
        use lopdf::xref::XrefType;
        for kind in [XrefType::CrossReferenceTable, XrefType::CrossReferenceStream] {
            let source = sample_pdf(kind, false);
            let previous = Document::load_mem(&source).unwrap().xref_start;
            let (staged, pages) = prepare_bytes(source, &test_stamp(), &test_signer(), &[]).unwrap();
            let parsed = Document::load_mem(&staged).unwrap();
            assert_eq!(pages, 1);
            assert!(matches!((parsed.reference_table.cross_reference_type, kind),
                (XrefType::CrossReferenceTable, XrefType::CrossReferenceTable)
                | (XrefType::CrossReferenceStream, XrefType::CrossReferenceStream)),
                "xref kind changed: {:?} -> {:?}", kind, parsed.reference_table.cross_reference_type);
            // lopdf consumes /Prev while resolving the chain; inspect the written revision.
            let xref = &staged[parsed.xref_start..];
            let prev_at = find_subsequence(xref, b"/Prev").unwrap() + 5;
            let prev_text = String::from_utf8_lossy(&xref[prev_at..]);
            let prev: usize = prev_text.trim_start().chars().take_while(|c| c.is_ascii_digit())
                .collect::<String>().parse().unwrap();
            assert_eq!(prev, previous);
            let xref_at = parsed.xref_start;
            match kind {
                XrefType::CrossReferenceTable => assert!(staged[xref_at..].starts_with(b"xref")),
                XrefType::CrossReferenceStream => {
                    let (&(id, generation), object) = parsed.objects.iter().rev().find(|(_, obj)| {
                        obj.as_stream().is_ok_and(|s| s.dict.get(b"Type").and_then(Object::as_name).is_ok_and(|name| name == b"XRef"))
                    }).unwrap();
                    assert!(staged[xref_at..].starts_with(format!("{id} {generation} obj").as_bytes()));
                    let size = object.as_stream().unwrap().dict.get(b"Size").unwrap().as_i64().unwrap();
                    assert!(size > i64::from(id));
                    assert!(matches!(parsed.reference_table.entries.get(&id),
                        Some(lopdf::xref::XrefEntry::Normal { offset, generation: g })
                        if *offset as usize == xref_at && *g == generation));
                }
            }
            for (&id, entry) in &parsed.reference_table.entries {
                if let lopdf::xref::XrefEntry::Normal { offset, generation } = entry {
                    assert!(staged[*offset as usize..].starts_with(format!("{id} {generation} obj").as_bytes()));
                }
            }
        }
    }

    #[test]
    fn incremental_update_preserves_existing_signed_bytes() {
        for tail in [b"\n".as_slice(), b"\r\n", b"\r", b"", b"\r\n\n  "] {
            let mut source = sample_pdf(lopdf::xref::XrefType::CrossReferenceTable, false);
            while source.last().is_some_and(|b| b.is_ascii_whitespace()) {
                source.pop();
            }
            source.extend_from_slice(tail);
            let (staged, _) = prepare_bytes(source.clone(), &test_stamp(), &test_signer(), &[]).unwrap();
            assert_eq!(&staged[..source.len()], source.as_slice(), "tail {tail:?}");
            let (_, at, end) = locate(&staged).unwrap();
            let first = assemble_document(&staged, at, end, &[0x30, 0x00]).unwrap();
            let (second_staged, _) = prepare_bytes(first.clone(), &test_stamp(), &test_signer(), &[]).unwrap();
            let (_, at2, end2) = locate(&second_staged).unwrap();
            let second = assemble_document(&second_staged, at2, end2, &[0x30, 0x00]).unwrap();
            assert_eq!(&second[..first.len()], first.as_slice());
            let doc = Document::load_mem(&second).unwrap();
            let fields = signature_fields(&doc);
            assert_eq!(fields.len(), 2);
            let names: Vec<_> = fields.iter().map(|field| {
                doc.get_dictionary(field.as_reference().unwrap()).unwrap().get(b"T").unwrap().as_str().unwrap()
            }).collect();
            assert_ne!(names[0], names[1]);
            let page = doc.get_dictionary(*doc.get_pages().get(&1).unwrap()).unwrap();
            let annots = existing_array(&doc, page, b"Annots").unwrap();
            assert_eq!(annots.len(), 3);
            assert_eq!(doc.get_dictionary(annots[0].as_reference().unwrap()).unwrap()
                .get(b"Contents").unwrap().as_str().unwrap(), b"Existing annotation");
            for field in fields {
                assert!(annots.iter().any(|a| a.as_reference().unwrap() == field.as_reference().unwrap()));
            }
        }
    }

    fn signature_fields(doc: &Document) -> &[Object] {
        let acroform = doc.catalog().unwrap().get(b"AcroForm").unwrap();
        let (_, acroform) = doc.dereference(acroform).unwrap();
        let (_, fields) = doc.dereference(acroform.as_dict().unwrap().get(b"Fields").unwrap()).unwrap();
        fields.as_array().unwrap()
    }

    #[test]
    fn incremental_update_reads_objects_from_streams() {
        let source = sample_pdf(lopdf::xref::XrefType::CrossReferenceStream, true);
        let original = Document::load_mem(&source).unwrap();
        assert!(original.reference_table.entries.values().any(|entry|
            matches!(entry, lopdf::xref::XrefEntry::Compressed { .. })));
        let (bytes, count) = prepare_bytes(source, &test_stamp(), &test_signer(), &[]).unwrap();
        let doc = Document::load_mem(&bytes).unwrap();
        assert_eq!(count, 1);
        assert_eq!(doc.get_pages(), original.get_pages());
        let fields = signature_fields(&doc);
        assert_eq!(fields.len(), 1);
        let page = doc.get_dictionary(*doc.get_pages().get(&1).unwrap()).unwrap();
        let annots = existing_array(&doc, page, b"Annots").unwrap();
        assert!(annots.iter().any(|a| a.as_reference().unwrap() == fields[0].as_reference().unwrap()));
    }

    #[test]
    fn assembled_byte_range_matches_signing_input() {
        let staged = sample_staged_pdf();
        let (signing, at, end) = with_byte_range(&staged).unwrap();
        let expected = signed_content(&signing, at, end).unwrap();
        let final_bytes = assemble_document(&staged, at, end, &[0x30, 0x00]).unwrap();
        let doc = Document::load_mem(&final_bytes).unwrap();
        let field = doc.get_dictionary(signature_fields(&doc)[0].as_reference().unwrap()).unwrap();
        let sig = doc.get_dictionary(field.get(b"V").unwrap().as_reference().unwrap()).unwrap();
        let range: Vec<usize> = sig.get(b"ByteRange").unwrap().as_array().unwrap()
            .iter().map(|v| usize::try_from(v.as_i64().unwrap()).unwrap()).collect();
        assert_eq!(range, vec![0, at, end + 1, final_bytes.len() - end - 1]);
        let actual = [&final_bytes[range[0]..range[0] + range[1]],
            &final_bytes[range[2]..range[2] + range[3]]].concat();
        assert_eq!(actual, expected);
        assert_eq!(final_bytes.len(), staged.len());
        let cms = sig.get(b"Contents").unwrap().as_str().unwrap();
        assert_eq!(&cms[..2], &[0x30, 0x00]);
        assert!(cms[2..].iter().all(|b| *b == 0));
    }

    #[test]
    fn locate_accepts_both_signature_key_orders() {
        for before in [true, false] {
            let contents = b"/Contents<0000>";
            let range = [b"/ByteRange".as_slice(), OFFSETS].concat();
            let bytes = if before {
                [b"<<".as_slice(), &range, contents, b">>"].concat()
            } else {
                [b"<<".as_slice(), contents, &range, b">>"].concat()
            };
            let (offsets, at, end) = locate(&bytes).unwrap();
            assert_eq!(&bytes[offsets..offsets + OFFSETS.len()], OFFSETS);
            assert_eq!(&bytes[at..=end], b"<0000>");
        }
    }

    #[test]
    fn invalid_pdf_is_rejected() {
        for bytes in [Vec::new(), b"not a PDF".to_vec()] {
            assert!(matches!(prepare_bytes(bytes, &test_stamp(), &test_signer(), &[]), Err(SignerError::Pdf(_))));
        }
        let mut bytes = sample_pdf(lopdf::xref::XrefType::CrossReferenceTable, false);
        let at = search_back(&bytes, 0..bytes.len(), b"startxref").unwrap() + b"startxref\n".len();
        let end = at + bytes[at..].iter().position(|b| !b.is_ascii_digit()).unwrap();
        bytes[at..end].fill(b'0');
        assert!(matches!(prepare_bytes(bytes, &test_stamp(), &test_signer(), &[]), Err(SignerError::Pdf(_))));
    }

    #[test]
    fn page_box_and_stamp_position() {
        let document = Document::load_mem(&sample_staged_pdf()).unwrap();
        let pages_id = document.catalog().unwrap().get(b"Pages").unwrap().as_reference().unwrap();
        let page_id = page_object_id(&document, pages_id, 0).unwrap();
        let (x, y, width, height) = page_box(&document, pages_id, page_id).unwrap();
        assert_eq!((x, y), (0.0, 0.0));
        assert_eq!((width.round(), height.round()), (595.0, 842.0));
        let stamp = PdfStampSpec {
            page: 0,
            left_mm: 120.0,
            top_mm: 220.0,
            width_mm: 60.0,
            height_mm: 30.0,
            position: String::new(),
        };
        let (x0, y0, x1, y1) = box_in_page(&stamp, width, height, 0).unwrap();
        assert!(x0 < x1 && y0 < y1);
        // 120 мм от левого края ≈ 340.16 pt.
        assert!((x0 - 340.157).abs() < 0.1);
        // Верх прямоугольника — 220 мм от верхнего края.
        let top = height - y1;
        assert!((top - 623.62).abs() < 0.2);
    }

    #[test]
    fn page_box_uses_crop_box_and_origin() {
        let mut document =
            Document::load_mem(&sample_pdf(lopdf::xref::XrefType::CrossReferenceTable, false))
                .unwrap();
        let pages_id = document.catalog().unwrap().get(b"Pages").unwrap().as_reference().unwrap();
        let page_id = page_object_id(&document, pages_id, 0).unwrap();
        document
            .get_object_mut(page_id)
            .unwrap()
            .as_dict_mut()
            .unwrap()
            .set("CropBox", box_array(50, 60, 545, 782));
        assert_eq!(
            page_box(&document, pages_id, page_id).unwrap(),
            (50.0, 60.0, 495.0, 722.0)
        );
    }

    #[test]
    fn crop_box_is_clipped_by_media_box() {
        let mut document =
            Document::load_mem(&sample_pdf(lopdf::xref::XrefType::CrossReferenceTable, false))
                .unwrap();
        let pages_id = document.catalog().unwrap().get(b"Pages").unwrap().as_reference().unwrap();
        let page_id = page_object_id(&document, pages_id, 0).unwrap();
        document
            .get_object_mut(page_id)
            .unwrap()
            .as_dict_mut()
            .unwrap()
            .set("CropBox", box_array(-10, -20, 700, 900));
        assert_eq!(
            page_box(&document, pages_id, page_id).unwrap(),
            (0.0, 0.0, 595.0, 842.0)
        );
    }

    #[test]
    fn stamp_position_on_180_rotated_page() {
        let stamp = PdfStampSpec {
            page: 0,
            left_mm: 120.0,
            top_mm: 220.0,
            width_mm: 60.0,
            height_mm: 30.0,
            position: String::new(),
        };
        let (x0, y0, x1, y1) = box_in_page(&stamp, 595.0, 842.0, 180).unwrap();
        // Точка (120; 220) мм от левого верхнего угла видимой стороны у 180° уходит вправо-вниз.
        assert!((x0 - 84.76).abs() < 0.1, "x0 = {x0}");
        assert!((y0 - 623.62).abs() < 0.1, "y0 = {y0}");
        assert!((x1 - 254.84).abs() < 0.1, "x1 = {x1}");
        assert!((y1 - 708.66).abs() < 0.1, "y1 = {y1}");
    }

    /// Видимые координаты (pt, начало сверху-слева) точки страницы при повороте `/Rotate`.
    ///
    /// Обратна `box_in_page` и совпадает с pdf.js `PageViewport`: так считает экранная
    /// система координат, в которой пользователь рисует отметку.
    fn display_point(x: f64, y: f64, page_width: f64, page_height: f64, rotation: i64) -> (f64, f64) {
        match rotation {
            90 => (y, x),
            180 => (page_width - x, y),
            270 => (page_height - y, page_width - x),
            _ => (x, page_height - y),
        }
    }

    /// Применяет PDF-матрицу `[a b c d e f]` к точке.
    fn apply_matrix([a, b, c, d, e, f]: [f64; 6], s: f64, t: f64) -> (f64, f64) {
        (a * s + c * t + e, b * s + d * t + f)
    }

    /// Числовое значение объекта PDF.
    fn number(value: &Object) -> f64 {
        match value {
            Object::Integer(number) => *number as f64,
            Object::Real(number) => f64::from(*number),
            other => panic!("ожидалось число, получено {other:?}"),
        }
    }

    #[test]
    fn stamp_appearance_is_upright_on_rotated_pages() {
        let (page_width, page_height) = (595.0, 842.0);
        // Размеры отметки на видимой стороне страницы (`test_stamp`: 80×35 мм).
        let (stamp_width, stamp_height) = (mm_to_points(80.0), mm_to_points(35.0));
        let margin = mm_to_points(20.0);
        for rotation in [0, 90, 180, 270] {
            let mut source = Document::load_mem(&sample_pdf(
                lopdf::xref::XrefType::CrossReferenceTable,
                false,
            ))
            .unwrap();
            let pages_id = source.catalog().unwrap().get(b"Pages").unwrap().as_reference().unwrap();
            let page_id = page_object_id(&source, pages_id, 0).unwrap();
            source
                .get_object_mut(page_id)
                .unwrap()
                .as_dict_mut()
                .unwrap()
                .set("Rotate", Object::Integer(rotation));
            let mut rotated = Vec::new();
            source.save_to(&mut rotated).unwrap();

            let (bytes, _) = prepare_bytes(rotated, &test_stamp(), &test_signer(), &[]).unwrap();
            let signed = Document::load_mem(&bytes).unwrap();
            let field = signature_fields(&signed)[0].as_reference().unwrap();
            let widget = signed.get_dictionary(field).unwrap();
            let rect: Vec<f64> = widget
                .get(b"Rect")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .map(number)
                .collect();
            let (rect_x0, rect_y0) = (rect[0], rect[1]);
            let (rect_width, rect_height) = (rect[2] - rect_x0, rect[3] - rect_y0);
            if rotation == 270 {
                // Отметка 80×35 мм в 20 мм от левого верхнего края повёрнутой страницы.
                for (value, expected) in rect.iter().zip([439.094, 558.535, 538.307, 785.307]) {
                    assert!(
                        (value - expected).abs() < 0.1,
                        "rotation 270: Rect {rect:?}, ожидалось значение {expected}"
                    );
                }
            }
            let appearance = widget
                .get(b"AP")
                .unwrap()
                .as_dict()
                .unwrap()
                .get(b"N")
                .unwrap()
                .as_reference()
                .unwrap();
            let stream = signed.get_object(appearance).unwrap().as_stream().unwrap();

            // `/BBox` описывает ровно нарисованный прямоугольник (хранится как `Real(f32)`).
            let bbox: Vec<f64> = stream
                .dict
                .get(b"BBox")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .map(number)
                .collect();
            assert_eq!((bbox[0], bbox[1]), (0.0, 0.0), "rotation {rotation}: BBox {bbox:?}");
            assert!(
                (bbox[2] - rect_width).abs() < 1e-3,
                "rotation {rotation}: BBox {bbox:?}, ширина прямоугольника {rect_width}"
            );
            assert!(
                (bbox[3] - rect_height).abs() < 1e-3,
                "rotation {rotation}: BBox {bbox:?}, высота прямоугольника {rect_height}"
            );

            // Поток начинается с матрицы, компенсирующей поворот страницы.
            let content = String::from_utf8(stream.content.clone()).unwrap();
            let mut head = content.lines().next().unwrap().split_whitespace();
            assert_eq!(head.next(), Some("q"), "rotation {rotation}: нет `q` в начале потока");
            let matrix: Vec<f64> = (0..6)
                .map(|_| {
                    head.next()
                        .expect("в матрице не хватает чисел")
                        .parse::<f64>()
                        .expect("в матрице не число")
                })
                .collect();
            assert_eq!(head.next(), Some("cm"), "rotation {rotation}: нет `cm` после матрицы");
            let expected = appearance_transform(rotation, rect_width, rect_height);
            for (index, value) in matrix.iter().enumerate() {
                assert!(
                    (value - expected[index]).abs() < 1e-4,
                    "rotation {rotation}: матрица {matrix:?}, ожидалось {expected:?}"
                );
            }
            let matrix: [f64; 6] = matrix.try_into().unwrap();
            let visible = |s: f64, t: f64| {
                let (x, y) = apply_matrix(matrix, s, t);
                display_point(rect_x0 + x, rect_y0 + y, page_width, page_height, rotation)
            };

            // Углы области отметки попадают ровно в нарисованный прямоугольник.
            let corners = [
                (0.0, 0.0),
                (stamp_width, 0.0),
                (0.0, stamp_height),
                (stamp_width, stamp_height),
            ];
            let expected = [
                (margin, margin + stamp_height),
                (margin + stamp_width, margin + stamp_height),
                (margin, margin),
                (margin + stamp_width, margin),
            ];
            for ((s, t), (want_u, want_v)) in corners.into_iter().zip(expected) {
                let (u, v) = visible(s, t);
                assert!(
                    (u - want_u).abs() < 0.05 && (v - want_v).abs() < 0.05,
                    "rotation {rotation}: точка ({s}; {t}) видна в ({u}; {v}), ожидалось ({want_u}; {want_v})"
                );
            }
            // Базис текста горизонтален и растёт слева-направо.
            let (start_u, start_v) = visible(0.0, 0.0);
            let (end_u, end_v) = visible(stamp_width, 0.0);
            assert!(
                end_u > start_u + 1.0,
                "rotation {rotation}: базис текста не растёт вправо ({start_u} → {end_u})"
            );
            assert!(
                (end_v - start_v).abs() < 0.05,
                "rotation {rotation}: базис текста наклонён ({start_v} → {end_v})"
            );
        }
    }

    #[test]
    fn font_encoding_maps_cids_to_unicode() {
        let (encoded, cids) = embed_font::encode_lines(&["ДОКУМЕНТ", "A Б"]);
        assert!(!cids.is_empty(), "CID должны быть выданы");
        // CID — номер глифа DejaVu, а не Unicode: у «Д» (U+0414) глиф 1040.
        let font = embed_font::font();
        let cid_d = font.glyph('Д' as u16);
        assert!(cid_d > 0, "у «Д» есть глиф");
        assert_eq!(encoded[0].cids[0].cid, cid_d);
        // «О» — следующий по порядку символ, отображение есть в /ToUnicode.
        let cid_o = font.glyph('О' as u16);
        assert_ne!(cid_d, cid_o);
        assert_eq!(cids.get(&cid_o), Some(&('О' as u16)));
        assert!(encoded[0].cids.iter().all(|glyph| glyph.width > 0));
        assert!(encoded[0].width_units > 0);
        // Пробел во второй строке имеет свой CID, иначе слова слипнутся.
        let space_cid = font.glyph(' ' as u16);
        assert!(encoded[1].cids.iter().any(|glyph| glyph.cid == space_cid));
        // Без явного кегля строки получают DEFAULT_FONT_SIZE.
        assert_eq!(encoded[0].font_size, embed_font::DEFAULT_FONT_SIZE);
    }

    #[test]
    fn page_rotations_persist_for_unstamped_pages() {
        let source = sample_pdf_with_pages(3);
        // Сценарий интерфейса: повернуть первую страницу, переключиться, повернуть
        // вторую, переключиться и поставить отметку на третьей.
        let stamp = PdfStampSpec {
            page: 2, left_mm: 20.0, top_mm: 20.0,
            width_mm: 80.0, height_mm: 35.0, position: String::new(),
        };
        let rotations = [
            PageRotation { page: 0, rotation: 90 },
            PageRotation { page: 1, rotation: 270 },
        ];
        let (bytes, count) = prepare_bytes(source, &stamp, &test_signer(), &rotations).unwrap();
        assert_eq!(count, 3);
        let document = Document::load_mem(&bytes).unwrap();
        let pages_id = document.catalog().unwrap().get(b"Pages").unwrap().as_reference().unwrap();
        let page_id = |index: usize| page_object_id(&document, pages_id, index).unwrap();
        assert_eq!(page_rotation(&document, pages_id, page_id(0)), 90);
        assert_eq!(page_rotation(&document, pages_id, page_id(1)), 270);
        assert_eq!(page_rotation(&document, pages_id, page_id(2)), 0);
        // Новый /Rotate записан в словари самих страниц, а не в дерево /Pages.
        assert!(document.get_dictionary(page_id(0)).unwrap().get(b"Rotate").is_ok());
        assert!(document.get_dictionary(page_id(1)).unwrap().get(b"Rotate").is_ok());
        assert!(document.get_dictionary(page_id(2)).unwrap().get(b"Rotate").is_err());
        // Отметка осталась на третьей странице: повороты соседних её не сдвинули.
        let widget = document
            .get_dictionary(signature_fields(&document)[0].as_reference().unwrap())
            .unwrap();
        assert_eq!(widget.get(b"P").unwrap().as_reference().unwrap(), page_id(2));
    }

    #[test]
    fn repeated_preparation_keeps_rotations_absolute() {
        let source = sample_pdf_with_pages(2);
        let stamp = PdfStampSpec {
            page: 0, left_mm: 20.0, top_mm: 20.0,
            width_mm: 80.0, height_mm: 35.0, position: String::new(),
        };
        let rotations = [
            PageRotation { page: 0, rotation: 90 },
            PageRotation { page: 1, rotation: 180 },
        ];
        let (staged, _) = prepare_bytes(source, &stamp, &test_signer(), &rotations).unwrap();
        let (_, at, end) = locate(&staged).unwrap();
        let signed = assemble_document(&staged, at, end, &[0x30, 0x00]).unwrap();
        // Вторая подпись приносит те же целевые углы: они не складываются с прежними.
        let (again, _) = prepare_bytes(signed, &stamp, &test_signer(), &rotations).unwrap();
        let document = Document::load_mem(&again).unwrap();
        let pages_id = document.catalog().unwrap().get(b"Pages").unwrap().as_reference().unwrap();
        assert_eq!(page_rotation(&document, pages_id, page_object_id(&document, pages_id, 0).unwrap()), 90);
        assert_eq!(page_rotation(&document, pages_id, page_object_id(&document, pages_id, 1).unwrap()), 180);
    }

    #[test]
    fn stamp_uses_requested_rotation() {
        let source = sample_pdf_with_pages(1);
        let stamp = PdfStampSpec {
            page: 0, left_mm: 20.0, top_mm: 20.0,
            width_mm: 80.0, height_mm: 35.0, position: String::new(),
        };
        let rotations = [PageRotation { page: 0, rotation: 90 }];
        let (bytes, _) = prepare_bytes(source, &stamp, &test_signer(), &rotations).unwrap();
        let document = Document::load_mem(&bytes).unwrap();
        let pages_id = document.catalog().unwrap().get(b"Pages").unwrap().as_reference().unwrap();
        let page_id = page_object_id(&document, pages_id, 0).unwrap();
        assert_eq!(page_rotation(&document, pages_id, page_id), 90);
        let widget = document
            .get_dictionary(signature_fields(&document)[0].as_reference().unwrap())
            .unwrap();
        let rect: Vec<f64> = widget
            .get(b"Rect").unwrap().as_array().unwrap()
            .iter().map(number).collect();
        // Прямоугольник считается как для уже повёрнутой страницы.
        let expected = box_in_page(&stamp, 595.0, 842.0, 90).unwrap();
        for (actual, expected) in rect.iter().zip([expected.0, expected.1, expected.2, expected.3]) {
            assert!(
                (actual - expected).abs() < 0.05,
                "Rect {rect:?}, ожидалось {expected:?}"
            );
        }
        // Внешний вид компенсирует новый /Rotate: текст печатается прямо.
        let appearance = widget
            .get(b"AP").unwrap().as_dict().unwrap()
            .get(b"N").unwrap().as_reference().unwrap();
        let stream = document.get_object(appearance).unwrap().as_stream().unwrap();
        let content = String::from_utf8(stream.content.clone()).unwrap();
        let matrix: Vec<f64> = content.lines().next().unwrap()
            .split_whitespace().skip(1).take(6)
            .map(|value| value.parse().unwrap()).collect();
        let (rect_width, rect_height) = (rect[2] - rect[0], rect[3] - rect[1]);
        let expected = appearance_transform(90, rect_width, rect_height);
        for (index, value) in matrix.iter().enumerate() {
            assert!(
                (value - expected[index]).abs() < 1e-4,
                "матрица {matrix:?}, ожидалось {expected:?}"
            );
        }
    }

    #[test]
    fn invalid_page_rotation_is_rejected() {
        let source = sample_pdf_with_pages(1);
        let not_right_angle = [PageRotation { page: 0, rotation: 45 }];
        assert!(matches!(
            prepare_bytes(source.clone(), &test_stamp(), &test_signer(), &not_right_angle),
            Err(SignerError::Pdf(_))
        ));
        let missing_page = [PageRotation { page: 1, rotation: 90 }];
        assert!(matches!(
            prepare_bytes(source, &test_stamp(), &test_signer(), &missing_page),
            Err(SignerError::Pdf(_))
        ));
    }

    #[test]
    fn widget_box_mm_matches_visible_page_rotation() {
        let (page_width, page_height) = (595.0, 842.0);
        // Прямоугольник 100 × 50 pt в левом нижнем углу страницы.
        let rect = (10.0, 20.0, 110.0, 70.0);
        let mm = |value: f64| value * 25.4 / 72.0;
        let expected = [
            (0, (10.0, 842.0 - 70.0, 100.0, 50.0)),
            (90, (20.0, 10.0, 50.0, 100.0)),
            (180, (595.0 - 110.0, 20.0, 100.0, 50.0)),
            (270, (842.0 - 70.0, 595.0 - 110.0, 50.0, 100.0)),
        ];
        for (rotation, (left, top, width, height)) in expected {
            let (got_left, got_top, got_width, got_height) =
                widget_box_mm(rotation, page_width, page_height, rect);
            assert!((got_left - mm(left)).abs() < 1e-9, "left при {rotation}°");
            assert!((got_top - mm(top)).abs() < 1e-9, "top при {rotation}°");
            assert!((got_width - mm(width)).abs() < 1e-9, "width при {rotation}°");
            assert!(
                (got_height - mm(height)).abs() < 1e-9,
                "height при {rotation}°"
            );
        }
    }

    #[test]
    fn signature_coverage_requires_the_whole_file() {
        assert!(covers_document(&[(0, 100), (140, 60)], 200));
        assert!(!covers_document(&[(0, 100), (140, 59)], 200));
        assert!(!covers_document(&[(4, 96), (140, 60)], 200));
        assert!(!covers_document(&[(0, 100), (100, 100)], 200));
        assert!(!covers_document(&[(0, 100)], 100));
    }

    #[test]
    fn byte_ranges_are_read_from_the_signature_dictionary() {
        let value = Object::Array(vec![
            Object::Integer(0),
            Object::Integer(4),
            Object::Integer(8),
            Object::Integer(2),
        ]);
        let ranges = byte_ranges(&value).expect("ranges");
        assert_eq!(ranges, vec![(0, 4), (8, 2)]);
        let bytes = b"0123456789";
        assert_eq!(signed_ranges(bytes, &ranges).unwrap(), b"012389".to_vec());
        assert!(byte_ranges(&Object::Array(vec![Object::Integer(0)])).is_none());
        assert!(signed_ranges(b"short", &[(0, 3), (4, 2)]).is_err());
    }

    #[test]
    fn pdf_date_is_formatted_for_the_viewer() {
        assert_eq!(
            format_pdf_date(b"D:20261111103512+03'00'"),
            "11.11.2026 10:35:12"
        );
        assert_eq!(format_pdf_date(b"D:20261111"), "11.11.2026");
        assert_eq!(format_pdf_date(b"garbage"), "garbage");
    }
}
