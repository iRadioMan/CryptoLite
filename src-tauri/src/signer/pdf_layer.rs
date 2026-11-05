#![deny(unsafe_code)]
//! Встроенная подпись PDF (PAdES-BES) с видимой отметкой об ЭП.
//!
//! Порядок берётся у КриптоПро PDF / КриптоАРМ (эталонный подписанный документ):
//!
//! - Исходный файл **не перезаписывается**: к нему дописывается инкрементальное обновление
//!   (ISO 32000-1, 7.5.6): новые объекты, новая таблица `xref`, `trailer` с прежним `/Root`,
//!   `startxref`, `%%EOF`. Поэтому уже существующие подписи и разметка остаются целыми.
//! - Поле подписи — виджет `/Sig` в `/AcroForm /Fields` со ссылкой `/V` на словарь `/Sig`
//!   и внешним видом `/AP` (рисуется встроенным шрифтом, а не стандартным Helvetica, из-за
//!   которой кириллица превращалась в «кракозябры»).
//! - `/SubFilter` — `adbe.pkcs7.detached`; `/Contents` фиксированной длины заполняется
//!   шестнадцатеричной CMS, `/ByteRange` — `[0 A B C]`.
//!
//! Подписываемые байты (ISO 32000-1, 7.6.2): всё до `<` в `/Contents` и всё после `>`;
//! CMS при этом сама помечена как `id-data` и содержит подписанные атрибуты (CMS v3).
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use lopdf::{Dictionary, Document, Object, Stream, StringFormat};

use crate::signer::embed_font;
use crate::signer::{CertInfo, PdfSignaturePayload, PdfStampSpec, SignResult, SignerError};

/// Ширина `/ByteRange`-заглушки. Настоящие смещения пишутся в это поле через пробелы
/// (как у КриптоПро PDF: `[ 0 64180 166598 14908]`), поэтому длина файла при подписи не меняется.
const OFFSETS: &[u8] = b"[ 0 0000000000 0000000000 0000000000]";

/// Подготовленный PDF и позиции его полей подписи.
pub struct PreparedDocument {
    pub path: PathBuf,
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

fn signing_error(message: impl Into<String>) -> SignerError {
    SignerError::Pdf(message.into())
}

/// Подготавливает PDF: дописывает поле `/Sig` с отметкой к последней версии документа.
pub fn prepare(
    source: &Path,
    stamp: &PdfStampSpec,
    certificate_id: &str,
    _digest_algorithm: &str,
    new_id: &str,
) -> Result<PreparedDocument, SignerError> {
    if !source.is_file() {
        return Err(signing_error(format!(
            "документ {} не найден",
            source.display()
        )));
    }
    let signer = certificate_info(certificate_id)?;
    let document = Document::load(source)
        .map_err(|error| signing_error(format!("не удалось прочитать PDF: {error}")))?;
    if document.is_encrypted() {
        return Err(signing_error(
            "PDF защищён паролем: встроенная подпись такого документа пока не поддерживается",
        ));
    }
    let catalog_id = document
        .trailer
        .get(b"Root")
        .and_then(Object::as_reference)
        .map_err(|error| signing_error(format!("не найден каталог PDF: {error}")))?;
    // Каталог может быть в потоке объектов: проверяем доступность
    let _catalog = document
        .get_dictionary(catalog_id)
        .map_err(|error| signing_error(format!("не удалось прочитать каталог PDF: {error}")))?;
    let catalog = document
        .get_dictionary(catalog_id)
        .map_err(|error| signing_error(format!("не удалось прочитать каталог PDF: {error}")))?
        .clone();
    let pages_id = catalog
        .get(b"Pages")
        .and_then(Object::as_reference)
        .map_err(|error| signing_error(format!("не найдено дерево страниц PDF: {error}")))?;
    let page_id = page_object_id(&document, pages_id, stamp.page)?;
    let (page_x, page_y, page_width, page_height) = page_box(&document, pages_id, page_id)?;
    let rotation = page_rotation(&document, pages_id, page_id);
    let (x0, y0, x1, y1) = box_in_page(stamp, page_width, page_height, rotation)?;
    let (x0, y0, x1, y1) = (x0 + page_x, y0 + page_y, x1 + page_x, y1 + page_y);
    let width = x1 - x0;
    let height = y1 - y0;

    // Исходные байты — основа инкрементального обновления. Добавляемый `%%EOF` остаётся
    // в подписанном диапазоне, поэтому `Catalog`/`Pages` ниже читаются только для адресов
    // объектов; сами объекты копируются без изменений.
    let mut bytes = std::fs::read(source)
        .map_err(|error| signing_error(format!("не удалось прочитать документ: {error}")))?;
    trim_to_last_eof(&mut bytes);
    if !bytes.ends_with(b"\n") && !bytes.ends_with(b"\r") {
        bytes.extend_from_slice(b"\n");
    }

    // Номера объектов: новые идут после максимального существующего, чтобы не затереть
    // объекты прошлых версий (в том числе подписи, которые могли быть в потоке объектов).
    let first = document.max_id + 1;

    // Отметка набирается встроенным DejaVu Sans Condensed: кириллица и латиница
    // отображаются одинаково на любой системе.
    let texts = stamp_lines(stamp, &signer);
    let lines: Vec<&str> = texts.iter().map(|(text, _)| text.as_str()).collect();
    let (encoded, cid_to_code) = embed_font::encode_lines(&lines);
    let mut allocator = Allocator {
        bytes: &mut bytes,
        next: first,
        offsets: BTreeMap::new(),
    };
    let font_id = allocator.reserve();
    let font_file_id = allocator.reserve();
    let descriptor_id = allocator.reserve();
    let cid_font_id = allocator.reserve();
    let to_unicode_id = allocator.reserve();
    let appearance_id = allocator.reserve();
    let signature_id = allocator.reserve();
    let widget_id = allocator.reserve();
    let acroform_id = allocator.reserve();
    let annots_id = allocator.reserve();

    let objects = embed_font::font_objects(&cid_to_code);
    allocator.write(font_file_id, objects.font_file)?;
    let mut descriptor = match objects.descriptor {
        Object::Dictionary(d) => d,
        _ => Dictionary::new(),
    };
    descriptor.set(b"FontFile2".to_vec(), Object::Reference(font_file_id));
    allocator.write(descriptor_id, Object::Dictionary(descriptor))?;

    let mut cid_font = match objects.cid_font {
        Object::Dictionary(d) => d,
        _ => Dictionary::new(),
    };
    cid_font.set(b"FontDescriptor".to_vec(), Object::Reference(descriptor_id));
    allocator.write(cid_font_id, Object::Dictionary(cid_font))?;
    allocator.write(to_unicode_id, objects.to_unicode)?;
    
    let font_dict = match objects.font {
        lopdf::Object::Dictionary(mut dict) => {
            dict.set(b"DescendantFonts".to_vec(), lopdf::Object::Array(vec![lopdf::Object::Reference(cid_font_id)]));
            dict.set(b"ToUnicode".to_vec(), lopdf::Object::Reference(to_unicode_id));
            dict
        }
        _ => lopdf::Dictionary::new(),
    };
    allocator.write(font_id, lopdf::Object::Dictionary(font_dict))?;
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
        appearance_content(&encoded, width, height),
    );
    allocator.write(appearance_id, Object::Stream(appearance))?;

    let signature = Dictionary::from_iter([
        (b"Type".to_vec(), Object::Name(b"Sig".to_vec())),
        (
            b"Filter".to_vec(),
            Object::Name(b"Adobe.PPKLite".to_vec()),
        ),
        (
            b"SubFilter".to_vec(),
            Object::Name(b"ETSI.CAdES.detached".to_vec()),
        ),
        // Зарезервировано под CMS фиксированной длины; заполняется после записи файла.
        (
            b"Contents".to_vec(),
            Object::String(vec![b'0'; reserved_contents_bytes() * 2], StringFormat::Hexadecimal)
                .into(),
        ),
        // Диапазон фиксированной ширины: заполняется на месте, длина файла не меняется.
        (
            b"ByteRange".to_vec(),
            Object::String(OFFSETS.to_vec(), StringFormat::Literal).into(),
        ),
        (b"M".to_vec(), pdf_date_string()),
        (
            b"Reason".to_vec(),
            text_string("Документ подписан электронной подписью"),
        ),
        (
            b"Name".to_vec(),
            Object::String(format!("Signature_{new_id}").into_bytes(), StringFormat::Literal)
                .into(),
        ),
        (
            b"Location".to_vec(),
            Object::String(b"RU".to_vec(), StringFormat::Literal).into(),
        ),
        (b"ContactInfo".to_vec(), text_string(&signer.owner_name)),
    ]);
    allocator.write(signature_id, Object::Dictionary(signature))?;

    // Ссылки на существующие объекты в новых словарях обязательны: слайды/страница
    // остаются на месте, инкрементальное обновление их не трогает.
    let widget = Dictionary::from_iter([
        (b"Type".to_vec(), Object::Name(b"Annot".to_vec())),
        (b"Subtype".to_vec(), Object::Name(b"Widget".to_vec())),
        (b"FT".to_vec(), Object::Name(b"Sig".to_vec())),
        (
            b"T".to_vec(),
            Object::String(
                format!("Signature_{new_id}").into_bytes(),
                StringFormat::Literal,
            )
            .into(),
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
    allocator.write(widget_id, Object::Dictionary(widget))?;

    // Обновлённые версии страницы и каталога: старые объекты остаются в подписанных байтах
    // без изменений, новые версии переопределяют `/Annots` и `/AcroForm`.
    let page = document
        .get_dictionary(page_id)
        .map_err(|error| signing_error(format!("не удалось прочитать страницу PDF: {error}")))?
        .clone();
    let mut new_page = page.clone();
    let annots = existing_array(&document, &page, b"Annots")?;
    allocator.write(annots_id, Object::Array(annots))?;
    new_page.set(
        b"Annots".to_vec(),
        Object::Array(vec![
            Object::Reference(annots_id),
            Object::Reference(widget_id),
        ]),
    );
    allocator
        .write(page_id, Object::Dictionary(new_page))
        .map_err(|error| {
            signing_error(format!(
                "страница PDF находится внутри потока объектов и не может быть обновлена: {error:?}"
            ))
        })?;
    let _ = annots_id;

    // Поле подписи в AcroForm: `/Fields` — массив существующих полей плюс новый виджет.
    let acroform = match catalog.get(b"AcroForm") {
        Ok(Object::Reference(id)) => document.get_dictionary(*id).cloned().unwrap_or_default(),
        Ok(Object::Dictionary(dictionary)) => dictionary.clone(),
        _ => Dictionary::new(),
    };
    let mut fields = match acroform.get(b"Fields").and_then(Object::as_array) {
        Ok(fields) => fields.clone(),
        Err(_) => Vec::new(),
    };
    fields.push(Object::Reference(widget_id));
    let mut new_acroform = acroform.clone();
    new_acroform.set(b"Fields".to_vec(), Object::Array(fields));
    new_acroform.set(b"SigFlags".to_vec(), Object::Integer(3));
    allocator
        .write(acroform_id, Object::Dictionary(new_acroform))?;
    let mut new_catalog = catalog.clone();
    new_catalog.set(b"AcroForm".to_vec(), Object::Reference(acroform_id));
    allocator
        .write(catalog_id, Object::Dictionary(new_catalog))
        .map_err(|error| {
            signing_error(format!(
                "каталог PDF находится внутри потока объектов и не может быть обновлён: {error:?}"
            ))
        })?;

    // Таблица xref и trailer продлевают файл, а не меняют уже существующие байты.
    let mut trailer = document.trailer.clone();
    trailer.remove(b"Prev");
    trailer.remove(b"XRefStm");
    let size = allocator.next;                       // max_id + 1 по документу
    let offsets = std::mem::take(&mut allocator.offsets);
    drop(allocator);
    let previous_start = find_previous_xref(&bytes).unwrap_or(0);
    write_xref(&mut bytes, &offsets, &trailer, size, previous_start)?;

    let (offsets_at, contents_at, contents_end) = locate(&bytes)?;
    let path = staging_path(source);
    if let Err(error) = std::fs::write(&path, &bytes) {
        let _ = std::fs::remove_file(&path);
        return Err(signing_error(format!(
            "не удалось записать временный файл: {error}"
        )));
    }
    Ok(PreparedDocument {
        path,
        bytes,
        digest_algorithm: _digest_algorithm.to_owned(),
        page_count: document.get_pages().len(),
        offsets_at,
        contents_at,
        contents_end,
    })
}

/// Сколько байт резервируется под CMS. CAdES-BES по ГОСТ с цепочкой 2–3 сертификатов
/// занимает 4–6 КБ; для ГОСТ 2012-512 подписи длиннее, поэтому резерв больше.
fn reserved_contents_bytes() -> usize {
    16 * 1024
}

/// Выделяет номера новых объектов и дописывает их в файл.
struct Allocator<'a> {
    bytes: &'a mut Vec<u8>,
    next: u32,
    offsets: BTreeMap<u32, u64>,
}

impl Allocator<'_> {
    fn reserve(&mut self) -> lopdf::ObjectId {
        let id = (self.next, 0);
        self.next += 1;
        id
    }

    fn write(&mut self, id: lopdf::ObjectId, object: Object) -> Result<(), SignerError> {
        let mut body = Vec::new();
        serialize_object(&mut body, &object);
        self.offsets.insert(id.0, self.bytes.len() as u64 + 1); // +1: пропускаем ведущий '\n'
        write_object(self.bytes, id, &body);
        Ok(())
    }
}

fn serialize_dict(buf: &mut Vec<u8>, dict: &Dictionary) {
    buf.extend_from_slice(b"<<");
    for (key, value) in dict.iter() {
        buf.push(b'/');
        buf.extend_from_slice(key);
        // ByteRange - сырой массив фиксированной ширины, а не строка
        if key.as_slice() == b"ByteRange" {
            buf.extend_from_slice(OFFSETS);
            continue;
        }
        // пробел нужен только перед числом/ссылкой/bool/null;
        // перед `<`, `(`, `[`, `/` он не нужен (это даёт `/Contents<...>`)
        if !matches!(
            value,
            Object::Array(_) | Object::Dictionary(_) | Object::Name(_) | Object::String(..)
        ) {
            buf.push(b' ');
        }
        serialize_object(buf, value);
    }
    buf.extend_from_slice(b">>");
}

/// Записывает объект с указанным номером (`N 0 obj … endobj`).
fn serialize_object(buf: &mut Vec<u8>, obj: &Object) {
    match obj {
        Object::Null => buf.extend_from_slice(b"null"),
        Object::Boolean(b) => buf.extend_from_slice(if *b { b"true" } else { b"false" }),
        Object::Integer(i) => buf.extend_from_slice(i.to_string().as_bytes()),
        Object::Real(f) => buf.extend_from_slice(format!("{:.6}", f).trim_end_matches('0').trim_end_matches('.').as_bytes()),
        Object::Name(n) => {
            buf.push(b'/');
            buf.extend_from_slice(n);
        }
        Object::String(s, format) => match format {
            lopdf::StringFormat::Literal => {
                buf.push(b'(');
                for &b in s {
                    match b {
                        b'(' | b')' | b'\\' => { buf.push(b'\\'); buf.push(b); }
                        b'\r' => buf.extend_from_slice(b"\\r"),
                        _ => buf.push(b),
                    }
                }
                buf.push(b')');
            }
            lopdf::StringFormat::Hexadecimal => {
                buf.push(b'<');
                buf.extend_from_slice(s);
                buf.push(b'>');
            }
        },
        Object::Array(arr) => {
            buf.push(b'[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    buf.push(b' ');
                }
                serialize_object(buf, item);
            }
            buf.push(b']');
        }
        Object::Dictionary(dict) => serialize_dict(buf, dict),
        Object::Stream(stream) => {
            serialize_object(buf, &Object::Dictionary(stream.dict.clone()));
            buf.extend_from_slice(b"\nstream\n");
            buf.extend_from_slice(&stream.content);
            buf.extend_from_slice(b"\nendstream");
        }
        Object::Reference(id) => {
            buf.extend_from_slice(format!("{} {} R", id.0, id.1).as_bytes());
        }
    }
}

fn write_object(bytes: &mut Vec<u8>, id: lopdf::ObjectId, body: &[u8]) {
    use std::io::Write as _;
    write!(bytes, "\n{} {} obj\n", id.0, id.1).unwrap();
    bytes.extend_from_slice(body);
    bytes.extend_from_slice(b"\nendobj\n");
}

fn write_xref(
    bytes: &mut Vec<u8>,
    offsets: &BTreeMap<u32, u64>,   // id -> смещение, только объекты этого обновления
    trailer: &Dictionary,
    size: u32,                      // max_id + 1 по всему документу
    previous_start: u64,
) -> Result<(), SignerError> {
    let xref_at = bytes.len();
    bytes.extend_from_slice(b"xref\n");

    // группируем подряд идущие id в подсекции
    let ids: Vec<u32> = offsets.keys().copied().collect();
    let mut i = 0;
    while i < ids.len() {
        let mut j = i;
        while j + 1 < ids.len() && ids[j + 1] == ids[j] + 1 {
            j += 1;
        }
        write!(bytes, "{} {}\n", ids[i], j - i + 1).unwrap();
        for id in &ids[i..=j] {
            write!(bytes, "{:010} 00000 n \n", offsets[id]).unwrap();
        }
        i = j + 1;
    }

    let mut trailer = trailer.clone();
    trailer.set(b"Size".to_vec(), Object::Integer(size as i64));
    if previous_start > 0 {
        trailer.set(b"Prev".to_vec(), Object::Integer(previous_start as i64));
    }
    bytes.extend_from_slice(b"trailer\n");
    serialize_object(bytes, &Object::Dictionary(trailer));
    write!(bytes, "\nstartxref\n{xref_at}\n%%EOF\n").unwrap();
    Ok(())
}

/// Абсолютные позиции `/ByteRange`, `<` и `>` поля подписи.
///
/// В документе бывает несколько `/Contents` (например, содержимое страницы), поэтому поле
/// ищется по паре «`/ByteRange (` + `/Contents<`», добавленной в конец файла.
pub fn locate(bytes: &[u8]) -> Result<(usize, usize, usize), SignerError> {
    let contents_at = locate_contents(bytes).ok_or_else(|| {
        signing_error("не удалось найти поле подписи в подготовленном PDF")
    })?;
    let mut contents_end = contents_at + 1;
    while contents_end < bytes.len() && bytes[contents_end] != b'>' {
        if !bytes[contents_end].is_ascii_hexdigit() {
            return Err(signing_error("повреждено поле /Contents подписи PDF"));
        }
        contents_end += 1;
    }
    if contents_end >= bytes.len() {
        return Err(signing_error("не закрыто поле /Contents подписи PDF"));
    }
    let marker = b"/ByteRange";
    let before = contents_at.saturating_sub(1024)..contents_at;
    let after_end = (contents_end + 1024).min(bytes.len());
    let offsets_at = search_back(bytes, before, marker)
        .or_else(|| {
            find_subsequence(&bytes[contents_end..after_end], marker).map(|p| contents_end + p)
        })
        .map(|at| at + marker.len())
        .ok_or_else(|| signing_error("не удалось найти диапазон подписи в PDF"))?;
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
        return Err(signing_error(format!(
            "поле подписи вне документа: <{} .. {}>, файл {} байт",
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
        return Err(signing_error(
            "подпись относится к другому положению поля PDF",
        ));
    }
    if cms.is_empty() {
        return Err(signing_error("пустая CMS подписи PDF"));
    }
    let cms = trim_der(cms)?;
    let capacity = contents_end.saturating_sub(contents_at + 1);
    if cms.len() * 2 > capacity {
        return Err(signing_error(format!(
            "подпись не помещается в зарезервированное поле PDF: {} > {} байт",
            cms.len(),
            capacity / 2
        )));
    }
    let mut output = staged.to_vec();
    let br_len = OFFSETS.len();
    if output.get(offsets_at) != Some(&b'[')
        || output.get(offsets_at + br_len - 1) != Some(&b']')
    {
        return Err(signing_error("заглушка /ByteRange не на своём месте"));
    }
    let tail_start = contents_end + 1;
    let text = format!("[0 {} {} {}", contents_at, tail_start, staged.len() - tail_start);
    if text.len() >= br_len {
        return Err(signing_error("диапазон подписи не помещается в заглушку"));
    }
    let mut field = text.into_bytes();
    field.resize(br_len - 1, b' ');   // добиваем пробелами
    field.push(b']');
    output[offsets_at..offsets_at + br_len].copy_from_slice(&field);
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

/// `/ByteRange`: `[ 0 A B C]`, где `A` — смещение `<` в `/Contents`, `B` — сразу после `>`.
fn range_value(file_len: usize, contents_at: usize, contents_end: usize) -> String {
    let tail_start = contents_end + 1;
    format!("[ 0 {contents_at} {tail_start} {}]", file_len - tail_start)
}

/// Вписывает CMS в `/Contents` и записывает подписанный PDF (существующий файл не перезаписывается).
pub fn finish(
    prepared: &PreparedDocument,
    payload: &PdfSignaturePayload,
    output_path: &Path,
) -> Result<SignResult, SignerError> {
    let (_, contents_at, contents_end) = locate(&prepared.bytes)?;
    if payload.contents_at != contents_at {
        return Err(signing_error(
            "подпись относится к другому положению поля PDF",
        ));
    }
    let bytes = assemble_document(&prepared.bytes, contents_at, contents_end, &payload.cms)?;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
        .map_err(|error| {
            signing_error(format!(
                "не удалось создать файл результата без перезаписи ({}): {error}",
                output_path.display()
            ))
        })?;
    if let Err(error) = file.write_all(&bytes) {
        drop(file);
        let _ = std::fs::remove_file(output_path);
        return Err(signing_error(format!(
            "не удалось записать подписанный PDF: {error}"
        )));
    }
    let _ = std::fs::remove_file(&prepared.path);
    Ok(SignResult {
        output_path: output_path.display().to_string(),
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

fn certificate_info(certificate_id: &str) -> Result<CertInfo, SignerError> {
    use crate::signer::Signer as _;
    crate::signer::native::NativeSigner
        .list_certs()?
        .into_iter()
        .find(|certificate| certificate.id == certificate_id)
        .ok_or_else(|| {
            signing_error("выбранный сертификат больше не найден в Windows Personal")
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
        return Err(signing_error("CMS не начинается с DER SEQUENCE"));
    }
    let (header, len) = match cms[1] {
        n if n < 0x80 => (2, n as usize),
        0x80 => return Ok(cms), // BER с неопределённой длиной: обрезать нельзя
        n => {
            let k = (n & 0x7F) as usize;
            if k > 4 || cms.len() < 2 + k {
                return Err(signing_error("некорректная длина CMS"));
            }
            let len = cms[2..2 + k].iter().fold(0usize, |a, &b| (a << 8) | b as usize);
            (2 + k, len)
        }
    };
    let total = header + len;
    if total > cms.len() {
        return Err(signing_error("CMS короче, чем заявлено в заголовке"));
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
        return Err(signing_error("заглушка /ByteRange не на своём месте"));
    }
    let tail_start = contents_end + 1;
    let text = format!("[0 {} {} {}", contents_at, tail_start, out.len() - tail_start);
    if text.len() >= br_len {
        return Err(signing_error("диапазон подписи не помещается в заглушку"));
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

/// Отрезает всё после последнего `%%EOF`: в PDF допустим мусор в конце, но он попадёт
/// в подписанный диапазон, поэтому его лучше не переносить.
fn trim_to_last_eof(bytes: &mut Vec<u8>) {
    let needle = b"%%EOF";
    if let Some(at) = search_back(bytes, 0..bytes.len(), needle) {
        bytes.truncate(at + needle.len());
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn find_previous_xref(bytes: &[u8]) -> Option<u64> {
    let at = bytes
        .windows(b"\nstartxref\n".len())
        .rposition(|w| w == b"\nstartxref\n")?;
    let tail = &bytes[at + b"\nstartxref\n".len()..];
    let end = tail.iter().position(|&b| b == b'\n' || b == b'\r')?;
    std::str::from_utf8(&tail[..end]).ok()?.parse::<u64>().ok()
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
        signing_error(format!(
            "в PDF нет страницы {} (всего {})",
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
        return Err(signing_error("дерево страниц PDF вложено слишком глубоко"));
    }
    let dictionary = document
        .get_dictionary(node)
        .map_err(|error| signing_error(format!("не удалось прочитать страницу PDF: {error}")))?;
    let kind = dictionary
        .get(b"Type")
        .and_then(Object::as_name)
        .unwrap_or_default();
    if kind == b"Pages" {
        let kids = dictionary
            .get(b"Kids")
            .and_then(Object::as_array)
            .map_err(|error| signing_error(format!("нет /Kids в дереве страниц: {error}")))?;
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

/// `/MediaBox` и `/CropBox` страницы: начало координат и размер видимой области.
fn page_box(
    document: &Document,
    pages_id: lopdf::ObjectId,
    page_id: lopdf::ObjectId,
) -> Result<(f64, f64, f64, f64), SignerError> {
    let page = document
        .get_dictionary(page_id)
        .map_err(|error| signing_error(format!("не удалось прочитать страницу PDF: {error}")))?;
    let media = inheritable(document, page, pages_id, b"MediaBox")
        .or_else(|| inheritable(document, page, pages_id, b"CropBox"))
        .and_then(|value| value.as_array().ok().cloned())
        .ok_or_else(|| signing_error("в странице PDF нет MediaBox"))?;
    if media.len() != 4 {
        return Err(signing_error("некорректный MediaBox страницы PDF"));
    }
    let values = media
        .iter()
        .map(|value| value.as_float().map(f64::from))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| signing_error("некорректный MediaBox страницы PDF"))?;
    let (left, bottom) = (values[0].min(values[2]), values[1].min(values[3]));
    let (right, top) = (values[2].max(values[0]), values[3].max(values[1]));
    Ok((left, bottom, right - left, top - bottom))
}

fn page_rotation(document: &Document, pages_id: lopdf::ObjectId, page_id: lopdf::ObjectId) -> i64 {
    document
        .get_dictionary(page_id)
        .ok()
        .and_then(|page| inheritable(document, page, pages_id, b"Rotate"))
        .and_then(|value| value.as_i64().ok())
        .unwrap_or(0)
        .rem_euclid(360)
}

fn mm_to_points(mm: f64) -> f64 {
    mm * 72.0 / 25.4
}

/// Переводит прямоугольник (мм от левого верхнего угла отображаемой страницы) в координаты PDF.
///
/// Повёрнутая страница показывается в Reader повёрнутой, поэтому отметка размещается в той
/// же видимой точке: координаты считаются в системе «после поворота» и переводятся обратно.
fn box_in_page(
    stamp: &PdfStampSpec,
    page_width: f64,
    page_height: f64,
    rotation: i64,
) -> Result<(f64, f64, f64, f64), SignerError> {
    let rotated = rotation == 90 || rotation == 270;
    let (display_width, display_height) = if rotated {
        (page_height, page_width)
    } else {
        (page_width, page_height)
    };
    let left = mm_to_points(stamp.left_mm);
    let top = mm_to_points(stamp.top_mm);
    let width = mm_to_points(stamp.width_mm);
    let height = mm_to_points(stamp.height_mm);
    if width <= 0.0 || height <= 0.0 {
        return Err(signing_error(
            "область отметки пуста: нарисуйте прямоугольник штампа",
        ));
    }
    if left < -0.5
        || top < -0.5
        || left + width > display_width + 0.5
        || top + height > display_height + 0.5
    {
        return Err(signing_error(
            "область отметки выходит за пределы страницы PDF",
        ));
    }
    if !rotated {
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
    lines.push((format!("Владелец {}", signer.owner_name), 5.5));
    if !signer.not_before.is_empty() && !signer.not_after.is_empty() {
        lines.push((
            format!("Действителен с {} по {}", signer.not_before, signer.not_after),
            5.5,
        ));
    }
    lines
}

/// Поток формы отметки: рамка и строки, уложенные по ширине штампа.
///
/// Текст пишется CID-кодами Identity-H встроенного DejaVu, поэтому кириллица отображается
/// на любой машине. Строка уменьшается, если не помещается в область.
fn appearance_content(encoded: &[embed_font::EncodedLine], width: f64, height: f64) -> Vec<u8> {
    let font = embed_font::font();
    let available = width - 9.0;
    let mut content = String::new();
    content.push_str(&format!(
        "q 0.55 0.55 0.55 RG 0.6 w 0.6 0.6 {:.2} {:.2} re S Q\n",
        width - 1.2,
        height - 1.2
    ));
    let mut y = height - 11.0;
    for line in encoded {
        if y < 6.0 {
            break;
        }
        let size = line.font_size.max(4.0);
        let natural = f64::from(line.width_units) / f64::from(font.units_per_em) * size;
        let scale = if natural > available {
            (available / natural).clamp(0.55, 1.0)
        } else {
            1.0
        };
        let hex = embed_font::cids_to_hex(line);
        content.push_str(&format!(
            "BT /F0 {:.2} Tf 0.12 0.12 0.12 rg 4.5 {:.2} Td <{}> Tj ET\n",
            size * scale,
            y,
            hex
        ));
        y -= size + 2.4;
    }
    content.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Минимальный PDF с таблицей xref и полем `/Sig`-заглушкой.
    fn sample_staged_pdf() -> Vec<u8> {
        let mut document = Document::with_version("1.7");
        let pages_id = document.new_object_id();
        let content_id = document.add_object(Stream::new(
            Dictionary::new(),
            b"BT /F1 12 Tf 72 720 Td (Probe) Tj ET".to_vec(),
        ));
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
        document.add_object(Object::Dictionary(Dictionary::from_iter([
            (b"Type".to_vec(), Object::Name(b"Sig".to_vec())),
            (
                b"SubFilter".to_vec(),
                Object::Name(b"ETSI.CAdES.detached".to_vec()),
            ),
            (
                b"Contents".to_vec(),
                Object::String(vec![b'0'; 4096 * 2], StringFormat::Hexadecimal).into(),
            ),
            (
                b"ByteRange".to_vec(),
                Object::String(OFFSETS.to_vec(), StringFormat::Literal).into(),
            ),
        ])));
        let mut bytes = Vec::new();
        document.save_to(&mut bytes).unwrap();
        bytes
    }

    #[test]
    fn byte_range_keeps_file_length() {
        let bytes = sample_staged_pdf();
        let contents_at = locate_contents(&bytes).unwrap();
        let offsets_at = find_subsequence(&bytes, b"/ByteRange")
            .map(|at| at + b"/ByteRange".len())
            .unwrap();
        assert_eq!(bytes[contents_at], b'<');
        let contents_end = contents_at + 1 + 8192;
        assert_eq!(bytes[contents_end], b'>');

        let signed = assemble_document(&bytes, contents_at, contents_end, &[0x30, 0x80]).unwrap();
        assert_eq!(signed.len(), bytes.len(), "длина файла не меняется");
        let range = range_value(bytes.len(), contents_at, contents_end);
        assert_eq!(signed[offsets_at], b'[');
        assert_eq!(signed[offsets_at + OFFSETS.len() - 1], b']');
        assert_eq!(
            &signed[offsets_at + OFFSETS.len() - 1 - range.len()..offsets_at + OFFSETS.len() - 1],
            range.as_bytes()
        );
        assert_eq!(signed[contents_at], b'<');
        assert_eq!(&signed[contents_at + 1..contents_at + 5], b"3080");
        assert_eq!(signed[contents_end], b'>');
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
}