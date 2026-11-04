#![deny(unsafe_code)]
//! Встраивание DejaVu Sans Condensed в PDF и кодирование текста отметки об ЭП.
//!
//! Шрифт поставляется вместе с приложением (`assets/fonts/DejaVuSansCondensed.ttf`,
//! лицензия Bitstream Vera / DejaVu, см. `LICENSE-DejaVu.txt`), поэтому кириллица
//! отображается одинаково независимо от шрифтов в системе.
//!
//! Кодировка — Type0/Identity-H: в PDF пишутся двухбайтовые CID, а отображение
//! «CID → Unicode» записывается в `/ToUnicode`, поэтому текст ищется и копируется.
//! Глифы берутся из `cmap` шрифта: CID — это номер глифа DejaVu (U+0410 → глиф 1040),
//! а не Unicode-код, иначе «Р» рисовалась бы чужим символом.

use lopdf::{Dictionary, Object, Stream, StringFormat};
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// Кегль строки по умолчанию, если он не задан при кодировании.
pub const DEFAULT_FONT_SIZE: f64 = 5.5;

/// Минимальный разбор TrueType: нужны `head`, `hhea`, `hmtx` и `cmap`.
pub struct EmbeddedFont {
    pub data: &'static [u8],
    pub units_per_em: u16,
    pub ascent: i16,
    pub descent: i16,
    pub bbox: [i16; 4],
    /// Unicode → номер глифа.
    cmap: BTreeMap<u16, u16>,
    /// Номер глифа → ширина (в единицах шрифта).
    advance_widths: Vec<u16>,
}

const FONT_BYTES: &[u8] = include_bytes!("../../assets/fonts/DejaVuSansCondensed.ttf");
/// Имя шрифта в PDF. В файл встраиваются все глифы DejaVu, поэтому префикс подмножества
/// (`ABCDEF+`) не используется: он заставляет Reader искать недостающие глифы в системе.
const BASE_FONT: &[u8] = b"DejaVuSansCondensed";

fn read_u16(data: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([data[at], data[at + 1]])
}

fn read_i16(data: &[u8], at: usize) -> i16 {
    read_u16(data, at) as i16
}

fn read_u32(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

/// (offset, length) таблицы по тегу.
fn table(data: &[u8], tag: &[u8; 4]) -> Option<(usize, usize)> {
    if data.len() < 12 {
        return None;
    }
    let count = read_u16(data, 4) as usize;
    for index in 0..count {
        let entry = 12 + index * 16;
        if entry + 16 > data.len() {
            return None;
        }
        if &data[entry..entry + 4] == tag {
            let offset = read_u32(data, entry + 8) as usize;
            let length = read_u32(data, entry + 12) as usize;
            return Some((offset, length.min(data.len().saturating_sub(offset))));
        }
    }
    None
}

/// Разбор `cmap`: формат 4 (BMP) обязателен для DejaVu. Сначала ищется Windows BMP
/// (3/1), затем Unicode (0/3): кириллица есть в обоих.
fn parse_cmap(data: &[u8]) -> BTreeMap<u16, u16> {
    let mut map = BTreeMap::new();
    let Some((cmap, _)) = table(data, b"cmap") else {
        return map;
    };
    if cmap + 4 > data.len() {
        return map;
    }
    let count = read_u16(data, cmap + 2) as usize;
    for index in 0..count {
        let record = cmap + 4 + index * 8;
        if record + 8 > data.len() {
            break;
        }
        let platform = read_u16(data, record);
        let encoding = read_u16(data, record + 2);
        let offset = cmap + read_u32(data, record + 4) as usize;
        let usable = (platform == 3 && (encoding == 1 || encoding == 10)) || platform == 0;
        if !usable || offset + 2 > data.len() {
            continue;
        }
        let format = read_u16(data, offset);
        if format != 4 {
            continue;
        }
        let seg_count = read_u16(data, offset + 6) as usize / 2;
        let ends = offset + 14;
        let starts = ends + seg_count * 2 + 2;
        let deltas = starts + seg_count * 2;
        let ranges = deltas + seg_count * 2;
        if ranges + seg_count * 2 > data.len() {
            continue;
        }
        for segment in 0..seg_count {
            let end = read_u16(data, ends + segment * 2);
            let start = read_u16(data, starts + segment * 2);
            let delta = read_i16(data, deltas + segment * 2);
            let range = read_u16(data, ranges + segment * 2);
            if start > end {
                continue;
            }
            for code in start..=end {
                if code == 0xFFFF {
                    continue;
                }
                let glyph = if range == 0 {
                    code.wrapping_add_signed(delta)
                } else {
                    let at = ranges + segment * 2 + range as usize + (code - start) as usize * 2;
                    if at + 2 > data.len() {
                        continue;
                    }
                    let raw = read_u16(data, at);
                    if raw == 0 {
                        continue;
                    }
                    raw.wrapping_add_signed(delta)
                };
                if glyph != 0 {
                    map.insert(code, glyph);
                }
            }
        }
        if !map.is_empty() {
            break;
        }
    }
    map
}

fn parse_advance_widths(data: &[u8], glyph_count: usize) -> Vec<u16> {
    let mut widths = vec![0u16; glyph_count];
    let (Some((_, _)), Some((hhea, _)), Some((hmtx, _))) = (
        table(data, b"head"),
        table(data, b"hhea"),
        table(data, b"hmtx"),
    ) else {
        return widths;
    };
    let metrics = if hhea > 0 && hhea + 36 <= data.len() {
        read_u16(data, hhea + 34) as usize
    } else {
        0
    };
    if metrics == 0 || hmtx + metrics * 4 > data.len() {
        return widths;
    }
    let mut last = 0u16;
    for glyph in 0..glyph_count {
        if glyph < metrics {
            last = read_u16(data, hmtx + glyph * 4);
        }
        widths[glyph] = last;
    }
    widths
}

fn load() -> EmbeddedFont {
    let data = FONT_BYTES;
    let (head, _) = table(data, b"head").unwrap_or((0, 0));
    let (hhea, _) = table(data, b"hhea").unwrap_or((0, 0));
    let (maxp, _) = table(data, b"maxp").unwrap_or((0, 0));
    let glyph_count = if maxp > 0 {
        read_u16(data, maxp + 4) as usize
    } else {
        0
    };
    let cmap = parse_cmap(data);
    let advance_widths = if glyph_count > 0 {
        parse_advance_widths(data, glyph_count)
    } else {
        Vec::new()
    };
    EmbeddedFont {
        data,
        units_per_em: if head > 0 {
            read_u16(data, head + 18)
        } else {
            2048
        },
        ascent: if hhea > 0 {
            read_i16(data, hhea + 4)
        } else {
            1901
        },
        descent: if hhea > 0 {
            read_i16(data, hhea + 6)
        } else {
            -483
        },
        bbox: if head > 0 {
            [
                read_i16(data, head + 36),
                read_i16(data, head + 38),
                read_i16(data, head + 40),
                read_i16(data, head + 42),
            ]
        } else {
            [-1881, -948, 3306, 2524]
        },
        cmap,
        advance_widths,
    }
}

/// Единственный экземпляр: шрифт разбирается один раз на процесс.
pub fn font() -> &'static EmbeddedFont {
    static FONT: OnceLock<EmbeddedFont> = OnceLock::new();
    FONT.get_or_init(load)
}

impl EmbeddedFont {
    /// Номер глифа по Unicode-символу; 0 — символ в шрифте отсутствует.
    pub fn glyph(&self, code: u16) -> u16 {
        self.cmap.get(&code).copied().unwrap_or(0)
    }

    /// Ширина глифа в единицах шрифта.
    pub fn width_of_glyph(&self, glyph: u16) -> u16 {
        self.advance_widths
            .get(glyph as usize)
            .copied()
            .filter(|width| *width > 0)
            .unwrap_or(self.units_per_em / 2)
    }

    /// Ширина символа в единицах шрифта.
    fn width_of(&self, code: u16) -> u16 {
        self.width_of_glyph(self.glyph(code))
    }
}

/// Один символ отметки: Unicode, его CID (номер глифа) и ширина.
#[derive(Debug, Clone, Copy)]
pub struct GlyphRef {
    pub code: u16,
    pub cid: u16,
    pub width: u16,
}

/// Разметка строки: символы с CID, их общая ширина и кегль.
pub struct EncodedLine {
    pub cids: Vec<GlyphRef>,
    pub width_units: u32,
    pub font_size: f64,
}

/// Кодирует строки шрифтом по умолчанию.
pub fn encode_lines(lines: &[&str]) -> (Vec<EncodedLine>, BTreeMap<u16, u16>) {
    encode_lines_with_sizes(lines, &vec![DEFAULT_FONT_SIZE; lines.len()])
}

/// Кодирует строки с кеглями из `sizes` (строки без кегля получают [`DEFAULT_FONT_SIZE`]).
///
/// Возвращает строки и отображение «CID → Unicode» для `/ToUnicode` и `/CIDSInit`.
pub fn encode_lines_with_sizes(
    lines: &[&str],
    sizes: &[f64],
) -> (Vec<EncodedLine>, BTreeMap<u16, u16>) {
    let font = font();
    let mut cid_to_code: BTreeMap<u16, u16> = BTreeMap::new();
    let encoded = lines
        .iter()
        .enumerate()
        .map(|(index, line)| {
            let mut cids = Vec::new();
            let mut width = 0u32;
            for code in line.encode_utf16() {
                let glyph = font.glyph(code);
                // Символ, которого нет в шрифте, заменяется пробелом, а не пустым глифом.
                let (cid, width_of) = if glyph != 0 {
                    (glyph, font.width_of_glyph(glyph))
                } else {
                    let space = font.glyph(b' ' as u16);
                    (space, font.width_of_glyph(space))
                };
                cid_to_code.insert(cid, code);
                cids.push(GlyphRef {
                    code,
                    cid,
                    width: width_of,
                });
                width += u32::from(width_of);
            }
            EncodedLine {
                cids,
                width_units: width,
                font_size: sizes
                    .get(index)
                    .copied()
                    .filter(|size| *size > 0.0)
                    .unwrap_or(DEFAULT_FONT_SIZE),
            }
        })
        .collect();
    (encoded, cid_to_code)
}

/// Ширина строки в пунктах для её кегля.
pub fn line_width(line: &EncodedLine) -> f64 {
    f64::from(line.width_units) / f64::from(font().units_per_em) * line.font_size
}

/// Hex-строка кодов Identity-H (по 2 байта на CID).
pub fn cids_to_hex(line: &EncodedLine) -> String {
    line.cids
        .iter()
        .map(|glyph| format!("{:04X}", glyph.cid))
        .collect()
}

/// Объекты шрифта Type0 с встроенным TrueType: (font, font_file, descriptor,
/// cid_font, to_unicode). Номера выдаёт вызывающий: документ дописывается
/// инкрементальным обновлением.
pub struct FontObjects {
    pub font: Object,
    pub font_file: Object,
    pub descriptor: Object,
    pub cid_font: Object,
    pub to_unicode: Object,
}

pub fn font_objects(cid_to_code: &BTreeMap<u16, u16>) -> FontObjects {
    let font_data = font();
    let font_file = Object::Stream(Stream::new(
        Dictionary::from_iter([(
            b"Length1".to_vec(),
            Object::Integer(font_data.data.len() as i64),
        )]),
        font_data.data.to_vec(),
    ));

    let descriptor = Dictionary::from_iter([
        (b"Type".to_vec(), Object::Name(b"FontDescriptor".to_vec())),
        (b"FontName".to_vec(), Object::Name(BASE_FONT.to_vec())),
        // Флаг 32 — Nonsymbolic: коды интерпретируются по CMap, а не как кодовая страница.
        (b"Flags".to_vec(), Object::Integer(32)),
        (
            b"FontBBox".to_vec(),
            Object::Array(
                font_data.bbox
                    .iter()
                    .map(|value| Object::Integer(i64::from(*value)))
                    .collect(),
            ),
        ),
        (b"ItalicAngle".to_vec(), Object::Integer(0)),
        (b"Ascent".to_vec(), Object::Integer(i64::from(font_data.ascent))),
        (
            b"Descent".to_vec(),
            Object::Integer(i64::from(font_data.descent)),
        ),
        (b"CapHeight".to_vec(), Object::Integer(1493)),
        (b"StemV".to_vec(), Object::Integer(80)),
    ]);

    // /W: ширины ровно для использованных CID, по 1000 единиц на кегль.
    let widths: Vec<Object> = cid_to_code
        .keys()
        .map(|cid| {
            let width = (f64::from(font_data.width_of_glyph(*cid))
                / f64::from(font_data.units_per_em)
                * 1000.0)
                .round() as i64;
            Object::Array(vec![
                Object::Integer(i64::from(*cid)),
                Object::Array(vec![Object::Integer(width)]),
            ])
        })
        .collect();

    let cid_font = Dictionary::from_iter([
        (b"Type".to_vec(), Object::Name(b"Font".to_vec())),
        (b"Subtype".to_vec(), Object::Name(b"CIDFontType2".to_vec())),
        (b"BaseFont".to_vec(), Object::Name(BASE_FONT.to_vec())),
        (
            b"CIDSystemInfo".to_vec(),
            Object::Dictionary(Dictionary::from_iter([
                (
                    b"Registry".to_vec(),
                    Object::String(b"Adobe".to_vec(), StringFormat::Literal).into(),
                ),
                (
                    b"Ordering".to_vec(),
                    Object::String(b"Identity".to_vec(), StringFormat::Literal).into(),
                ),
                (b"Supplement".to_vec(), Object::Integer(0)),
            ])),
        ),
        (
            b"DW".to_vec(),
            Object::Integer(i64::from(font_data.width_of(b' ' as u16))),
        ),
        (b"W".to_vec(), Object::Array(widths)),
        // Код CID — это номер глифа TrueType-шрифта: таблица глифов не переставляется.
        (
            b"CIDToGIDMap".to_vec(),
            Object::Name(b"Identity".to_vec()),
        ),
    ]);

    // /ToUnicode: CID → Unicode, чтобы текст корректно копировался и искался.
    let mut cmap = String::from(
        "/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n\
         /CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n\
         /CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n\
         1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n",
    );
    let pairs: Vec<(&u16, &u16)> = cid_to_code.iter().collect();
    for chunk in pairs.chunks(100) {
        cmap.push_str(&format!("{} beginbfchar\n", chunk.len()));
        for (cid, code) in chunk {
            cmap.push_str(&format!("<{cid:04X}> <{code:04X}>\n"));
        }
        cmap.push_str("endbfchar\n");
    }
    cmap.push_str("endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n");

    FontObjects {
        font: Object::Dictionary(Dictionary::from_iter([
            (b"Type".to_vec(), Object::Name(b"Font".to_vec())),
            (b"Subtype".to_vec(), Object::Name(b"Type0".to_vec())),
            (b"BaseFont".to_vec(), Object::Name(BASE_FONT.to_vec())),
            (b"Encoding".to_vec(), Object::Name(b"Identity-H".to_vec())),
        ])),
        font_file,
        descriptor: Object::Dictionary(descriptor),
        cid_font: Object::Dictionary(cid_font),
        to_unicode: Object::Stream(Stream::new(Dictionary::new(), cmap.into_bytes())),
    }
}