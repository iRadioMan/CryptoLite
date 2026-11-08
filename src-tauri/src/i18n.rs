#![deny(unsafe_code)]
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Language {
    Ru = 0,
    En = 1,
}

impl Language {
    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "ru" => Some(Self::Ru),
            "en" => Some(Self::En),
            _ => None,
        }
    }
}

static CURRENT: AtomicU8 = AtomicU8::new(Language::Ru as u8);

pub fn set(language: Language) {
    CURRENT.store(language as u8, Ordering::Relaxed);
}

pub fn current() -> Language {
    if CURRENT.load(Ordering::Relaxed) == Language::En as u8 {
        Language::En
    } else {
        Language::Ru
    }
}

#[macro_export]
macro_rules! tr {
    ($ru:literal, $en:literal $(, $arg:expr)* $(,)?) => {
        match $crate::i18n::current() {
            $crate::i18n::Language::Ru => format!($ru $(, $arg)*),
            $crate::i18n::Language::En => format!($en $(, $arg)*),
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_tags_are_strict() {
        assert_eq!(Language::from_tag("ru"), Some(Language::Ru));
        assert_eq!(Language::from_tag("en"), Some(Language::En));
        assert_eq!(Language::from_tag("system"), None);
        assert_eq!(Language::from_tag("de"), None);
    }

    #[test]
    fn messages_follow_current_language() {
        set(Language::En);
        assert_eq!(tr!("ошибка", "error"), "error");
        assert_eq!(
            crate::signer::SignerError::Signing("detail".to_owned()).to_string(),
            "Could not sign the file: detail"
        );

        set(Language::Ru);
        assert_eq!(tr!("ошибка", "error"), "ошибка");
        assert_eq!(
            crate::signer::SignerError::Signing("detail".to_owned()).to_string(),
            "Не удалось подписать файл: detail"
        );
    }
}
