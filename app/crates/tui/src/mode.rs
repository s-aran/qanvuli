use ratatui::style::Color;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SearchMode {
    FreeText,
    Product,
    Vendor,
    Cwe,
    Cve,
}

impl SearchMode {
    pub(super) fn next(self) -> Self {
        match self {
            Self::FreeText => Self::Product,
            Self::Product => Self::Vendor,
            Self::Vendor => Self::Cwe,
            Self::Cwe => Self::Cve,
            Self::Cve => Self::FreeText,
        }
    }

    pub(super) fn previous(self) -> Self {
        match self {
            Self::FreeText => Self::Cve,
            Self::Product => Self::FreeText,
            Self::Vendor => Self::Product,
            Self::Cwe => Self::Vendor,
            Self::Cve => Self::Cwe,
        }
    }

    pub(super) fn from_query_prefix(query: &str) -> Option<Self> {
        let query = query.trim_start();
        if query
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("CWE-"))
        {
            Some(Self::Cwe)
        } else if query
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("CVE-"))
        {
            Some(Self::Cve)
        } else {
            None
        }
    }

    pub(super) fn footer_text(self) -> &'static str {
        match self {
            Self::FreeText => "free text",
            Self::Product => "product",
            Self::Vendor => "vendor",
            Self::Cwe => "CWE",
            Self::Cve => "CVE prefix",
        }
    }

    pub(super) fn color(self) -> Color {
        match self {
            Self::FreeText => Color::Cyan,
            Self::Product => Color::Green,
            Self::Vendor => Color::Magenta,
            Self::Cwe => Color::Yellow,
            Self::Cve => Color::Blue,
        }
    }
}
