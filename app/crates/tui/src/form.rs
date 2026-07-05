use qanvuli_db::{CveAdvancedQueryMode, CveAdvancedSearch, CveStateScope, CveSummarySortOrder};

use super::mode::SearchMode;

#[derive(Clone, Debug)]
pub(super) struct AdvancedForm {
    pub(super) query: String,
    pub(super) query_mode: SearchMode,
    pub(super) published_from: String,
    pub(super) published_to: String,
    pub(super) cwe: String,
    pub(super) product: String,
    pub(super) product_exact: String,
    pub(super) vendor: String,
    pub(super) vendor_exact: String,
    pub(super) state_scope: CveStateScope,
    pub(super) active_field: AdvancedField,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AdvancedField {
    Query,
    PublishedFrom,
    PublishedTo,
    Cwe,
    Product,
    ProductExact,
    Vendor,
    VendorExact,
    StateScope,
}

impl Default for AdvancedForm {
    fn default() -> Self {
        Self {
            query: String::new(),
            query_mode: SearchMode::FreeText,
            published_from: String::new(),
            published_to: String::new(),
            cwe: String::new(),
            product: String::new(),
            product_exact: String::new(),
            vendor: String::new(),
            vendor_exact: String::new(),
            state_scope: CveStateScope::PublishedOnly,
            active_field: AdvancedField::Query,
        }
    }
}

impl AdvancedForm {
    pub(super) fn push(&mut self, ch: char) {
        if let Some(field) = self.active_text_mut() {
            field.push(ch);
        }
        self.apply_query_prefix_mode();
    }

    pub(super) fn backspace(&mut self) {
        if let Some(field) = self.active_text_mut() {
            field.pop();
        }
        self.apply_query_prefix_mode();
    }

    fn active_text_mut(&mut self) -> Option<&mut String> {
        match self.active_field {
            AdvancedField::Query => Some(&mut self.query),
            AdvancedField::PublishedFrom => Some(&mut self.published_from),
            AdvancedField::PublishedTo => Some(&mut self.published_to),
            AdvancedField::Cwe => Some(&mut self.cwe),
            AdvancedField::Product => Some(&mut self.product),
            AdvancedField::ProductExact => Some(&mut self.product_exact),
            AdvancedField::Vendor => Some(&mut self.vendor),
            AdvancedField::VendorExact => Some(&mut self.vendor_exact),
            AdvancedField::StateScope => None,
        }
    }

    pub(super) fn next_field(&mut self) {
        self.active_field = self.active_field.next();
    }

    pub(super) fn previous_field(&mut self) {
        self.active_field = self.active_field.previous();
    }

    pub(super) fn next_value(&mut self) {
        if matches!(self.active_field, AdvancedField::StateScope) {
            self.state_scope = self.state_scope.next();
        }
    }

    pub(super) fn previous_value(&mut self) {
        if matches!(self.active_field, AdvancedField::StateScope) {
            self.state_scope = self.state_scope.previous();
        }
    }

    pub(super) fn to_search_options(&self, sort_order: CveSummarySortOrder) -> CveAdvancedSearch {
        CveAdvancedSearch {
            query: option_string(&self.query),
            query_mode: Some(self.query_mode.into()),
            published_from: option_string(&self.published_from),
            published_to: option_string(&self.published_to),
            cwe: option_string(&self.cwe),
            product: option_string(&self.product),
            product_exact: option_string(&self.product_exact),
            vendor: option_string(&self.vendor),
            vendor_exact: option_string(&self.vendor_exact),
            state_scope: self.state_scope,
            sort_order,
        }
    }

    fn apply_query_prefix_mode(&mut self) {
        if matches!(self.active_field, AdvancedField::Query)
            && let Some(mode) = SearchMode::from_query_prefix(&self.query)
        {
            self.query_mode = mode;
        }
    }
}

impl AdvancedField {
    fn next(self) -> Self {
        match self {
            Self::Query => Self::PublishedFrom,
            Self::PublishedFrom => Self::PublishedTo,
            Self::PublishedTo => Self::Cwe,
            Self::Cwe => Self::Product,
            Self::Product => Self::ProductExact,
            Self::ProductExact => Self::Vendor,
            Self::Vendor => Self::VendorExact,
            Self::VendorExact => Self::StateScope,
            Self::StateScope => Self::Query,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::Query => Self::StateScope,
            Self::PublishedFrom => Self::Query,
            Self::PublishedTo => Self::PublishedFrom,
            Self::Cwe => Self::PublishedTo,
            Self::Product => Self::Cwe,
            Self::ProductExact => Self::Product,
            Self::Vendor => Self::ProductExact,
            Self::VendorExact => Self::Vendor,
            Self::StateScope => Self::VendorExact,
        }
    }
}

impl From<SearchMode> for CveAdvancedQueryMode {
    fn from(value: SearchMode) -> Self {
        match value {
            SearchMode::FreeText => Self::FreeText,
            SearchMode::Product => Self::Product,
            SearchMode::Vendor => Self::Vendor,
            SearchMode::Cwe => Self::Cwe,
            SearchMode::Cve => Self::Cve,
            SearchMode::Identifier => Self::FreeText,
        }
    }
}

pub(super) trait StateScopeUi {
    fn next(self) -> Self;
    fn previous(self) -> Self;
    fn label(self) -> &'static str;
}

impl StateScopeUi for CveStateScope {
    fn next(self) -> Self {
        match self {
            Self::PublishedOnly => Self::IncludeRejected,
            Self::IncludeRejected => Self::PublishedOnly,
        }
    }

    fn previous(self) -> Self {
        self.next()
    }

    fn label(self) -> &'static str {
        match self {
            Self::PublishedOnly => "published only",
            Self::IncludeRejected => "include rejected",
        }
    }
}

fn option_string(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}
