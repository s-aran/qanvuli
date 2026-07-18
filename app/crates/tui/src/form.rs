use qanvuli_core::database::{
    CveAdvancedQueryMode, CveAdvancedSearch, CveStateScope, CveSummarySortOrder,
};

use super::mode::SearchMode;

#[derive(Clone, Debug)]
pub(super) struct AdvancedForm {
    pub(super) query: String,
    pub(super) query_mode: SearchMode,
    pub(super) published_from: String,
    pub(super) published_to: String,
    pub(super) cwe: String,
    pub(super) product: String,
    pub(super) product_exact: bool,
    pub(super) vendor: String,
    pub(super) vendor_exact: bool,
    pub(super) state_scope: CveStateScope,
    pub(super) active_field: AdvancedField,
    pub(super) source_cve: bool,
    pub(super) source_osv: bool,
    pub(super) advisories: Vec<(String, bool)>,
    pub(super) scope_cursor: usize,
    pub(super) scope_filter: String,
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
            product_exact: false,
            vendor: String::new(),
            vendor_exact: false,
            state_scope: CveStateScope::PublishedOnly,
            active_field: AdvancedField::Query,
            source_cve: true,
            source_osv: true,
            advisories: Vec::new(),
            scope_cursor: 0,
            scope_filter: String::new(),
        }
    }
}

impl AdvancedForm {
    pub(super) fn next_scope(&mut self) {
        self.scope_cursor = (self.scope_cursor + 1) % self.scope_entries().len().max(1);
    }
    pub(super) fn previous_scope(&mut self) {
        self.scope_cursor = if self.scope_cursor == 0 {
            self.scope_entries().len().saturating_sub(1)
        } else {
            self.scope_cursor - 1
        };
    }

    pub(super) fn toggle_scope_current(&mut self) {
        match self.scope_entries().get(self.scope_cursor).copied() {
            Some(ScopeEntry::Cve) => self.source_cve = !self.source_cve,
            Some(ScopeEntry::Osv) => self.source_osv = !self.source_osv,
            Some(ScopeEntry::Advisory(index)) => {
                self.advisories[index].1 = !self.advisories[index].1
            }
            Some(ScopeEntry::AllAdvisories) => self.select_all_scope(),
            Some(ScopeEntry::ClearAdvisories) => self.clear_all_scope(),
            None => {}
        }
        self.clamp_scope_cursor();
    }

    pub(super) fn set_scope_candidates(&mut self, advisories: Vec<String>) {
        self.advisories = merge_candidates(&self.advisories, advisories);
        self.scope_cursor = self
            .scope_cursor
            .min(self.scope_entries().len().saturating_sub(1));
    }

    pub(super) fn push_scope_filter(&mut self, ch: char) {
        self.scope_filter.push(ch);
        self.scope_cursor = 0;
    }
    pub(super) fn backspace_scope_filter(&mut self) {
        self.scope_filter.pop();
        self.scope_cursor = 0;
    }
    pub(super) fn scope_entries(&self) -> Vec<ScopeEntry> {
        let mut entries = vec![ScopeEntry::Cve, ScopeEntry::Osv];
        if self.source_osv {
            entries.extend(
                self.advisories
                    .iter()
                    .enumerate()
                    .filter(|(_, (name, _))| fuzzy_matches(name, &self.scope_filter))
                    .map(|(index, _)| ScopeEntry::Advisory(index)),
            );
        }
        entries.extend([ScopeEntry::AllAdvisories, ScopeEntry::ClearAdvisories]);
        entries
    }

    pub(super) fn selected_advisories(&self) -> Vec<String> {
        self.advisories
            .iter()
            .filter(|(_, selected)| *selected)
            .map(|(name, _)| name.clone())
            .collect()
    }

    pub(super) fn select_all_scope(&mut self) {
        self.source_osv = true;
        self.advisories
            .iter_mut()
            .for_each(|(_, selected)| *selected = true);
    }

    pub(super) fn clear_all_scope(&mut self) {
        self.source_osv = false;
        self.advisories
            .iter_mut()
            .for_each(|(_, selected)| *selected = false);
        self.clamp_scope_cursor();
    }

    fn clamp_scope_cursor(&mut self) {
        self.scope_cursor = self
            .scope_cursor
            .min(self.scope_entries().len().saturating_sub(1));
    }
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
            AdvancedField::Vendor => Some(&mut self.vendor),
            AdvancedField::ProductExact
            | AdvancedField::VendorExact
            | AdvancedField::StateScope => None,
        }
    }

    pub(super) fn next_field(&mut self) {
        self.active_field = self.active_field.next();
    }

    pub(super) fn previous_field(&mut self) {
        self.active_field = self.active_field.previous();
    }

    pub(super) fn next_value(&mut self) {
        match self.active_field {
            AdvancedField::ProductExact => self.product_exact = !self.product_exact,
            AdvancedField::VendorExact => self.vendor_exact = !self.vendor_exact,
            AdvancedField::StateScope => self.state_scope = self.state_scope.next(),
            _ => {}
        }
    }

    pub(super) fn previous_value(&mut self) {
        match self.active_field {
            AdvancedField::ProductExact => self.product_exact = !self.product_exact,
            AdvancedField::VendorExact => self.vendor_exact = !self.vendor_exact,
            AdvancedField::StateScope => self.state_scope = self.state_scope.previous(),
            _ => {}
        }
    }

    pub(super) fn toggle_current(&mut self) {
        match self.active_field {
            AdvancedField::ProductExact => self.product_exact = !self.product_exact,
            AdvancedField::VendorExact => self.vendor_exact = !self.vendor_exact,
            AdvancedField::StateScope => self.state_scope = self.state_scope.next(),
            _ => {}
        }
    }

    /// Returns whether the focused field accepts text input.
    pub(super) fn active_field_accepts_text(&self) -> bool {
        matches!(
            self.active_field,
            AdvancedField::Query
                | AdvancedField::PublishedFrom
                | AdvancedField::PublishedTo
                | AdvancedField::Cwe
                | AdvancedField::Product
                | AdvancedField::Vendor
        )
    }

    pub(super) fn to_search_options(&self, sort_order: CveSummarySortOrder) -> CveAdvancedSearch {
        let product = option_string(&self.product);
        let vendor = option_string(&self.vendor);
        CveAdvancedSearch {
            query: option_string(&self.query),
            query_mode: Some(self.query_mode.into()),
            published_from: option_string(&self.published_from),
            published_to: option_string(&self.published_to),
            cwe: option_string(&self.cwe),
            product: (!self.product_exact).then(|| product.clone()).flatten(),
            product_exact: self.product_exact.then_some(product).flatten(),
            vendor: (!self.vendor_exact).then(|| vendor.clone()).flatten(),
            vendor_exact: self.vendor_exact.then_some(vendor).flatten(),
            kev_only: false,
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

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum ScopeEntry {
    Cve,
    Osv,
    Advisory(usize),
    AllAdvisories,
    ClearAdvisories,
}

fn fuzzy_matches(value: &str, query: &str) -> bool {
    let mut query = query.chars().flat_map(char::to_lowercase);
    let mut next = query.next();
    for ch in value.chars().flat_map(char::to_lowercase) {
        if next == Some(ch) {
            next = query.next();
        }
    }
    next.is_none()
}

fn merge_candidates(current: &[(String, bool)], values: Vec<String>) -> Vec<(String, bool)> {
    values
        .into_iter()
        .map(|value| {
            let selected = current
                .iter()
                .find(|(name, _)| *name == value)
                .map(|(_, selected)| *selected)
                .unwrap_or(true);
            (value, selected)
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_checkboxes_route_values_to_exact_options() {
        let form = AdvancedForm {
            product: "Django".to_owned(),
            product_exact: true,
            vendor: "Example".to_owned(),
            vendor_exact: false,
            ..AdvancedForm::default()
        };

        let options = form.to_search_options(CveSummarySortOrder::PublishedDesc);

        assert_eq!(options.product, None);
        assert_eq!(options.product_exact.as_deref(), Some("Django"));
        assert_eq!(options.vendor.as_deref(), Some("Example"));
        assert_eq!(options.vendor_exact, None);
    }

    #[test]
    fn exact_checkbox_toggle_does_not_edit_text_fields() {
        let mut form = AdvancedForm {
            product: "Django".to_owned(),
            active_field: AdvancedField::ProductExact,
            ..AdvancedForm::default()
        };

        form.push('x');
        assert_eq!(form.product, "Django");
        assert!(!form.product_exact);

        form.toggle_current();
        assert!(form.product_exact);
    }

    #[test]
    fn text_fields_accept_spaces() {
        let mut form = AdvancedForm {
            active_field: AdvancedField::Product,
            ..AdvancedForm::default()
        };

        assert!(form.active_field_accepts_text());
        form.push(' ');
        assert_eq!(form.product, " ");
    }

    #[test]
    fn scope_candidates_are_filterable_and_selectable() {
        let mut form = AdvancedForm::default();
        form.set_scope_candidates(vec!["GHSA".to_owned(), "RUSTSEC".to_owned()]);

        form.push_scope_filter('g');
        assert!(
            form.scope_entries()
                .iter()
                .any(|entry| matches!(entry, ScopeEntry::Advisory(0)))
        );
        assert!(
            !form
                .scope_entries()
                .iter()
                .any(|entry| matches!(entry, ScopeEntry::Advisory(1)))
        );

        form.clear_all_scope();
        assert!(form.source_cve);
        assert!(!form.source_osv);
        assert!(form.selected_advisories().is_empty());

        form.select_all_scope();
        assert!(form.source_cve);
        assert!(form.source_osv);
        assert_eq!(form.selected_advisories(), vec!["GHSA", "RUSTSEC"]);
    }

    #[test]
    fn disabling_osv_hides_advisories_without_losing_their_selection() {
        let mut form = AdvancedForm::default();
        form.set_scope_candidates(vec!["GHSA".to_owned()]);
        form.scope_cursor = 1;
        form.toggle_scope_current();

        assert!(!form.source_osv);
        assert!(
            !form
                .scope_entries()
                .iter()
                .any(|entry| matches!(entry, ScopeEntry::Advisory(_)))
        );
        assert_eq!(form.selected_advisories(), vec!["GHSA"]);
    }
}
