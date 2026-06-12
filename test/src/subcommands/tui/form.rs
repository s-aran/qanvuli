use qanvuli_db::{CveAdvancedSearch, CveSummarySortOrder};

#[derive(Clone, Debug)]
pub(super) struct AdvancedForm {
    pub(super) published_from: String,
    pub(super) published_to: String,
    pub(super) cwe: String,
    pub(super) product: String,
    pub(super) vendor: String,
    pub(super) sort_order: CveSummarySortOrder,
    pub(super) active_field: AdvancedField,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AdvancedField {
    PublishedFrom,
    PublishedTo,
    Cwe,
    Product,
    Vendor,
    SortOrder,
}

impl Default for AdvancedForm {
    fn default() -> Self {
        Self {
            published_from: String::new(),
            published_to: String::new(),
            cwe: String::new(),
            product: String::new(),
            vendor: String::new(),
            sort_order: CveSummarySortOrder::PublishedDesc,
            active_field: AdvancedField::PublishedFrom,
        }
    }
}

impl AdvancedForm {
    pub(super) fn push(&mut self, ch: char) {
        if let Some(field) = self.active_text_mut() {
            field.push(ch);
        }
    }

    pub(super) fn backspace(&mut self) {
        if let Some(field) = self.active_text_mut() {
            field.pop();
        }
    }

    fn active_text_mut(&mut self) -> Option<&mut String> {
        match self.active_field {
            AdvancedField::PublishedFrom => Some(&mut self.published_from),
            AdvancedField::PublishedTo => Some(&mut self.published_to),
            AdvancedField::Cwe => Some(&mut self.cwe),
            AdvancedField::Product => Some(&mut self.product),
            AdvancedField::Vendor => Some(&mut self.vendor),
            AdvancedField::SortOrder => None,
        }
    }

    pub(super) fn next_field(&mut self) {
        self.active_field = self.active_field.next();
    }

    pub(super) fn previous_field(&mut self) {
        self.active_field = self.active_field.previous();
    }

    pub(super) fn next_sort_order(&mut self) {
        if self.active_field == AdvancedField::SortOrder {
            self.sort_order = self.sort_order.next();
        }
    }

    pub(super) fn previous_sort_order(&mut self) {
        if self.active_field == AdvancedField::SortOrder {
            self.sort_order = self.sort_order.previous();
        }
    }

    pub(super) fn to_search_options(&self) -> CveAdvancedSearch {
        CveAdvancedSearch {
            published_from: option_string(&self.published_from),
            published_to: option_string(&self.published_to),
            cwe: option_string(&self.cwe),
            product: option_string(&self.product),
            vendor: option_string(&self.vendor),
            sort_order: self.sort_order,
        }
    }
}

impl AdvancedField {
    fn next(self) -> Self {
        match self {
            Self::PublishedFrom => Self::PublishedTo,
            Self::PublishedTo => Self::Cwe,
            Self::Cwe => Self::Product,
            Self::Product => Self::Vendor,
            Self::Vendor => Self::SortOrder,
            Self::SortOrder => Self::PublishedFrom,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::PublishedFrom => Self::SortOrder,
            Self::PublishedTo => Self::PublishedFrom,
            Self::Cwe => Self::PublishedTo,
            Self::Product => Self::Cwe,
            Self::Vendor => Self::Product,
            Self::SortOrder => Self::Vendor,
        }
    }
}

pub(super) trait SortOrderUi {
    fn next(self) -> Self;
    fn previous(self) -> Self;
    fn label(self) -> &'static str;
}

impl SortOrderUi for CveSummarySortOrder {
    fn next(self) -> Self {
        match self {
            Self::PublishedAsc => Self::PublishedDesc,
            Self::PublishedDesc => Self::CveIdAsc,
            Self::CveIdAsc => Self::CveIdDesc,
            Self::CveIdDesc => Self::RelationRankAsc,
            Self::RelationRankAsc => Self::RelationRankDesc,
            Self::RelationRankDesc => Self::ScoreAsc,
            Self::ScoreAsc => Self::ScoreDesc,
            Self::ScoreDesc => Self::PublishedAsc,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::PublishedAsc => Self::ScoreDesc,
            Self::PublishedDesc => Self::PublishedAsc,
            Self::CveIdAsc => Self::PublishedDesc,
            Self::CveIdDesc => Self::CveIdAsc,
            Self::RelationRankAsc => Self::CveIdDesc,
            Self::RelationRankDesc => Self::RelationRankAsc,
            Self::ScoreAsc => Self::RelationRankDesc,
            Self::ScoreDesc => Self::ScoreAsc,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::PublishedAsc => "published asc",
            Self::PublishedDesc => "published desc",
            Self::CveIdAsc => "a-z asc",
            Self::CveIdDesc => "a-z desc",
            Self::RelationRankAsc => "relation rank asc",
            Self::RelationRankDesc => "relation rank desc",
            Self::ScoreAsc => "score asc",
            Self::ScoreDesc => "score desc",
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
