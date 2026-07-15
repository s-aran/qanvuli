use qanvuli_core::database::CveSummarySortOrder;

#[derive(Clone, Debug)]
pub(super) struct DisplaySettings {
    pub(super) tab: DisplayTab,
    pub(super) sort_field: SortField,
    pub(super) sort_direction: SortDirection,
    pub(super) timezone: TimeZone,
    pub(super) active_field: DisplayField,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DisplayTab {
    Settings,
    Sources,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DisplayField {
    SortField,
    SortDirection,
    TimeZone,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SortField {
    Published,
    Updated,
    CveId,
    RelationRank,
    Score,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SortDirection {
    Asc,
    Desc,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TimeZone {
    Utc,
    Jst,
    Pst,
}

impl Default for DisplaySettings {
    fn default() -> Self {
        Self {
            tab: DisplayTab::Settings,
            sort_field: SortField::Published,
            sort_direction: SortDirection::Desc,
            timezone: TimeZone::Utc,
            active_field: DisplayField::SortField,
        }
    }
}

impl DisplaySettings {
    pub(super) fn next_tab(&mut self) {
        self.tab = DisplayTab::Sources;
    }

    pub(super) fn previous_tab(&mut self) {
        self.tab = DisplayTab::Settings;
    }
    pub(super) fn next_field(&mut self) {
        self.active_field = self.active_field.next();
    }

    pub(super) fn previous_field(&mut self) {
        self.active_field = self.active_field.previous();
    }

    pub(super) fn next_value(&mut self) {
        match self.active_field {
            DisplayField::SortField => self.sort_field = self.sort_field.next(),
            DisplayField::SortDirection => self.sort_direction = self.sort_direction.next(),
            DisplayField::TimeZone => self.timezone = self.timezone.next(),
        }
    }

    pub(super) fn previous_value(&mut self) {
        match self.active_field {
            DisplayField::SortField => self.sort_field = self.sort_field.previous(),
            DisplayField::SortDirection => self.sort_direction = self.sort_direction.previous(),
            DisplayField::TimeZone => self.timezone = self.timezone.previous(),
        }
    }

    pub(super) fn sort_order(&self) -> CveSummarySortOrder {
        match (self.sort_field, self.sort_direction) {
            (SortField::Published, SortDirection::Asc) => CveSummarySortOrder::PublishedAsc,
            (SortField::Published, SortDirection::Desc) => CveSummarySortOrder::PublishedDesc,
            (SortField::Updated, SortDirection::Asc) => CveSummarySortOrder::UpdatedAsc,
            (SortField::Updated, SortDirection::Desc) => CveSummarySortOrder::UpdatedDesc,
            (SortField::CveId, SortDirection::Asc) => CveSummarySortOrder::CveIdAsc,
            (SortField::CveId, SortDirection::Desc) => CveSummarySortOrder::CveIdDesc,
            (SortField::RelationRank, SortDirection::Asc) => CveSummarySortOrder::RelationRankAsc,
            (SortField::RelationRank, SortDirection::Desc) => CveSummarySortOrder::RelationRankDesc,
            (SortField::Score, SortDirection::Asc) => CveSummarySortOrder::ScoreAsc,
            (SortField::Score, SortDirection::Desc) => CveSummarySortOrder::ScoreDesc,
        }
    }
}

impl DisplayField {
    fn next(self) -> Self {
        match self {
            Self::SortField => Self::SortDirection,
            Self::SortDirection => Self::TimeZone,
            Self::TimeZone => Self::SortField,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::SortField => Self::TimeZone,
            Self::SortDirection => Self::SortField,
            Self::TimeZone => Self::SortDirection,
        }
    }
}

impl SortField {
    fn next(self) -> Self {
        match self {
            Self::Published => Self::Updated,
            Self::Updated => Self::CveId,
            Self::CveId => Self::RelationRank,
            Self::RelationRank => Self::Score,
            Self::Score => Self::Published,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::Published => Self::Score,
            Self::Updated => Self::Published,
            Self::CveId => Self::Updated,
            Self::RelationRank => Self::CveId,
            Self::Score => Self::RelationRank,
        }
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Updated => "updated",
            Self::CveId => "a-z",
            Self::RelationRank => "relation rank",
            Self::Score => "score",
        }
    }
}

impl SortDirection {
    fn next(self) -> Self {
        match self {
            Self::Asc => Self::Desc,
            Self::Desc => Self::Asc,
        }
    }

    fn previous(self) -> Self {
        self.next()
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Asc => "asc",
            Self::Desc => "desc",
        }
    }
}

impl TimeZone {
    fn next(self) -> Self {
        match self {
            Self::Utc => Self::Jst,
            Self::Jst => Self::Pst,
            Self::Pst => Self::Utc,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::Utc => Self::Pst,
            Self::Jst => Self::Utc,
            Self::Pst => Self::Jst,
        }
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Utc => "UTC",
            Self::Jst => "JST",
            Self::Pst => "PST",
        }
    }
}
