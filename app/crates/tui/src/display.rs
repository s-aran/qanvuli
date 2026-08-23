use qanvuli_core::database::CveSummarySortOrder;

#[derive(Clone, Debug)]
pub(super) struct DisplaySettings {
    pub(super) sort_field: SortField,
    pub(super) sort_direction: SortDirection,
    pub(super) timezone: TimeZone,
    pub(super) kev_only: bool,
    pub(super) active_field: DisplayField,
    pub(super) source_focus: bool,
    pub(super) scroll: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DisplayField {
    SortField,
    SortDirection,
    TimeZone,
    KevOnly,
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
            sort_field: SortField::Published,
            sort_direction: SortDirection::Desc,
            timezone: TimeZone::Utc,
            kev_only: false,
            active_field: DisplayField::SortField,
            source_focus: false,
            scroll: 0,
        }
    }
}

impl DisplaySettings {
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
            DisplayField::KevOnly => self.kev_only = !self.kev_only,
        }
    }

    pub(super) fn previous_value(&mut self) {
        match self.active_field {
            DisplayField::SortField => self.sort_field = self.sort_field.previous(),
            DisplayField::SortDirection => self.sort_direction = self.sort_direction.previous(),
            DisplayField::TimeZone => self.timezone = self.timezone.previous(),
            DisplayField::KevOnly => self.kev_only = !self.kev_only,
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
            Self::TimeZone => Self::KevOnly,
            Self::KevOnly => Self::SortField,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::SortField => Self::KevOnly,
            Self::SortDirection => Self::SortField,
            Self::TimeZone => Self::SortDirection,
            Self::KevOnly => Self::TimeZone,
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
            Self::CveId => "source / identifier",
            Self::RelationRank => "per-source rank",
            Self::Score => "CVSS score",
        }
    }

    pub(super) fn hint(self) -> Option<&'static str> {
        match self {
            Self::CveId => Some("CVE and OSV are grouped, then identifiers are sorted."),
            Self::RelationRank => Some("Ranks are compared within each data source."),
            Self::Score => Some("OSV has no CVSS score and is listed after CVE."),
            Self::Published | Self::Updated => None,
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
