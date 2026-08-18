use super::*;

pub(crate) struct MainState {
    pub(crate) query: String,
    pub(crate) search_mode: SearchMode,
    pub(crate) search_mode_explicit: bool,
    pub(crate) state_scope: CveStateScope,
    pub(crate) advanced: AdvancedForm,
    pub(crate) display: DisplaySettings,
    pub(crate) limit: u64,
    pub(crate) search_offset: u64,
    pub(crate) search_continuation: SearchContinuation,
    pub(crate) candidates: Vec<SearchCandidate>,
    pub(crate) linked_osv: HashMap<String, Vec<OsvSummary>>,
    pub(crate) total_results: Option<u64>,
    pub(crate) list_state: ListState,
    pub(crate) focus: PaneFocus,
    pub(crate) right_tab: RightPaneTab,
    pub(crate) detail_scroll: u16,
    pub(crate) metadata_scroll: u16,
    pub(crate) enrichment: HashMap<String, EnrichedCveSummary>,
    pub(crate) metadata_capec_ids: HashMap<String, Vec<i32>>,
    pub(crate) searched_request: SearchRequest,
    pub(crate) exhausted: bool,
    pub(crate) left_page_size: usize,
    pub(crate) right_page_size: usize,
    pub(crate) metadata_page_size: usize,
    pub(crate) detail_content_width: usize,
    pub(crate) metadata_content_width: usize,
    pub(crate) db_as_of: Option<String>,
}

impl MainState {
    pub(crate) fn new(query: String, limit: u64, search_mode: SearchMode) -> Self {
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        Self {
            query,
            search_mode,
            search_mode_explicit: false,
            state_scope: CveStateScope::PublishedOnly,
            advanced: AdvancedForm::default(),
            display: DisplaySettings::default(),
            limit,
            search_offset: 0,
            search_continuation: SearchContinuation::default(),
            candidates: Vec::new(),
            linked_osv: HashMap::new(),
            total_results: None,
            list_state,
            focus: PaneFocus::Left,
            right_tab: RightPaneTab::Cve,
            detail_scroll: 0,
            metadata_scroll: 0,
            enrichment: HashMap::new(),
            metadata_capec_ids: HashMap::new(),
            searched_request: SearchRequest::Query {
                term: SearchTerm::new(search_mode, String::new()),
                state_scope: CveStateScope::PublishedOnly,
                kev_only: false,
                sort_order: CveSummarySortOrder::PublishedDesc,
            },
            exhausted: false,
            left_page_size: 10,
            right_page_size: 10,
            metadata_page_size: 10,
            detail_content_width: 80,
            metadata_content_width: 80,
            db_as_of: None,
        }
    }
}

pub(crate) struct RawState {
    pub(crate) view_mode: ViewMode,
    pub(crate) json: Option<String>,
    pub(crate) scroll: u16,
}

impl Default for RawState {
    fn default() -> Self {
        Self {
            view_mode: ViewMode::Normal,
            json: None,
            scroll: 0,
        }
    }
}

pub(crate) struct CweState {
    pub(crate) query: String,
    pub(crate) results: Vec<CweEntry>,
    pub(crate) scroll: u16,
    pub(crate) selected: usize,
    pub(crate) detail_scroll: u16,
    pub(crate) relation_return_id: Option<i32>,
    pub(crate) status_filter: [bool; CWE_STATUS_COUNT],
    pub(crate) status_cursor: usize,
    pub(crate) show_status: bool,
    pub(crate) capec_filter: String,
}

impl Default for CweState {
    fn default() -> Self {
        Self {
            query: String::new(),
            results: Vec::new(),
            scroll: 0,
            selected: 0,
            detail_scroll: 0,
            relation_return_id: None,
            status_filter: default_cwe_status_filter(),
            status_cursor: 0,
            show_status: false,
            capec_filter: String::new(),
        }
    }
}

#[derive(Default)]
pub(crate) struct CapecState {
    pub(crate) query: String,
    pub(crate) catalog: Vec<CapecEntry>,
    pub(crate) results: Vec<CapecEntry>,
    pub(crate) tree_paths: Vec<Vec<i32>>,
    pub(crate) tree_prefixes: Vec<String>,
    pub(crate) scroll: u16,
    pub(crate) selected: usize,
    pub(crate) detail_scroll: u16,
    pub(crate) relation_return_path: Option<Vec<i32>>,
    pub(crate) status_filter: String,
    pub(crate) type_filter: String,
    pub(crate) cwe_filter: String,
    pub(crate) show_filter: bool,
    pub(crate) filter_field: usize,
    pub(crate) show_taxonomy: bool,
    pub(crate) taxonomy_tab: usize,
    pub(crate) taxonomy_section: usize,
    pub(crate) taxonomy_scroll: u16,
    pub(crate) taxonomy_selected: usize,
    pub(crate) taxonomy: Option<CapecDetail>,
}

pub(crate) struct OverlayState {
    pub(crate) detail_search_query: String,
    pub(crate) detail_search_input: bool,
    pub(crate) detail_search_error: Option<String>,
    pub(crate) show_help: bool,
    pub(crate) show_advanced: bool,
    pub(crate) show_display: bool,
    pub(crate) show_timeout_prompt: bool,
    pub(crate) show_maintenance: bool,
    pub(crate) timeout_choice: TimeoutChoice,
    pub(crate) maintenance_choice: MaintenanceChoice,
    pub(crate) maintenance_keep_downloads: bool,
    pub(crate) status_message: Option<String>,
    pub(crate) maintenance_progress: Option<MaintenanceProgress>,
    pub(crate) maintenance_confirming: bool,
    pub(crate) snapshots: PopupSnapshots,
}

impl Default for OverlayState {
    fn default() -> Self {
        Self {
            detail_search_query: String::new(),
            detail_search_input: false,
            detail_search_error: None,
            show_help: false,
            show_advanced: false,
            show_display: false,
            show_timeout_prompt: false,
            show_maintenance: false,
            timeout_choice: TimeoutChoice::Continue,
            maintenance_choice: MaintenanceChoice::Update,
            maintenance_keep_downloads: false,
            status_message: None,
            maintenance_progress: None,
            maintenance_confirming: false,
            snapshots: PopupSnapshots::default(),
        }
    }
}

#[derive(Default)]
pub(crate) struct Tasks {
    pub(crate) search: Option<PendingSearch>,
    pub(crate) count: Option<JoinHandle<Result<u64, String>>>,
    pub(crate) raw_json: Option<JoinHandle<Result<String, String>>>,
    pub(crate) enrichment: Option<PendingEnrichment>,
    pub(crate) metadata_capec: Option<PendingMetadataCapec>,
    pub(crate) cwe: Option<JoinHandle<Result<Vec<CweEntry>, String>>>,
    pub(crate) capec: Option<JoinHandle<Result<Vec<CapecEntry>, String>>>,
    pub(crate) capec_detail: Option<JoinHandle<Result<Option<CapecDetail>, String>>>,
    pub(crate) scope: Option<JoinHandle<Result<Vec<String>, String>>>,
    pub(crate) maintenance: Option<PendingMaintenance>,
    pub(crate) search_started_at: Option<Instant>,
    pub(crate) search_timeout_at: Option<Instant>,
}

#[derive(Default)]
pub(crate) struct PopupSnapshots {
    pub(crate) advanced: Option<AdvancedForm>,
    pub(crate) display: Option<(DisplaySettings, AdvancedForm)>,
    pub(crate) cwe_filter: Option<([bool; CWE_STATUS_COUNT], String)>,
    pub(crate) capec_filter: Option<(String, String, String)>,
}
