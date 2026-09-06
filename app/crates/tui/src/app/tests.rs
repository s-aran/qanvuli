use super::*;

#[tokio::test]
async fn metadata_completion_is_tracked_until_its_result_is_polled() {
    let mut app = App::new(String::new(), 30);
    app.tasks.metadata_capec = Some(PendingMetadataCapec {
        handle: tokio::spawn(async { Ok(Vec::new()) }),
    });
    assert!(app.has_background_task());
    while !app
        .tasks
        .metadata_capec
        .as_ref()
        .unwrap()
        .handle
        .is_finished()
    {
        tokio::task::yield_now().await;
    }
    // Rendering must still observe the final transition even though the task
    // itself has completed and polling will remove its handle.
    assert!(app.has_background_task());
    app.poll_metadata_capec().await;
    assert!(!app.has_background_task());
}

#[tokio::test]
async fn empty_enter_starts_a_sorted_cve_browse_search() {
    let database = CveDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize_schema().await.unwrap();
    let mut app = App::new(String::new(), 25);

    app.start_search(database);

    match &app.main.searched_request {
        SearchRequest::Advanced {
            options,
            include_cve,
            include_osv,
            ..
        } => {
            assert_eq!(options.sort_order, CveSummarySortOrder::PublishedDesc);
            assert!(options.query.is_none());
            assert!(*include_cve);
            assert!(!include_osv);
        }
        SearchRequest::Query { .. } => panic!("empty Enter must browse CVEs"),
    }
    app.abort_search();
}

#[tokio::test]
async fn search_modes_and_display_apply_preserve_the_selected_sort() {
    let database = CveDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize_schema().await.unwrap();
    let mut app = App::new("CVE-2099".to_owned(), 25);
    app.main.display.sort_field = crate::display::SortField::Updated;
    app.main.display.sort_direction = crate::display::SortDirection::Asc;

    app.start_search(database.clone());
    match &app.main.searched_request {
        SearchRequest::Query {
            term, sort_order, ..
        } => {
            assert_eq!(term, &SearchTerm::CvePrefix("CVE-2099".to_owned()));
            assert_eq!(*sort_order, CveSummarySortOrder::UpdatedAsc);
        }
        SearchRequest::Advanced { .. } => panic!("CVE prefix lost its typed search term"),
    }

    app.main.display.sort_field = crate::display::SortField::Score;
    app.main.display.sort_direction = crate::display::SortDirection::Desc;
    app.apply_display_settings(Some(database.clone()));
    match &app.main.searched_request {
        SearchRequest::Query {
            term, sort_order, ..
        } => {
            assert_eq!(term, &SearchTerm::CvePrefix("CVE-2099".to_owned()));
            assert_eq!(*sort_order, CveSummarySortOrder::ScoreDesc);
        }
        SearchRequest::Advanced { .. } => {
            panic!("display apply must preserve the typed search request")
        }
    }

    app.main.query = "GHSA-2099-example".to_owned();
    app.main.display.sort_field = crate::display::SortField::RelationRank;
    app.main.display.sort_direction = crate::display::SortDirection::Desc;
    app.start_search(database);
    match &app.main.searched_request {
        SearchRequest::Query {
            term, sort_order, ..
        } => {
            assert_eq!(
                term,
                &SearchTerm::Identifier("GHSA-2099-example".to_owned())
            );
            assert_eq!(*sort_order, CveSummarySortOrder::RelationRankDesc);
        }
        SearchRequest::Advanced { .. } => panic!("identifier searches must retain graph rank"),
    }
    app.abort_search();
}

#[tokio::test]
async fn hyphenated_product_input_stays_in_product_mode() {
    let database = CveDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize_schema().await.unwrap();
    let mut app = App::new(String::new(), 25);
    app.next_search_mode();
    assert_eq!(app.main.search_mode, SearchMode::Product);

    for ch in "example-product".chars() {
        app.push_query(ch);
    }
    assert_eq!(app.main.search_mode, SearchMode::Product);

    app.start_search(database);
    match &app.main.searched_request {
        SearchRequest::Query { term, .. } => {
            assert_eq!(term, &SearchTerm::Product("example-product".to_owned()));
        }
        SearchRequest::Advanced { .. } => panic!("main search lost its typed product term"),
    }
    app.abort_search();
}

#[test]
fn explicit_and_inferred_search_modes_are_distinct() {
    let mut inferred = App::new(String::new(), 25);
    for ch in "GHSA-2099-example".chars() {
        inferred.push_query(ch);
    }
    assert_eq!(inferred.main.search_mode, SearchMode::Identifier);
    while !inferred.main.query.is_empty() {
        inferred.backspace_query();
    }
    assert_eq!(inferred.main.search_mode, SearchMode::FreeText);

    let mut explicit = App::new(String::new(), 25);
    for _ in 0..6 {
        explicit.next_search_mode();
    }
    assert_eq!(explicit.main.search_mode, SearchMode::FreeText);
    for ch in "GHSA-2099-example".chars() {
        explicit.push_query(ch);
    }
    assert_eq!(explicit.main.search_mode, SearchMode::FreeText);
}

#[test]
fn popup_cancel_restores_edited_settings_and_filters() {
    let mut app = App::new("before".to_owned(), 25);

    app.open_advanced_search(None);
    app.main.advanced.query = "after".to_owned();
    app.main.advanced.product = "changed-product".to_owned();
    app.sync_main_from_advanced();
    app.cancel_advanced_search();
    assert_eq!(app.main.query, "before");
    assert!(app.main.advanced.product.is_empty());

    let original_sort = app.main.display.sort_field;
    app.open_display_settings();
    app.main.display.sort_field = crate::display::SortField::Score;
    app.main.advanced.source_cve = false;
    app.cancel_display_settings();
    assert_eq!(app.main.display.sort_field, original_sort);
    assert!(app.main.advanced.source_cve);

    app.capec.status_filter = "Stable".to_owned();
    app.open_capec_filter();
    app.capec.status_filter = "Deprecated".to_owned();
    app.cancel_capec_filter();
    assert_eq!(app.capec.status_filter, "Stable");

    app.cwe.capec_filter = "100".to_owned();
    app.open_cwe_status_popup();
    app.cwe.capec_filter = "200".to_owned();
    app.cwe.status_filter = [false; CWE_STATUS_COUNT];
    app.cancel_cwe_status_popup();
    assert_eq!(app.cwe.capec_filter, "100");
    assert_eq!(app.cwe.status_filter, default_cwe_status_filter());
}

#[test]
fn maintenance_requires_confirmation_before_it_can_start() {
    let mut app = App::new(String::new(), 25);
    app.open_maintenance();

    assert!(!app.overlay.maintenance_confirming);
    app.confirm_maintenance_choice();
    assert!(app.overlay.maintenance_confirming);
    app.cancel_maintenance_confirmation();
    assert!(!app.overlay.maintenance_confirming);

    app.overlay.maintenance_choice = MaintenanceChoice::Cancel;
    app.confirm_maintenance_choice();
    assert!(!app.overlay.show_maintenance);
}

#[tokio::test]
async fn mixed_source_sort_pages_only_append_to_the_loaded_order() {
    let database = CveDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize_schema().await.unwrap();
    database
            .import_cve_raw_jsons(vec![
                r#"{"cveMetadata":{"cveId":"CVE-2099-300","state":"PUBLISHED","datePublished":"2099-03-01T00:00:00Z","dateUpdated":"2099-03-01T00:00:00Z"},"containers":{"cna":{"title":"timelineproof newest"}}}"#.to_owned(),
                r#"{"cveMetadata":{"cveId":"CVE-2099-100","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"timelineproof older"}}}"#.to_owned(),
            ])
            .await
            .unwrap();
    database
            .import_osv_records(vec![
                qanvuli_core::database::OsvRawRecord {
                    source_path: None,
                    raw_json: r#"{"schema_version":"1.7.5","id":"GHSA-2099-middle","published":"2099-02-01T00:00:00Z","modified":"2099-04-01T00:00:00Z","summary":"timelineproof middle","affected":[]}"#.to_owned(),
                },
                qanvuli_core::database::OsvRawRecord {
                    source_path: None,
                    raw_json: r#"{"schema_version":"1.7.5","id":"ALSA-2098-oldest","published":"2098-12-01T00:00:00Z","modified":"2099-02-01T00:00:00Z","summary":"timelineproof oldest","affected":[]}"#.to_owned(),
                },
            ])
            .await
            .unwrap();
    let request = SearchRequest::Query {
        term: SearchTerm::FreeText("timelineproof".to_owned()),
        state_scope: CveStateScope::PublishedOnly,
        kev_only: false,
        sort_order: CveSummarySortOrder::PublishedDesc,
    };
    let mut app = App::new("test".to_owned(), 25);
    app.main.searched_request = request.clone();
    let expected = [
        "CVE-2099-300",
        "GHSA-2099-middle",
        "CVE-2099-100",
        "ALSA-2098-oldest",
    ];
    for offset in 0..expected.len() {
        let kind = if offset == 0 {
            SearchKind::Replace
        } else {
            SearchKind::Append {
                select_offset: app.candidate_count(),
            }
        };
        app.start_pending_search(
            database.clone(),
            request.clone(),
            1,
            app.main.search_offset,
            kind,
            "pagination test failed",
        );
        for _ in 0..100_000 {
            app.poll_search().await.unwrap();
            if !app.searching() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(!app.searching(), "search task did not finish");
        assert_eq!(app.main.search_offset, offset as u64 + 1);
        assert_eq!(app.main.exhausted, offset + 1 == expected.len());

        let loaded = app
            .main
            .candidates
            .iter()
            .map(|candidate| match candidate {
                SearchCandidate::Cve(cve) => cve.summary.cve_id.as_str(),
                SearchCandidate::Osv(osv) => osv.osv_id.as_str(),
            })
            .collect::<Vec<_>>();
        assert_eq!(loaded, expected[..=offset]);
    }

    app.select_candidate(1);
    assert_eq!(app.selected_osv().unwrap().osv_id, "GHSA-2099-middle");
    app.select_candidate(2);
    assert_eq!(app.selected().unwrap().summary.cve_id, "CVE-2099-100");

    for (sort_order, expected) in [
        (
            CveSummarySortOrder::UpdatedDesc,
            [
                "GHSA-2099-middle",
                "CVE-2099-300",
                "ALSA-2098-oldest",
                "CVE-2099-100",
            ],
        ),
        (
            CveSummarySortOrder::CveIdAsc,
            [
                "CVE-2099-100",
                "CVE-2099-300",
                "ALSA-2098-oldest",
                "GHSA-2099-middle",
            ],
        ),
        (
            CveSummarySortOrder::CveIdDesc,
            [
                "GHSA-2099-middle",
                "ALSA-2098-oldest",
                "CVE-2099-300",
                "CVE-2099-100",
            ],
        ),
    ] {
        let request = SearchRequest::Query {
            term: SearchTerm::FreeText("timelineproof".to_owned()),
            state_scope: CveStateScope::PublishedOnly,
            kev_only: false,
            sort_order,
        };
        let mut loaded = Vec::new();
        for offset in 0..expected.len() {
            let result = run_search_request(database.clone(), request.clone(), 1, offset as u64)
                .await
                .unwrap();
            assert_eq!(result.candidates.len(), 1);
            loaded.extend(
                result
                    .candidates
                    .into_iter()
                    .map(|candidate| match candidate {
                        SearchCandidate::Cve(cve) => cve.summary.cve_id,
                        SearchCandidate::Osv(osv) => osv.osv_id,
                    }),
            );
            assert_eq!(
                loaded.iter().map(String::as_str).collect::<Vec<_>>(),
                expected[..=offset],
                "unexpected {sort_order:?} prefix"
            );
        }
    }
}

#[test]
fn candidate_and_tab_changes_reset_scroll_and_use_item_height_for_pages() {
    let mut app = App::new(String::new(), 25);
    app.main.candidates = vec![
        SearchCandidate::Osv(test_osv("OSV-1")),
        SearchCandidate::Osv(test_osv("OSV-2")),
    ];
    app.main.detail_scroll = 8;
    app.main.metadata_scroll = 9;

    app.select_candidate(1);
    assert_eq!(app.main.detail_scroll, 0);
    assert_eq!(app.main.metadata_scroll, 0);

    app.main.detail_scroll = 4;
    app.main.metadata_scroll = 5;
    app.next_right_tab();
    assert_eq!(app.main.detail_scroll, 0);
    assert_eq!(app.main.metadata_scroll, 0);

    app.main.left_page_size = 20;
    assert_eq!(app.left_step(PageAmount::Full), 10);
    assert_eq!(app.left_step(PageAmount::Half), 5);
}

fn test_osv(id: &str) -> OsvSummary {
    OsvSummary {
        osv_id: id.to_owned(),
        schema_version: None,
        published_at: None,
        modified_at: None,
        withdrawn_at: None,
        summary: None,
        details: None,
        package_summary: None,
    }
}

#[test]
fn capec_tree_projects_each_parent_path_and_stops_cycles() {
    let entry = |id, parents| CapecEntry {
        id,
        name: format!("CAPEC-{id}"),
        description: String::new(),
        extended_description: None,
        status: "Stable".to_owned(),
        abstraction: "Standard".to_owned(),
        parent_ids: parents,
        cwe_ids: Vec::new(),
        category_ids: Vec::new(),
        view_ids: Vec::new(),
        child_count: 0,
    };
    let rows = project_capec_tree(vec![
        entry(1, Vec::new()),
        entry(2, Vec::new()),
        entry(3, vec![1, 2]),
    ]);
    assert_eq!(rows.entries.iter().filter(|row| row.id == 3).count(), 2);
    assert!(rows.paths.contains(&vec![1, 3]));
    assert!(rows.paths.contains(&vec![2, 3]));
    assert_eq!(rows.prefixes, ["", "└─ ", "", "└─ "]);

    let nested = project_capec_tree(vec![
        entry(10, Vec::new()),
        entry(20, vec![10]),
        entry(30, vec![10]),
        entry(40, vec![20]),
    ]);
    assert_eq!(nested.prefixes, ["", "├─ ", "│  └─ ", "└─ "]);
    let filtered = filter_capec_tree(nested, &HashSet::from([40]));
    assert_eq!(filtered.paths, [vec![10], vec![10, 20], vec![10, 20, 40]]);
    assert_eq!(filtered.prefixes, ["", "└─ ", "   └─ "]);

    let cyclic = project_capec_tree(vec![entry(4, vec![5]), entry(5, vec![4])]);
    assert_eq!(cyclic.paths, [vec![4], vec![4, 5], vec![5], vec![5, 4]]);
}

#[test]
fn switches_between_cwe_and_capec_catalogs() {
    let mut app = App::new(String::new(), 25);
    app.toggle_cwe_list_mode(None);
    assert_eq!(app.raw.view_mode, ViewMode::CweList);
    app.toggle_capec_list_mode(None);
    assert_eq!(app.raw.view_mode, ViewMode::CapecList);
    app.toggle_capec_list_mode(None);
    assert_eq!(app.raw.view_mode, ViewMode::Normal);
}

#[test]
fn capec_typing_filters_cached_catalog_and_keeps_ancestors() {
    let entry = |id, name: &str, parents| CapecEntry {
        id,
        name: name.to_owned(),
        description: String::new(),
        extended_description: None,
        status: "Stable".to_owned(),
        abstraction: "Standard".to_owned(),
        parent_ids: parents,
        cwe_ids: Vec::new(),
        category_ids: Vec::new(),
        view_ids: Vec::new(),
        child_count: 0,
    };
    let mut app = App::new(String::new(), 25);
    app.capec.catalog = vec![
        entry(1, "Root", Vec::new()),
        entry(2, "Target child", vec![1]),
        entry(3, "Other child", vec![1]),
    ];

    for ch in "target".chars() {
        app.push_capec_query(ch, None);
    }

    assert!(app.tasks.capec.is_none());
    assert_eq!(app.capec.tree_paths, [vec![1], vec![1, 2]]);
    assert_eq!(app.capec.tree_prefixes, ["", "└─ "]);
}
