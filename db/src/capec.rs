use std::collections::{HashMap, HashSet};

use qanvuli_models::capec::{
    AttackPatternCatalog,
    common::{ContentHistory, Reference},
    enumeration::RelationNature,
};
use serde::Serialize;
use sqlx::{Connection, QueryBuilder, Row, Sqlite, SqliteConnection};

use crate::SqlxDatabase;

#[derive(Clone, Debug, Default)]
pub struct CapecSearchFilters {
    pub query: Option<String>,
    pub statuses: Vec<String>,
    pub types: Vec<String>,
    pub cwe_id: Option<i32>,
    pub limit: u64,
    pub offset: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct CapecEntry {
    pub id: i32,
    pub name: String,
    pub description: String,
    pub extended_description: Option<String>,
    pub status: String,
    pub abstraction: String,
    pub parent_ids: Vec<i32>,
    pub cwe_ids: Vec<i32>,
    pub category_ids: Vec<i32>,
    pub view_ids: Vec<i32>,
    pub child_count: usize,
}

#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
pub struct CapecCategory {
    pub id: i32,
    pub name: String,
    pub status: String,
    pub summary: String,
}

#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
pub struct CapecView {
    pub id: i32,
    pub name: String,
    pub view_type: String,
    pub status: String,
    pub objective: String,
    pub filter: Option<String>,
}

#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
pub struct CapecReference {
    pub reference_id: String,
    pub section: Option<String>,
    pub authors: String,
    pub title: String,
    pub edition: Option<String>,
    pub publication: Option<String>,
    pub publication_year: Option<String>,
    pub publisher: Option<String>,
    pub url: Option<String>,
}

#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
pub struct CapecHistory {
    pub event_type: String,
    pub event_date: String,
    pub actor_name: Option<String>,
    pub organization: Option<String>,
    pub comment: Option<String>,
    pub previous_name: Option<String>,
}

#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
pub struct CapecNote {
    pub note_type: String,
    pub note_text: String,
}

#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
pub struct CapecTaxonomyMapping {
    pub taxonomy: String,
    pub entry_id: Option<String>,
    pub entry_name: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CapecDetail {
    #[serde(flatten)]
    pub entry: CapecEntry,
    pub categories: Vec<CapecCategoryDetail>,
    pub views: Vec<CapecViewDetail>,
    pub references: Vec<CapecReference>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CapecCategoryDetail {
    #[serde(flatten)]
    pub category: CapecCategory,
    pub member_ids: Vec<i32>,
    pub references: Vec<CapecReference>,
    pub history: Vec<CapecHistory>,
    pub notes: Vec<CapecNote>,
    pub taxonomy_mappings: Vec<CapecTaxonomyMapping>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CapecViewDetail {
    #[serde(flatten)]
    pub view: CapecView,
    pub category_ids: Vec<i32>,
    pub capec_ids: Vec<i32>,
    pub references: Vec<CapecReference>,
    pub history: Vec<CapecHistory>,
    pub notes: Vec<CapecNote>,
}

type HistoryRow = (
    i64,
    i64,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);
type ExternalReferenceRow = (
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);
type TaxonomyRow = (i64, i64, String, Option<String>, Option<String>);

#[derive(Default)]
struct Rows {
    patterns: Vec<(i64, String, String, Option<String>, String, String)>,
    parents: Vec<(i64, i64, i64)>,
    weaknesses: Vec<(i64, i64, i64)>,
    categories: Vec<(i64, String, String, String)>,
    category_members: Vec<(i64, i64, i64)>,
    views: Vec<(i64, String, String, String, String, Option<String>)>,
    view_categories: Vec<(i64, i64, i64)>,
    view_patterns: Vec<(i64, i64, i64)>,
    references: Vec<ExternalReferenceRow>,
    authors: Vec<(String, i64, String)>,
    pattern_references: Vec<(i64, String, Option<String>, i64)>,
    category_references: Vec<(i64, String, Option<String>, i64)>,
    view_references: Vec<(i64, String, Option<String>, i64)>,
    category_history: Vec<HistoryRow>,
    view_history: Vec<HistoryRow>,
    category_notes: Vec<(i64, i64, String, String)>,
    view_notes: Vec<(i64, i64, String, String)>,
    taxonomy: Vec<TaxonomyRow>,
}

impl Rows {
    fn from_catalog(catalog: &AttackPatternCatalog) -> Result<Self, sqlx::Error> {
        let mut rows = Self::default();
        let pattern_ids = catalog
            .attack_patterns
            .as_ref()
            .into_iter()
            .flat_map(|group| &group.items)
            .map(|pattern| pattern.id)
            .collect::<HashSet<_>>();
        let category_ids = catalog
            .categories
            .as_ref()
            .into_iter()
            .flat_map(|group| &group.items)
            .map(|category| category.id)
            .collect::<HashSet<_>>();
        if !pattern_ids.is_disjoint(&category_ids) {
            return Err(protocol("CAPEC pattern and category IDs overlap"));
        }

        if let Some(patterns) = &catalog.attack_patterns {
            for pattern in &patterns.items {
                rows.patterns.push((
                    pattern.id,
                    pattern.name.clone(),
                    pattern.description.plain_text(),
                    pattern
                        .extended_description
                        .as_ref()
                        .map(|text| text.plain_text()),
                    pattern.status.to_string(),
                    pattern.abstraction.to_string(),
                ));
                if let Some(relations) = &pattern.related_attack_patterns {
                    for (order, relation) in relations.items.iter().enumerate() {
                        if relation.nature == RelationNature::ChildOf {
                            if !pattern_ids.contains(&relation.capec_id) {
                                return Err(protocol(format!(
                                    "CAPEC-{} has unknown parent CAPEC-{}",
                                    pattern.id, relation.capec_id
                                )));
                            }
                            rows.parents
                                .push((pattern.id, relation.capec_id, order as i64));
                        }
                    }
                }
                if let Some(weaknesses) = &pattern.related_weaknesses {
                    rows.weaknesses.extend(
                        weaknesses
                            .items
                            .iter()
                            .enumerate()
                            .map(|(order, weakness)| (pattern.id, weakness.cwe_id, order as i64)),
                    );
                }
                push_references(
                    pattern.id,
                    pattern
                        .references
                        .as_ref()
                        .map(|refs| refs.items.as_slice()),
                    &mut rows.pattern_references,
                );
            }
        }

        if let Some(categories) = &catalog.categories {
            for category in &categories.items {
                rows.categories.push((
                    category.id,
                    category.name.clone(),
                    category.status.to_string(),
                    category.summary.plain_text(),
                ));
                if let Some(members) = &category.relationships {
                    for (order, member) in members.items.iter().enumerate() {
                        if !pattern_ids.contains(&member.capec_id) {
                            return Err(protocol(format!(
                                "CAPEC category {} has unknown member {}",
                                category.id, member.capec_id
                            )));
                        }
                        rows.category_members
                            .push((category.id, member.capec_id, order as i64));
                    }
                }
                push_references(
                    category.id,
                    category
                        .references
                        .as_ref()
                        .map(|refs| refs.items.as_slice()),
                    &mut rows.category_references,
                );
                push_history(
                    category.id,
                    category.content_history.as_ref(),
                    &mut rows.category_history,
                );
                if let Some(notes) = &category.notes {
                    rows.category_notes
                        .extend(notes.items.iter().enumerate().map(|(order, note)| {
                            (
                                category.id,
                                order as i64,
                                note.note_type.clone(),
                                note.plain_text(),
                            )
                        }));
                }
                if let Some(mappings) = &category.taxonomy_mappings {
                    rows.taxonomy.extend(mappings.items.iter().enumerate().map(
                        |(order, mapping)| {
                            (
                                category.id,
                                order as i64,
                                mapping.taxonomy.clone(),
                                mapping.entry_id.clone(),
                                mapping.entry_name.clone(),
                            )
                        },
                    ));
                }
            }
        }

        if let Some(views) = &catalog.views {
            for view in &views.items {
                rows.views.push((
                    view.id,
                    view.name.clone(),
                    view.view_type.to_string(),
                    view.status.to_string(),
                    view.objective.plain_text(),
                    view.filter.clone(),
                ));
                if let Some(members) = &view.members {
                    for (order, member) in members.items.iter().enumerate() {
                        match (
                            pattern_ids.contains(&member.capec_id),
                            category_ids.contains(&member.capec_id),
                        ) {
                            (true, false) => {
                                rows.view_patterns
                                    .push((view.id, member.capec_id, order as i64));
                            }
                            (false, true) => {
                                rows.view_categories
                                    .push((view.id, member.capec_id, order as i64));
                            }
                            _ => {
                                return Err(protocol(format!(
                                    "CAPEC view {} cannot resolve member {}",
                                    view.id, member.capec_id
                                )));
                            }
                        }
                    }
                }
                push_references(
                    view.id,
                    view.references.as_ref().map(|refs| refs.items.as_slice()),
                    &mut rows.view_references,
                );
                push_history(
                    view.id,
                    view.content_history.as_ref(),
                    &mut rows.view_history,
                );
                if let Some(notes) = &view.notes {
                    rows.view_notes
                        .extend(notes.items.iter().enumerate().map(|(order, note)| {
                            (
                                view.id,
                                order as i64,
                                note.note_type.clone(),
                                note.plain_text(),
                            )
                        }));
                }
            }
        }

        if let Some(references) = &catalog.external_references {
            for reference in &references.items {
                rows.references.push((
                    reference.reference_id.clone(),
                    reference.title.clone(),
                    reference.edition.clone(),
                    reference.publication.clone(),
                    reference.publication_year.clone(),
                    reference.publication_month.clone(),
                    reference.publication_day.clone(),
                    reference.publisher.clone(),
                    reference.url.clone(),
                    reference.url_date.clone(),
                ));
                rows.authors
                    .extend(reference.authors.iter().enumerate().map(|(order, author)| {
                        (reference.reference_id.clone(), order as i64, author.clone())
                    }));
            }
        }

        // The catalog may repeat the same semantic relation; normalized links keep its first order.
        dedup_by_key(&mut rows.parents, |row| (row.0, row.1));
        dedup_by_key(&mut rows.weaknesses, |row| (row.0, row.1));
        dedup_by_key(&mut rows.category_members, |row| (row.0, row.1));
        dedup_by_key(&mut rows.view_categories, |row| (row.0, row.1));
        dedup_by_key(&mut rows.view_patterns, |row| (row.0, row.1));
        dedup_by_key(&mut rows.pattern_references, |row| (row.0, row.1.clone()));
        dedup_by_key(&mut rows.category_references, |row| (row.0, row.1.clone()));
        dedup_by_key(&mut rows.view_references, |row| (row.0, row.1.clone()));

        let reference_ids = rows
            .references
            .iter()
            .map(|row| row.0.as_str())
            .collect::<HashSet<_>>();
        for reference_id in rows
            .pattern_references
            .iter()
            .map(|row| row.1.as_str())
            .chain(rows.category_references.iter().map(|row| row.1.as_str()))
            .chain(rows.view_references.iter().map(|row| row.1.as_str()))
        {
            if !reference_ids.contains(reference_id) {
                return Err(protocol(format!(
                    "CAPEC catalog references unknown {reference_id}"
                )));
            }
        }
        ensure_acyclic_parents(&rows.parents)?;
        Ok(rows)
    }
}

fn dedup_by_key<T, K>(rows: &mut Vec<T>, key: impl Fn(&T) -> K)
where
    K: Eq + std::hash::Hash,
{
    let mut seen = HashSet::new();
    rows.retain(|row| seen.insert(key(row)));
}

fn ensure_acyclic_parents(parents: &[(i64, i64, i64)]) -> Result<(), sqlx::Error> {
    let mut by_child = HashMap::<i64, Vec<i64>>::new();
    for (child, parent, _) in parents {
        by_child.entry(*child).or_default().push(*parent);
    }
    for start in by_child.keys() {
        let mut stack = vec![(*start, HashSet::new())];
        while let Some((current, mut path)) = stack.pop() {
            if !path.insert(current) {
                return Err(protocol(format!(
                    "CAPEC parent relation contains a cycle at CAPEC-{current}"
                )));
            }
            if let Some(next) = by_child.get(&current) {
                stack.extend(next.iter().map(|parent| (*parent, path.clone())));
            }
        }
    }
    Ok(())
}

macro_rules! insert_chunks {
    ($tx:expr, $sql:literal, $rows:expr, |$row:ident, $value:ident| $body:block) => {{
        for chunk in $rows.chunks(500) {
            let mut query = QueryBuilder::<Sqlite>::new($sql);
            query.push_values(chunk, |mut $row, $value| $body);
            query.build().execute(&mut **$tx).await?;
        }
    }};
}

impl SqlxDatabase {
    pub async fn replace_capec_catalog(
        &self,
        catalog: &AttackPatternCatalog,
    ) -> Result<usize, sqlx::Error> {
        let rows = Rows::from_catalog(catalog)?;
        let count = rows.patterns.len();
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let mut tx = connection.begin().await?;
                    sqlx::query("DELETE FROM capec_view").execute(&mut *tx).await?;
                    sqlx::query("DELETE FROM capec_category").execute(&mut *tx).await?;
                    sqlx::query("DELETE FROM capec").execute(&mut *tx).await?;
                    sqlx::query("DELETE FROM capec_external_reference").execute(&mut *tx).await?;

                    insert_chunks!(&mut tx, "INSERT INTO capec (id,name,description,extended_description,status,abstraction) ", rows.patterns, |row, value| {
                        row.push_bind(value.0).push_bind(&value.1).push_bind(&value.2).push_bind(&value.3).push_bind(&value.4).push_bind(&value.5);
                    });
                    insert_chunks!(&mut tx, "INSERT INTO capec_category (id,name,status,summary) ", rows.categories, |row, value| {
                        row.push_bind(value.0).push_bind(&value.1).push_bind(&value.2).push_bind(&value.3);
                    });
                    insert_chunks!(&mut tx, "INSERT INTO capec_view (id,name,view_type,status,objective,filter) ", rows.views, |row, value| {
                        row.push_bind(value.0).push_bind(&value.1).push_bind(&value.2).push_bind(&value.3).push_bind(&value.4).push_bind(&value.5);
                    });
                    insert_chunks!(&mut tx, "INSERT INTO capec_external_reference (reference_id,title,edition,publication,publication_year,publication_month,publication_day,publisher,url,url_date) ", rows.references, |row, value| {
                        row.push_bind(&value.0).push_bind(&value.1).push_bind(&value.2).push_bind(&value.3).push_bind(&value.4).push_bind(&value.5).push_bind(&value.6).push_bind(&value.7).push_bind(&value.8).push_bind(&value.9);
                    });
                    validate_cwe_ids(&mut tx, &rows.weaknesses).await?;

                    insert_chunks!(&mut tx, "INSERT INTO capec_parent (capec_id,parent_id,relation_order) ", rows.parents, |row, value| {
                        row.push_bind(value.0).push_bind(value.1).push_bind(value.2);
                    });
                    insert_chunks!(&mut tx, "INSERT INTO capec_cwe (capec_id,cwe_id,relation_order) ", rows.weaknesses, |row, value| {
                        row.push_bind(value.0).push_bind(value.1).push_bind(value.2);
                    });
                    insert_chunks!(&mut tx, "INSERT INTO capec_category_member (category_id,capec_id,member_order) ", rows.category_members, |row, value| {
                        row.push_bind(value.0).push_bind(value.1).push_bind(value.2);
                    });
                    insert_chunks!(&mut tx, "INSERT INTO capec_view_category (view_id,category_id,member_order) ", rows.view_categories, |row, value| {
                        row.push_bind(value.0).push_bind(value.1).push_bind(value.2);
                    });
                    insert_chunks!(&mut tx, "INSERT INTO capec_view_capec (view_id,capec_id,member_order) ", rows.view_patterns, |row, value| {
                        row.push_bind(value.0).push_bind(value.1).push_bind(value.2);
                    });
                    insert_chunks!(&mut tx, "INSERT INTO capec_external_reference_author (reference_id,author_order,author) ", rows.authors, |row, value| {
                        row.push_bind(&value.0).push_bind(value.1).push_bind(&value.2);
                    });
                    insert_chunks!(&mut tx, "INSERT INTO capec_reference (capec_id,reference_id,section,reference_order) ", rows.pattern_references, |row, value| {
                        row.push_bind(value.0).push_bind(&value.1).push_bind(&value.2).push_bind(value.3);
                    });
                    insert_chunks!(&mut tx, "INSERT INTO capec_category_reference (category_id,reference_id,section,reference_order) ", rows.category_references, |row, value| {
                        row.push_bind(value.0).push_bind(&value.1).push_bind(&value.2).push_bind(value.3);
                    });
                    insert_chunks!(&mut tx, "INSERT INTO capec_view_reference (view_id,reference_id,section,reference_order) ", rows.view_references, |row, value| {
                        row.push_bind(value.0).push_bind(&value.1).push_bind(&value.2).push_bind(value.3);
                    });
                    insert_chunks!(&mut tx, "INSERT INTO capec_category_history (category_id,event_order,event_type,event_date,actor_name,organization,comment,previous_name) ", rows.category_history, |row, value| {
                        row.push_bind(value.0).push_bind(value.1).push_bind(&value.2).push_bind(&value.3).push_bind(&value.4).push_bind(&value.5).push_bind(&value.6).push_bind(&value.7);
                    });
                    insert_chunks!(&mut tx, "INSERT INTO capec_view_history (view_id,event_order,event_type,event_date,actor_name,organization,comment,previous_name) ", rows.view_history, |row, value| {
                        row.push_bind(value.0).push_bind(value.1).push_bind(&value.2).push_bind(&value.3).push_bind(&value.4).push_bind(&value.5).push_bind(&value.6).push_bind(&value.7);
                    });
                    insert_chunks!(&mut tx, "INSERT INTO capec_category_note (category_id,note_order,note_type,note_text) ", rows.category_notes, |row, value| {
                        row.push_bind(value.0).push_bind(value.1).push_bind(&value.2).push_bind(&value.3);
                    });
                    insert_chunks!(&mut tx, "INSERT INTO capec_view_note (view_id,note_order,note_type,note_text) ", rows.view_notes, |row, value| {
                        row.push_bind(value.0).push_bind(value.1).push_bind(&value.2).push_bind(&value.3);
                    });
                    insert_chunks!(&mut tx, "INSERT INTO capec_category_taxonomy_mapping (category_id,mapping_order,taxonomy,entry_id,entry_name) ", rows.taxonomy, |row, value| {
                        row.push_bind(value.0).push_bind(value.1).push_bind(&value.2).push_bind(&value.3).push_bind(&value.4);
                    });
                    tx.commit().await?;
                    Ok(count)
                })
            })
            .await
    }

    pub async fn search_capec_entries(
        &self,
        filters: CapecSearchFilters,
    ) -> Result<Vec<CapecEntry>, sqlx::Error> {
        let query = filters.query.unwrap_or_default();
        let pattern = format!("%{}%", query.trim());
        let id = parse_id(&query, "CAPEC");
        let statuses = serde_json::to_string(&filters.statuses)
            .map_err(|error| protocol(error.to_string()))?;
        let types =
            serde_json::to_string(&filters.types).map_err(|error| protocol(error.to_string()))?;
        let limit = filters.limit.max(1);
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let rows = sqlx::query(
                        "SELECT id,name,description,extended_description,status,abstraction FROM capec
                         WHERE (?='' OR id=? OR name LIKE ? OR description LIKE ? OR COALESCE(extended_description,'') LIKE ?)
                           AND (json_array_length(?)=0 OR status IN (SELECT value FROM json_each(?)))
                           AND (json_array_length(?)=0 OR abstraction IN (SELECT value FROM json_each(?)))
                           AND (? IS NULL OR EXISTS(SELECT 1 FROM capec_cwe link WHERE link.capec_id=capec.id AND link.cwe_id=?))
                         ORDER BY id LIMIT ? OFFSET ?",
                    )
                    .bind(query.trim())
                    .bind(id)
                    .bind(&pattern)
                    .bind(&pattern)
                    .bind(&pattern)
                    .bind(&statuses)
                    .bind(&statuses)
                    .bind(&types)
                    .bind(&types)
                    .bind(filters.cwe_id)
                    .bind(filters.cwe_id)
                    .bind(limit as i64)
                    .bind(filters.offset as i64)
                    .fetch_all(&mut *connection)
                    .await?;
                    hydrate_entries(connection, rows).await
                })
            })
            .await
    }

    pub async fn capec_ids_for_cwes(
        &self,
        cwe_ids: &[i32],
    ) -> Result<HashMap<i32, Vec<i32>>, sqlx::Error> {
        if cwe_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let cwe_ids =
            serde_json::to_string(cwe_ids).map_err(|error| protocol(error.to_string()))?;
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let rows = sqlx::query_as::<_, (i32, i32)>(
                        "SELECT cwe_id,capec_id
                         FROM capec_cwe
                         WHERE cwe_id IN (SELECT value FROM json_each(?))
                         ORDER BY cwe_id,capec_id",
                    )
                    .bind(cwe_ids)
                    .fetch_all(connection)
                    .await?;
                    let mut ids = HashMap::<i32, Vec<i32>>::new();
                    for (cwe_id, capec_id) in rows {
                        ids.entry(cwe_id).or_default().push(capec_id);
                    }
                    Ok(ids)
                })
            })
            .await
    }

    pub async fn get_capec_detail(&self, id: i32) -> Result<Option<CapecDetail>, sqlx::Error> {
        let mut entries = self
            .search_capec_entries(CapecSearchFilters {
                query: Some(format!("CAPEC-{id}")),
                limit: 1,
                ..Default::default()
            })
            .await?;
        let Some(entry) = entries.pop() else {
            return Ok(None);
        };
        let category_ids = serde_json::to_string(&entry.category_ids)
            .map_err(|error| protocol(error.to_string()))?;
        let view_ids =
            serde_json::to_string(&entry.view_ids).map_err(|error| protocol(error.to_string()))?;
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let categories = category_details(connection, &category_ids).await?;
                    let views = view_details(connection, &view_ids).await?;
                    let references = references_for_capec(connection, id).await?;
                    Ok(Some(CapecDetail {
                        entry,
                        categories,
                        views,
                        references,
                    }))
                })
            })
            .await
    }

    pub async fn capec_category_history(&self, id: i32) -> Result<Vec<CapecHistory>, sqlx::Error> {
        self.writer
            .with_connection(|connection| Box::pin(async move {
                sqlx::query_as("SELECT event_type,event_date,actor_name,organization,comment,previous_name FROM capec_category_history WHERE category_id=? ORDER BY event_date DESC,event_order")
                    .bind(id).fetch_all(connection).await
            }))
            .await
    }

    pub async fn capec_view_history(&self, id: i32) -> Result<Vec<CapecHistory>, sqlx::Error> {
        self.writer
            .with_connection(|connection| Box::pin(async move {
                sqlx::query_as("SELECT event_type,event_date,actor_name,organization,comment,previous_name FROM capec_view_history WHERE view_id=? ORDER BY event_date DESC,event_order")
                    .bind(id).fetch_all(connection).await
            }))
            .await
    }
}

async fn category_details(
    connection: &mut SqliteConnection,
    ids: &str,
) -> Result<Vec<CapecCategoryDetail>, sqlx::Error> {
    let categories: Vec<CapecCategory> = sqlx::query_as(
        "SELECT id,name,status,summary FROM capec_category WHERE id IN (SELECT value FROM json_each(?)) ORDER BY id",
    )
    .bind(ids)
    .fetch_all(&mut *connection)
    .await?;
    let mut details = Vec::with_capacity(categories.len());
    for category in categories {
        let member_ids = sqlx::query_scalar(
            "SELECT capec_id FROM capec_category_member WHERE category_id=? ORDER BY member_order",
        )
        .bind(category.id)
        .fetch_all(&mut *connection)
        .await?;
        let references = references_for_category(connection, category.id).await?;
        let history = sqlx::query_as(
            "SELECT event_type,event_date,actor_name,organization,comment,previous_name FROM capec_category_history WHERE category_id=? ORDER BY event_order",
        )
        .bind(category.id)
        .fetch_all(&mut *connection)
        .await?;
        let notes = sqlx::query_as(
            "SELECT note_type,note_text FROM capec_category_note WHERE category_id=? ORDER BY note_order",
        )
        .bind(category.id)
        .fetch_all(&mut *connection)
        .await?;
        let taxonomy_mappings = sqlx::query_as(
            "SELECT taxonomy,entry_id,entry_name FROM capec_category_taxonomy_mapping WHERE category_id=? ORDER BY mapping_order",
        )
        .bind(category.id)
        .fetch_all(&mut *connection)
        .await?;
        details.push(CapecCategoryDetail {
            category,
            member_ids,
            references,
            history,
            notes,
            taxonomy_mappings,
        });
    }
    Ok(details)
}

async fn view_details(
    connection: &mut SqliteConnection,
    ids: &str,
) -> Result<Vec<CapecViewDetail>, sqlx::Error> {
    let views: Vec<CapecView> = sqlx::query_as(
        "SELECT id,name,view_type,status,objective,filter FROM capec_view WHERE id IN (SELECT value FROM json_each(?)) ORDER BY id",
    )
    .bind(ids)
    .fetch_all(&mut *connection)
    .await?;
    let mut details = Vec::with_capacity(views.len());
    for view in views {
        let category_ids = sqlx::query_scalar(
            "SELECT category_id FROM capec_view_category WHERE view_id=? ORDER BY member_order",
        )
        .bind(view.id)
        .fetch_all(&mut *connection)
        .await?;
        let capec_ids = sqlx::query_scalar(
            "SELECT capec_id FROM capec_view_capec WHERE view_id=? ORDER BY member_order",
        )
        .bind(view.id)
        .fetch_all(&mut *connection)
        .await?;
        let references = references_for_view(connection, view.id).await?;
        let history = sqlx::query_as(
            "SELECT event_type,event_date,actor_name,organization,comment,previous_name FROM capec_view_history WHERE view_id=? ORDER BY event_order",
        )
        .bind(view.id)
        .fetch_all(&mut *connection)
        .await?;
        let notes = sqlx::query_as(
            "SELECT note_type,note_text FROM capec_view_note WHERE view_id=? ORDER BY note_order",
        )
        .bind(view.id)
        .fetch_all(&mut *connection)
        .await?;
        details.push(CapecViewDetail {
            view,
            category_ids,
            capec_ids,
            references,
            history,
            notes,
        });
    }
    Ok(details)
}

fn push_references(
    owner_id: i64,
    references: Option<&[Reference]>,
    rows: &mut Vec<(i64, String, Option<String>, i64)>,
) {
    if let Some(references) = references {
        rows.extend(references.iter().enumerate().map(|(order, reference)| {
            (
                owner_id,
                canonical_reference_id(&reference.reference_id).to_owned(),
                reference.section.clone(),
                order as i64,
            )
        }));
    }
}

fn canonical_reference_id(reference_id: &str) -> &str {
    // CAPEC 3.9 links REF-97 as the XSS Filter Evasion Cheat Sheet, whose definition is REF-69.
    match reference_id {
        "REF-97" => "REF-69",
        _ => reference_id,
    }
}

fn push_history(owner_id: i64, history: Option<&ContentHistory>, rows: &mut Vec<HistoryRow>) {
    let Some(history) = history else {
        return;
    };
    let mut order = 0;
    if let Some(event) = &history.submission {
        rows.push((
            owner_id,
            order,
            "Submission".to_owned(),
            event.date.clone(),
            Some(event.name.clone()),
            event.organization.clone(),
            None,
            None,
        ));
        order += 1;
    }
    for event in &history.modifications {
        rows.push((
            owner_id,
            order,
            "Modification".to_owned(),
            event.date.clone(),
            Some(event.name.clone()),
            event.organization.clone(),
            event.comment.clone(),
            None,
        ));
        order += 1;
    }
    for event in &history.previous_names {
        rows.push((
            owner_id,
            order,
            "PreviousName".to_owned(),
            event.date.clone(),
            None,
            None,
            None,
            Some(event.name.clone()),
        ));
        order += 1;
    }
}

async fn validate_cwe_ids(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    rows: &[(i64, i64, i64)],
) -> Result<(), sqlx::Error> {
    let ids = rows.iter().map(|row| row.1).collect::<HashSet<_>>();
    let json =
        serde_json::to_string(&ids).map_err(|error| protocol(format!("CWE IDs: {error}")))?;
    let found: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM cwe WHERE id IN (SELECT value FROM json_each(?))")
            .bind(json)
            .fetch_one(&mut **tx)
            .await?;
    if found as usize != ids.len() {
        return Err(protocol(format!(
            "CAPEC references {} CWE IDs but only {found} exist",
            ids.len()
        )));
    }
    Ok(())
}

async fn hydrate_entries(
    connection: &mut sqlx::SqliteConnection,
    rows: Vec<sqlx::sqlite::SqliteRow>,
) -> Result<Vec<CapecEntry>, sqlx::Error> {
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let ids = rows
        .iter()
        .map(|row| row.get::<i32, _>("id"))
        .collect::<Vec<_>>();
    let json = serde_json::to_string(&ids).map_err(|error| protocol(error.to_string()))?;
    let relations: Vec<(i32, i32, i32, i64)> = sqlx::query_as(
        "SELECT capec_id,0,parent_id,relation_order FROM capec_parent
         WHERE capec_id IN (SELECT value FROM json_each(?))
         UNION ALL
         SELECT capec_id,1,cwe_id,relation_order FROM capec_cwe
         WHERE capec_id IN (SELECT value FROM json_each(?))
         UNION ALL
         SELECT capec_id,2,category_id,member_order FROM capec_category_member
         WHERE capec_id IN (SELECT value FROM json_each(?))
         UNION ALL
         SELECT capec_id,3,view_id,member_order FROM capec_view_capec
         WHERE capec_id IN (SELECT value FROM json_each(?))
         UNION ALL
         SELECT DISTINCT member.capec_id,4,link.view_id,link.member_order
         FROM capec_category_member member
         JOIN capec_view_category link ON link.category_id=member.category_id
         WHERE member.capec_id IN (SELECT value FROM json_each(?))
         UNION ALL
         SELECT parent_id,5,COUNT(*),0 FROM capec_parent
         WHERE parent_id IN (SELECT value FROM json_each(?))
         GROUP BY parent_id
         ORDER BY 1,2,4",
    )
    .bind(&json)
    .bind(&json)
    .bind(&json)
    .bind(&json)
    .bind(&json)
    .bind(&json)
    .fetch_all(&mut *connection)
    .await?;
    let mut parents = HashMap::<i32, Vec<i32>>::new();
    let mut weaknesses = HashMap::<i32, Vec<i32>>::new();
    let mut categories = HashMap::<i32, Vec<i32>>::new();
    let mut views = HashMap::<i32, Vec<i32>>::new();
    let mut children = HashMap::<i32, i64>::new();
    for (owner, kind, value, _) in relations {
        let target = match kind {
            0 => &mut parents,
            1 => &mut weaknesses,
            2 => &mut categories,
            3 | 4 => &mut views,
            5 => {
                children.insert(owner, value as i64);
                continue;
            }
            _ => continue,
        };
        let values = target.entry(owner).or_default();
        if !values.contains(&value) {
            values.push(value);
        }
    }

    Ok(rows
        .into_iter()
        .map(|row| {
            let id = row.get("id");
            CapecEntry {
                id,
                name: row.get("name"),
                description: row.get("description"),
                extended_description: row.get("extended_description"),
                status: row.get("status"),
                abstraction: row.get("abstraction"),
                parent_ids: parents.get(&id).cloned().unwrap_or_default(),
                cwe_ids: weaknesses.get(&id).cloned().unwrap_or_default(),
                category_ids: categories.get(&id).cloned().unwrap_or_default(),
                view_ids: views.get(&id).cloned().unwrap_or_default(),
                child_count: children.get(&id).copied().unwrap_or_default() as usize,
            }
        })
        .collect())
}

async fn references_for_capec(
    connection: &mut sqlx::SqliteConnection,
    owner_id: i32,
) -> Result<Vec<CapecReference>, sqlx::Error> {
    sqlx::query_as(
        "SELECT ref.reference_id,link.section,
         COALESCE((SELECT group_concat(author,'; ') FROM capec_external_reference_author a WHERE a.reference_id=ref.reference_id ORDER BY author_order),'') authors,
         ref.title,ref.edition,ref.publication,ref.publication_year,ref.publisher,ref.url
         FROM capec_reference link JOIN capec_external_reference ref ON ref.reference_id=link.reference_id
         WHERE link.capec_id=? ORDER BY link.reference_order",
    )
        .bind(owner_id)
        .fetch_all(connection)
        .await
}

async fn references_for_category(
    connection: &mut SqliteConnection,
    owner_id: i32,
) -> Result<Vec<CapecReference>, sqlx::Error> {
    sqlx::query_as(
        "SELECT ref.reference_id,link.section,
         COALESCE((SELECT group_concat(author,'; ') FROM capec_external_reference_author a WHERE a.reference_id=ref.reference_id ORDER BY author_order),'') authors,
         ref.title,ref.edition,ref.publication,ref.publication_year,ref.publisher,ref.url
         FROM capec_category_reference link JOIN capec_external_reference ref ON ref.reference_id=link.reference_id
         WHERE link.category_id=? ORDER BY link.reference_order",
    )
    .bind(owner_id)
    .fetch_all(connection)
    .await
}

async fn references_for_view(
    connection: &mut SqliteConnection,
    owner_id: i32,
) -> Result<Vec<CapecReference>, sqlx::Error> {
    sqlx::query_as(
        "SELECT ref.reference_id,link.section,
         COALESCE((SELECT group_concat(author,'; ') FROM capec_external_reference_author a WHERE a.reference_id=ref.reference_id ORDER BY author_order),'') authors,
         ref.title,ref.edition,ref.publication,ref.publication_year,ref.publisher,ref.url
         FROM capec_view_reference link JOIN capec_external_reference ref ON ref.reference_id=link.reference_id
         WHERE link.view_id=? ORDER BY link.reference_order",
    )
        .bind(owner_id)
        .fetch_all(connection)
        .await
}

fn parse_id(value: &str, prefix: &str) -> Option<i32> {
    value
        .trim()
        .to_ascii_uppercase()
        .trim_start_matches(prefix)
        .trim_start_matches('-')
        .parse()
        .ok()
}

fn protocol(message: impl Into<String>) -> sqlx::Error {
    sqlx::Error::Protocol(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use qanvuli_models::capec::parse_capec_catalog_xml;

    const XML: &str = r#"<Attack_Pattern_Catalog Name="CAPEC" Version="1" Date="2026-01-01">
      <Attack_Patterns>
        <Attack_Pattern ID="1" Name="Root" Abstraction="Meta" Status="Stable"><Description>Root</Description></Attack_Pattern>
        <Attack_Pattern ID="2" Name="Child" Abstraction="Standard" Status="Draft">
          <Description>Child</Description>
          <Related_Attack_Patterns><Related_Attack_Pattern Nature="ChildOf" CAPEC_ID="1"/></Related_Attack_Patterns>
          <Related_Weaknesses><Related_Weakness CWE_ID="79"/></Related_Weaknesses>
        </Attack_Pattern>
      </Attack_Patterns>
      <Categories><Category ID="100" Name="Cat" Status="Stable"><Summary>Summary</Summary><Relationships><Has_Member CAPEC_ID="2"/></Relationships></Category></Categories>
      <Views><View ID="1000" Name="View" Type="Graph" Status="Stable"><Objective>Objective</Objective><Members><Has_Member CAPEC_ID="100"/></Members></View></Views>
    </Attack_Pattern_Catalog>"#;

    #[tokio::test]
    async fn replaces_and_searches_catalog() {
        let db = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        db.initialize().await.unwrap();
        db.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query("INSERT INTO cwe(id,description,status) VALUES(79,'XSS','Stable')")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .await
            .unwrap();
        let catalog = parse_capec_catalog_xml(XML).unwrap();
        assert_eq!(db.replace_capec_catalog(&catalog).await.unwrap(), 2);
        let rows = db
            .search_capec_entries(CapecSearchFilters {
                cwe_id: Some(79),
                limit: 10,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].parent_ids, [1]);
        assert_eq!(rows[0].category_ids, [100]);
        assert_eq!(rows[0].view_ids, [1000]);
        assert_eq!(
            db.capec_ids_for_cwes(&[79]).await.unwrap().get(&79),
            Some(&vec![2])
        );
    }

    #[tokio::test]
    async fn rejects_dangling_reference_without_replacing_catalog() {
        let db = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        db.initialize().await.unwrap();
        db.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query("INSERT INTO cwe(id,description,status) VALUES(79,'XSS','Stable')")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .await
            .unwrap();
        let valid = parse_capec_catalog_xml(XML).unwrap();
        db.replace_capec_catalog(&valid).await.unwrap();
        let invalid = parse_capec_catalog_xml(
            r#"<Attack_Pattern_Catalog Name="CAPEC" Version="1" Date="2026-01-01">
              <Attack_Patterns><Attack_Pattern ID="1" Name="Root" Abstraction="Meta" Status="Stable">
                <Description>Root</Description>
                <References><Reference External_Reference_ID="REF-MISSING"/></References>
              </Attack_Pattern></Attack_Patterns>
            </Attack_Pattern_Catalog>"#,
        )
        .unwrap();

        assert!(db.replace_capec_catalog(&invalid).await.is_err());
        let rows = db
            .search_capec_entries(CapecSearchFilters {
                limit: 10,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[tokio::test]
    async fn resolves_official_ref_97_alias() {
        let db = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        db.initialize().await.unwrap();
        let catalog = parse_capec_catalog_xml(
            r#"<Attack_Pattern_Catalog Name="CAPEC" Version="1" Date="2026-01-01">
              <Attack_Patterns><Attack_Pattern ID="1" Name="XSS" Abstraction="Standard" Status="Stable">
                <Description>XSS</Description>
                <References><Reference External_Reference_ID="REF-97" Section="Cheat Sheet"/></References>
              </Attack_Pattern></Attack_Patterns>
              <External_References><External_Reference Reference_ID="REF-69">
                <Title>OWASP Cheatsheets</Title>
              </External_Reference></External_References>
            </Attack_Pattern_Catalog>"#,
        )
        .unwrap();

        db.replace_capec_catalog(&catalog).await.unwrap();
        let detail = db.get_capec_detail(1).await.unwrap().unwrap();
        assert_eq!(detail.references[0].reference_id, "REF-69");
        assert_eq!(detail.references[0].section.as_deref(), Some("Cheat Sheet"));
    }
}
