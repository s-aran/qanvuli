//! Shared FTS5 query normalization.

pub(crate) fn fts_query(query: &str) -> Option<String> {
    let tokens = fts_tokens(query)
        .into_iter()
        .map(|token| format!("{token}*"))
        .collect::<Vec<_>>();
    (!tokens.is_empty()).then(|| tokens.join(" AND "))
}

pub(crate) fn fts_tokens(query: &str) -> Vec<String> {
    query
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|token| token.len() >= 2)
        .map(fts_token)
        .collect()
}

pub(crate) fn fts_token(token: &str) -> String {
    token.chars().filter(|ch| ch.is_alphanumeric()).collect()
}
