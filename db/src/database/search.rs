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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitespace_separated_free_text_terms_are_joined_with_and() {
        assert_eq!(
            fts_query("remote code execution"),
            Some("remote* AND code* AND execution*".to_owned())
        );
        assert_eq!(
            fts_query("remote\tcode\nexecution"),
            Some("remote* AND code* AND execution*".to_owned())
        );
    }

    #[test]
    fn punctuation_inside_a_term_keeps_each_fts_token_required() {
        assert_eq!(
            fts_query("client-side validation"),
            Some("client* AND side* AND validation*".to_owned())
        );
    }
}
