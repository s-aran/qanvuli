//! Canonical UTC timestamp handling for searchable SQLite columns.

use chrono::{DateTime, NaiveDateTime, SecondsFormat, Utc};

pub(crate) fn canonical_utc(value: &str) -> Result<String, chrono::ParseError> {
    Ok(DateTime::parse_from_rfc3339(value)?
        .with_timezone(&Utc)
        .to_rfc3339_opts(SecondsFormat::Secs, true))
}

/// CVE List occasionally contains timestamps without an explicit offset.
/// Treat those values as UTC, matching the feed's timestamp convention.
pub(crate) fn canonical_cve_utc(value: &str) -> Result<String, chrono::ParseError> {
    match canonical_utc(value) {
        Ok(timestamp) => Ok(timestamp),
        Err(rfc3339_error) => NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S%.f")
            .map(|timestamp| {
                timestamp
                    .and_utc()
                    .to_rfc3339_opts(SecondsFormat::Secs, true)
            })
            .map_err(|_| rfc3339_error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_offsets_for_lexicographic_ordering() {
        assert_eq!(
            canonical_utc("2099-01-01T09:00:00+09:00").unwrap(),
            "2099-01-01T00:00:00Z"
        );
    }

    #[test]
    fn treats_offsetless_cve_timestamps_as_utc() {
        assert_eq!(
            canonical_cve_utc("2022-09-05T09:50:09").unwrap(),
            "2022-09-05T09:50:09Z"
        );
    }
}
