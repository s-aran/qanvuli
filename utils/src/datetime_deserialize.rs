use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Deserializer};

fn add_timezone_if_missing(s: String) -> String {
    if has_timezone_suffix(&s) {
        s
    } else {
        format!("{s}Z")
    }
}

fn has_timezone_suffix(value: &str) -> bool {
    if value.ends_with('Z') {
        return true;
    }
    let bytes = value.as_bytes();
    let len = bytes.len();
    if len < 6 {
        return false;
    }
    let suffix = &bytes[len - 6..];
    matches!(suffix[0], b'+' | b'-')
        && suffix[1].is_ascii_digit()
        && suffix[2].is_ascii_digit()
        && suffix[3] == b':'
        && suffix[4].is_ascii_digit()
        && suffix[5].is_ascii_digit()
}

pub fn deserialize_cve_timestamp<'de, D>(
    deserializer: D,
) -> Result<Option<DateTime<FixedOffset>>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = match Option::<String>::deserialize(deserializer)? {
        Some(s) => add_timezone_if_missing(s),
        None => return Ok(None),
    };

    Ok(Some(
        DateTime::parse_from_rfc3339(&s).map_err(serde::de::Error::custom)?,
    ))
}

pub fn deserialize_required_cve_timestamp<'de, D>(
    deserializer: D,
) -> Result<DateTime<FixedOffset>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = add_timezone_if_missing(String::deserialize(deserializer)?);
    DateTime::parse_from_rfc3339(&s).map_err(serde::de::Error::custom)
}
