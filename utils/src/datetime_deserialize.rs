use chrono::{DateTime, FixedOffset};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Deserializer};

fn add_timezone_if_missing(s: String) -> String {
    static TZ_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(Z|[+-][0-9]{2}:[0-9]{2})$").unwrap());

    if TZ_RE.is_match(s.as_str()) {
        s
    } else {
        format!("{s}Z")
    }
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
    Ok(DateTime::parse_from_rfc3339(&s).map_err(serde::de::Error::custom)?)
}
