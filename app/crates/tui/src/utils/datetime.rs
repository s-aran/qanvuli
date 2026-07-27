use chrono::{DateTime, FixedOffset};

use crate::display::TimeZone;

pub(crate) fn format_timestamp(value: &str, timezone: TimeZone) -> String {
    let Ok(datetime) = DateTime::parse_from_rfc3339(value) else {
        return value.to_owned();
    };
    let Some(offset) = timezone_offset(timezone) else {
        return value.to_owned();
    };
    datetime
        .with_timezone(&offset)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

pub(crate) fn timezone_offset(timezone: TimeZone) -> Option<FixedOffset> {
    match timezone {
        TimeZone::Utc => FixedOffset::east_opt(0),
        TimeZone::Jst => FixedOffset::east_opt(9 * 60 * 60),
        TimeZone::Pst => FixedOffset::west_opt(8 * 60 * 60),
    }
}
