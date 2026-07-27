use qanvuli_core::database::CveStateScope;

pub(crate) fn limit(value: Option<u64>) -> u64 {
    value.unwrap_or(10).clamp(1, 30)
}

pub(crate) fn offset(value: Option<u64>) -> u64 {
    value.unwrap_or(0)
}

pub(crate) fn state_scope(include_rejected: Option<bool>) -> CveStateScope {
    CveStateScope::from_include_rejected(include_rejected.unwrap_or(false))
}
