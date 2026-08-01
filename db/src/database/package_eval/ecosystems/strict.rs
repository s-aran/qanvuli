use super::EcosystemPolicy;

pub(super) static POLICY: StrictPolicy = StrictPolicy;

pub(super) struct StrictPolicy;

impl EcosystemPolicy for StrictPolicy {
    fn ecosystem_name(&self) -> &'static str {
        "unknown"
    }
}
