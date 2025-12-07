use serde::Deserialize;

use crate::cve::supporting_media::SupportingMedia;

#[derive(Debug, Deserialize)]
pub struct CnaDescription {
    #[serde(default = "default_lang")]
    pub lang: String,
    pub value: String,
    pub supporting_media: Vec<SupportingMedia>,
}

fn default_lang() -> String {
    "en".to_owned()
}
