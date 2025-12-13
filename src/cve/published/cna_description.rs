use serde::Deserialize;

use crate::cve::published::supporting_media::SupportingMedia;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CnaDescription {
    #[serde(default = "default_lang")]
    pub lang: String,
    pub value: String,
    pub supporting_media: Option<Vec<SupportingMedia>>,
}

fn default_lang() -> String {
    "en".to_owned()
}
