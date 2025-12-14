use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credit {
    #[serde(default = "default_lang")]
    pub lang: String,
    pub value: String,
    pub user: Option<String>,
    #[serde(rename = "type", default = "default_credit_type")]
    pub credit_type: String,
}

fn default_lang() -> String {
    "en".to_owned()
}

fn default_credit_type() -> String {
    "finder".to_owned()
}
