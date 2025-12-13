use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Scenario {
    #[serde(default = "default_lang")]
    pub lang: String,
    #[serde(default = "default_value")]
    pub value: String,
}

fn default_lang() -> String {
    "en".to_owned()
}

fn default_value() -> String {
    "GENERAL".to_owned()
}
