use regex::Regex;

pub(crate) struct DetailSearch {
    pub(crate) regex: Option<Regex>,
    pub(crate) error: Option<String>,
}

impl DetailSearch {
    pub(crate) fn new(query: &str) -> Self {
        if query.is_empty() {
            return Self {
                regex: None,
                error: None,
            };
        }
        match Regex::new(query) {
            Ok(regex) => Self {
                regex: Some(regex),
                error: None,
            },
            Err(err) => Self {
                regex: None,
                error: Some(format!("invalid regex: {err}")),
            },
        }
    }

    pub(crate) fn enabled(&self) -> bool {
        self.regex.is_some()
    }
}
