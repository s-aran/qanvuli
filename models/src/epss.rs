#[derive(Clone, Debug, Default)]
pub struct EpssCurrentCsv {
    pub model_version: Option<String>,
    pub score_date: Option<String>,
    pub rows: Vec<EpssCurrentRow>,
}

#[derive(Clone, Debug)]
pub struct EpssCurrentRow {
    pub cve_id: String,
    pub epss: f64,
    pub percentile: f64,
}

impl EpssCurrentCsv {
    pub fn parse(csv: &str) -> Result<Self, String> {
        let mut parsed = Self::default();
        let mut saw_header = false;
        for line in csv.lines().map(str::trim).filter(|line| !line.is_empty()) {
            if let Some(comment) = line.strip_prefix('#') {
                for part in comment.split(',') {
                    if let Some((key, value)) = part.split_once(':') {
                        match key.trim() {
                            "model_version" => parsed.model_version = Some(value.trim().to_owned()),
                            "score_date" => parsed.score_date = Some(value.trim().to_owned()),
                            _ => {}
                        }
                    }
                }
                continue;
            }
            let columns = line.split(',').map(str::trim).collect::<Vec<_>>();
            if !saw_header
                && columns
                    .first()
                    .is_some_and(|value| value.eq_ignore_ascii_case("cve"))
            {
                saw_header = true;
                continue;
            }
            if columns.len() < 3 {
                continue;
            }
            parsed.rows.push(EpssCurrentRow {
                cve_id: columns[0].trim().to_ascii_uppercase(),
                epss: columns[1]
                    .parse()
                    .map_err(|err| format!("invalid EPSS score `{}`: {err}", columns[1]))?,
                percentile: columns[2]
                    .parse()
                    .map_err(|err| format!("invalid EPSS percentile `{}`: {err}", columns[2]))?,
            });
        }
        Ok(parsed)
    }
}
