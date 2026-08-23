use qanvuli_core::model::{explain_cvss_vector, score_cvss_vector};

#[derive(Debug, clap::Args)]
pub struct Args {
    /// CVSS v2.0, v3.0, v3.1, or v4.0 vector to explain and score.
    #[arg(value_name = "VECTOR")]
    vector: String,
}

pub fn run(args: &Args) -> Result<(), String> {
    let vector = args.vector.trim();
    let score = score_cvss_vector(vector)?;

    println!(
        "CVSS {} {:.1} {} {}",
        score.version, score.score, score.severity, vector
    );
    for metric in explain_cvss_vector(&score.version, vector) {
        println!("- {}: {}", metric.name, metric.value);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Command {
        #[command(flatten)]
        args: Args,
    }

    #[test]
    fn parses_vector_as_a_positional_argument() {
        let command =
            Command::try_parse_from(["cvss", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"])
                .unwrap();

        assert_eq!(
            command.args.vector,
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
        );
    }
}
