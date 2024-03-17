use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;

use anyhow::{Context, Result};
use avbroot::crypto::{self, PassphraseSource};
use avbroot::format::payload::{PayloadHeader, PayloadWriter};
use clap::Parser;
use rsa::RsaPrivateKey;

/// Sign an unsigned payload.bin file.
#[derive(Debug, Parser)]
struct Cli {
    /// Path to unsigned payload.bin file.
    #[arg(long, value_name = "FILE", value_parser)]
    input: PathBuf,

    /// Path to output signed payload.bin file.
    #[arg(long, value_name = "FILE", value_parser)]
    output: PathBuf,

    /// Private key for signing the payload.
    #[arg(short, long, value_name = "FILE", value_parser)]
    key: PathBuf,

    /// Environment variable containing the private key passphrase.
    #[arg(long, value_name = "ENV_VAR", value_parser, group = "pass")]
    pass_env_var: Option<String>,

    /// Text file containing the private key passphrase.
    #[arg(long, value_name = "FILE", value_parser, group = "passphrase")]
    pass_file: Option<PathBuf>,
}

/// Sign a (potentially unsigned) payload without making any other
/// modifications to it.
fn sign_payload(
    unsigned_payload: &PathBuf,
    output: &PathBuf,
    key: &RsaPrivateKey,
) -> Result<()> {
    let inc_raw_reader = File::open(unsigned_payload)
        .with_context(|| format!("Failed to open for reading: {:?}", unsigned_payload))?;
    let mut inc_reader = BufReader::new(inc_raw_reader);
    let inc_header = PayloadHeader::from_reader(&mut inc_reader)
        .with_context(|| format!("Failed to parse payload header: {:?}", unsigned_payload))?;

    let output_file = File::create(output)
        .with_context(|| format!("Failed to create output file: {:?}", output))?;
    let output_writer = BufWriter::new(output_file);
    let mut payload_writer = PayloadWriter::new(output_writer, inc_header.clone(), key.clone())
        .context("Failed to write payload header")?;

    std::io::copy(&mut inc_reader, &mut payload_writer)
        .with_context(|| format!("Failed to copy payload data"))?;

    payload_writer
        .finish()
        .context("Failed to finalize payload")?;

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let passphrase_source = if let Some(v) = &cli.pass_env_var {
        PassphraseSource::EnvVar(v.clone())
    } else if let Some(p) = &cli.pass_file {
        PassphraseSource::File(p.clone())
    } else {
        PassphraseSource::Prompt(format!("Enter passphrase for {:?}: ", cli.key))
    };

    let key = crypto::read_pem_key_file(&cli.key, &passphrase_source)
        .with_context(|| format!("Failed to load key: {:?}", cli.key))?;

    sign_payload(&cli.input, &cli.output, &key)?;

    Ok(())
}
