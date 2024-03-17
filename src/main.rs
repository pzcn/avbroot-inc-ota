/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::{atomic::AtomicBool, Arc},
};

use anyhow::{anyhow, bail, Context, Result};
use avbroot::{
    cli::ota::ExtractCli,
    crypto::{self, PassphraseSource},
    format::{
        ota::{self, SigningWriter, ZipEntry},
        payload::{PayloadHeader, PayloadWriter},
    },
    protobuf::build::tools::releasetools::OtaMetadata,
    stream::{self, CountingWriter, FromReader, HolePunchingWriter},
};
use clap::Parser;
use itertools::Itertools;
use rsa::RsaPrivateKey;
use tempfile::TempDir;
use x509_cert::Certificate;
use zip::{write::FileOptions, CompressionMethod, ZipArchive, ZipWriter};

const APEX_INFO: &str = "apex_info.pb";

/// Generate an incremental OTA from two full OTAs.
///
/// The delta `payload.bin` generation requires the `delta_generator` executable
/// from AOSP.
///
/// The system temporary directory must have enough space to extract both full
/// OTAs and store the delta payload. To use a different temporary directory,
/// set the TMPDIR environment variable.
#[derive(Debug, Parser)]
struct Cli {
    /// Path to unsigned payload file.
    #[arg(long, value_name = "FILE", value_parser)]
    unsigned_payload: PathBuf,

    /// Path to output payload file.
    #[arg(long, value_name = "FILE", value_parser)]
    output_payload: PathBuf,

    /// Private key for signing the OTA.
    #[arg(short, long, value_name = "FILE", value_parser)]
    key: PathBuf,

    /// Environment variable containing the private key passphrase.
    #[arg(long, value_name = "ENV_VAR", value_parser, group = "pass")]
    pass_env_var: Option<OsString>,

    /// Text file containing the private key passphrase.
    #[arg(long, value_name = "FILE", value_parser, group = "passphrase")]
    pass_file: Option<PathBuf>,

    /// Certificate for OTA signing key.
    #[arg(short, long, value_name = "FILE", value_parser)]
    cert: PathBuf,
}

/// Sign a (potentially unsigned) payload without making any other
/// modifications to it.
fn sign_payload(
    unsigned_payload: &Path,
    writer: impl Write,
    key: &RsaPrivateKey,
) -> Result<(String, u64)> {
    let inc_raw_reader = File::open(unsigned_payload)
        .with_context(|| format!("Failed to open for reading: {unsigned_payload:?}"))?;
    let mut inc_reader = BufReader::new(inc_raw_reader);
    let inc_header = PayloadHeader::from_reader(&mut inc_reader)
        .with_context(|| format!("Failed to parse payload header: {unsigned_payload:?}"))?;

    let mut payload_writer = PayloadWriter::new(writer, inc_header.clone(), key.clone())
        .context("Failed to write payload header")?;

    while payload_writer
        .begin_next_operation()
        .context("Failed to begin next payload blob entry")?
    {
        let name = payload_writer.partition().unwrap().partition_name.clone();
        let operation = payload_writer.operation().unwrap();

        let Some(data_length) = operation.data_length else {
            // Otherwise, this is a ZERO/DISCARD operation.
            continue;
        };

        // Copy from the original payload.
        let pi = payload_writer.partition_index().unwrap();
        let oi = payload_writer.operation_index().unwrap();
        let orig_partition = &inc_header.manifest.partitions[pi];
        let orig_operation = &orig_partition.operations[oi];

        let data_offset = orig_operation
            .data_offset
            .and_then(|o| o.checked_add(inc_header.blob_offset))
            .ok_or_else(|| anyhow!("Missing data_offset in partition #{pi} operation #{oi}"))?;

        inc_reader
            .seek(SeekFrom::Start(data_offset))
            .with_context(|| format!("Failed to seek original payload to {data_offset}"))?;

        stream::copy_n(
            &mut inc_reader,
            &mut payload_writer,
            data_length,
            &Arc::new(AtomicBool::new(false)),
        )
        .with_context(|| format!("Failed to copy from original payload: {name}"))?;
    }

    let (_, p, m) = payload_writer
        .finish()
        .context("Failed to finalize payload")?;

    Ok((p, m))
}

    println!("Generating new OTA metadata");

    // Set up preconditions checks to ensure that the incremental OTA can only
    // be applied on top of the correct source OS build.
    let mut inc_metadata = new_metadata.clone();
    let inc_precondition = inc_metadata
        .precondition
        .as_mut()
        .ok_or_else(|| anyhow!("New full OTA has no preconditions"))?;
    let old_postcondition = old_metadata
        .postcondition
        .as_ref()
        .ok_or_else(|| anyhow!("Old full OTA has no postconditions"))?;
    inc_precondition.build = old_postcondition.build.clone();
    inc_precondition.build_incremental = old_postcondition.build_incremental.clone();

    let data_descriptor_size = 16;
    let metadata = ota::add_metadata(
        &entries,
        &mut zip_writer,
        // Offset where next entry would begin.
        entries.last().map(|e| e.offset + e.size).unwrap() + data_descriptor_size,
        &inc_metadata,
        payload_metadata_size.unwrap(),
    )
    .context("Failed to write new OTA metadata")?;

    let signing_writer = zip_writer
        .finish()
        .context("Failed to finalize output zip")?;
    let buffered_writer = signing_writer
        .finish(key, cert)
        .context("Failed to sign output zip")?;
    let hole_punching_writer = buffered_writer
        .into_inner()
        .context("Failed to flush output zip")?;
    let mut raw_writer = hole_punching_writer.into_inner();
    raw_writer.flush().context("Failed to flush output zip")?;

    println!("Verifying metadata offsets");
    raw_writer.rewind()?;
    ota::verify_metadata(
        BufReader::new(&mut raw_writer),
        &metadata,
        payload_metadata_size.unwrap(),
    )
    .context("Failed to verify OTA metadata offsets")?;

    Ok(())
}

fn main_wrapper(cli: &Cli) -> Result<()> {
    let passphrase_source = if let Some(v) = &cli.pass_env_var {
        PassphraseSource::EnvVar(v.clone())
    } else if let Some(p) = &cli.pass_file {
        PassphraseSource::File(p.clone())
    } else {
        PassphraseSource::Prompt(format!("Enter passphrase for {:?}: ", cli.key))
    };

    let key = crypto::read_pem_key_file(&cli.key, &passphrase_source)
        .with_context(|| format!("Failed to load key: {:?}", cli.key))?;
    let cert = crypto::read_pem_cert_file(&cli.cert)
        .with_context(|| format!("Failed to load certificate: {:?}", cli.cert))?;

    println!("Creating temporary directories");
    let old_temp_dir = TempDir::new()?;
    let new_temp_dir = TempDir::new()?;
    let inc_temp_dir = TempDir::new()?;

    sign_payload(
        &cli.unsigned_payload,
        &key,
        &cert,
    )?;

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    main_wrapper(&cli)
}
