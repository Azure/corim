// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Signed-CoRIM commands: `extract`, `sign prepare`, `sign finalize`.
//!
//! The `corim` crate performs no cryptography, so signing is a two-step,
//! bring-your-own-signer workflow:
//!
//! 1. `sign prepare` takes an unsigned CoRIM plus signer metadata and a
//!    certificate chain, and emits (a) a **staging** COSE_Sign1 with a
//!    placeholder (empty) signature and (b) the **to-be-signed** bytes
//!    (`Sig_structure1`, RFC 9052 §4.4).
//! 2. The operator signs the TBS bytes with their own key/HSM per the
//!    chosen COSE algorithm.
//! 3. `sign finalize` injects that signature into the staging CoRIM,
//!    producing the final `#6.18(COSE_Sign1)` signed CoRIM.
//!
//! `extract` pulls the embedded (attached) unsigned CoRIM payload back
//! out of a signed CoRIM.

use std::fs;
use std::io::{self, Write};
use std::process;

use base64::Engine;
use clap::{Parser, Subcommand};

use corim::types::signed::{
    decode_signed_corim, encode_signed_corim, CoseAlgorithm, CoseX509, CwtClaims,
    SignedCorimBuilder,
};

// ---------------------------------------------------------------------------
// extract
// ---------------------------------------------------------------------------

/// Arguments for the `extract` subcommand.
#[derive(Parser)]
pub struct ExtractArgs {
    /// Path to the signed CoRIM (`#6.18` COSE_Sign1). Use "-" or omit for stdin.
    #[arg(value_name = "SIGNED")]
    file: Option<String>,

    /// Output path for the extracted `tagged-unsigned-corim-map` bytes.
    /// Use "-" or omit for stdout.
    #[arg(short, long, value_name = "FILE")]
    output: Option<String>,

    /// Validate the extracted CoRIM after extraction.
    #[arg(long)]
    validate: bool,
}

/// Entry point for the `extract` subcommand.
pub fn run_extract(args: ExtractArgs) {
    if let Err(e) = run_extract_impl(args) {
        eprintln!("Error: {e}");
        process::exit(1);
    }
}

fn run_extract_impl(args: ExtractArgs) -> Result<(), String> {
    let bytes = read_input(args.file.as_deref())?;
    if bytes.is_empty() {
        return Err("input is empty".into());
    }

    let envelope =
        decode_signed_corim(&bytes).map_err(|e| format!("decoding signed CoRIM: {e}"))?;

    let payload = envelope.payload.ok_or_else(|| {
        "signed CoRIM has a detached (nil) payload; the unsigned CoRIM is transported \
         separately and cannot be extracted from this envelope"
            .to_string()
    })?;

    if args.validate {
        corim::validate::decode_and_validate(&payload)
            .map_err(|e| format!("extracted CoRIM failed validation: {e}"))?;
    }

    write_output(args.output.as_deref(), &payload)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// sign (prepare / finalize)
// ---------------------------------------------------------------------------

/// Arguments for the `sign` subcommand group.
#[derive(Parser)]
pub struct SignArgs {
    #[command(subcommand)]
    command: SignCommands,
}

/// The `sign` subcommands.
#[derive(Subcommand)]
enum SignCommands {
    /// Prepare a staging CoRIM and the to-be-signed (TBS) bytes.
    ///
    /// Builds the COSE_Sign1 protected header (algorithm, signer identity,
    /// certificate chain) around the unsigned CoRIM and writes a staging
    /// envelope with a placeholder signature plus the `Sig_structure1`
    /// bytes to sign. No cryptography is performed.
    Prepare(PrepareArgs),

    /// Assemble a signed CoRIM from a staging CoRIM and a signature.
    ///
    /// Injects an externally computed signature into the staging envelope
    /// produced by `prepare`, yielding the final signed CoRIM.
    Finalize(FinalizeArgs),
}

/// Arguments for `sign prepare`.
#[derive(Parser)]
pub struct PrepareArgs {
    /// Path to the unsigned CoRIM (`tagged-unsigned-corim-map`) to sign.
    #[arg(value_name = "UNSIGNED")]
    unsigned: String,

    /// COSE signing algorithm: a name (e.g. `ES256`, `ESP384`, `PS256`,
    /// `Ed25519`) or a raw COSE integer identifier (e.g. `-7`).
    #[arg(long, value_name = "ALG")]
    alg: String,

    /// Signer name, recorded as the CWT-Claims `iss` (key 15/1). Satisfies
    /// the §4.2.1 meta-group constraint that identifies the signer.
    #[arg(long, value_name = "NAME")]
    signer_name: String,

    /// X.509 certificate file (DER or PEM), end-entity (leaf) first.
    /// Repeat for a chain. PEM files may contain multiple certificates.
    #[arg(long = "x5chain", value_name = "CERT")]
    x5chain: Vec<String>,

    /// Produce a detached-payload envelope (the payload is carried as
    /// `nil`; the TBS is still computed over the real payload).
    #[arg(long)]
    detached: bool,

    /// Optional file of external additional authenticated data (AAD)
    /// mixed into the TBS. Verifiers must supply the same AAD.
    #[arg(long, value_name = "FILE")]
    external_aad: Option<String>,

    /// Output path for the staging CoRIM (COSE_Sign1 with a placeholder
    /// signature). Complete it later with `sign finalize`.
    #[arg(long, value_name = "FILE")]
    out_staging: String,

    /// Output path for the to-be-signed (`Sig_structure1`) bytes.
    #[arg(long, value_name = "FILE")]
    out_tbs: String,
}

/// Arguments for `sign finalize`.
#[derive(Parser)]
pub struct FinalizeArgs {
    /// Path to the staging CoRIM produced by `sign prepare`.
    #[arg(value_name = "STAGING")]
    staging: String,

    /// Path to the raw signature bytes computed over the TBS.
    #[arg(long, value_name = "FILE")]
    signature: String,

    /// Output path for the final signed CoRIM.
    #[arg(short, long, value_name = "FILE")]
    output: String,
}

/// Entry point for the `sign` subcommand group.
pub fn run_sign(args: SignArgs) {
    let result = match args.command {
        SignCommands::Prepare(a) => run_prepare_impl(a),
        SignCommands::Finalize(a) => run_finalize_impl(a),
    };
    if let Err(e) = result {
        eprintln!("Error: {e}");
        process::exit(1);
    }
}

fn run_prepare_impl(args: PrepareArgs) -> Result<(), String> {
    let unsigned =
        fs::read(&args.unsigned).map_err(|e| format!("reading {}: {e}", args.unsigned))?;
    if unsigned.is_empty() {
        return Err("unsigned CoRIM is empty".into());
    }

    let alg = parse_alg(&args.alg)?;

    let aad = match &args.external_aad {
        Some(p) => fs::read(p).map_err(|e| format!("reading external-aad {p}: {e}"))?,
        None => Vec::new(),
    };

    let mut builder =
        SignedCorimBuilder::new(alg, unsigned).set_cwt_claims(CwtClaims::new(&args.signer_name));

    if !args.x5chain.is_empty() {
        let certs = load_certs(&args.x5chain)?;
        let x5chain = if certs.len() == 1 {
            // Safe: length checked to be exactly 1 immediately above.
            CoseX509::Single(certs.into_iter().next().expect("certs.len() == 1"))
        } else {
            CoseX509::Chain(certs)
        };
        builder = builder.x5chain(x5chain);
    }

    // Compute the TBS first (this also caches the protected header), then
    // emit the staging envelope with a placeholder (empty) signature.
    let tbs = builder
        .to_be_signed(&aad)
        .map_err(|e| format!("computing to-be-signed bytes: {e}"))?;

    let staging = if args.detached {
        builder.build_detached_with_signature(Vec::new())
    } else {
        builder.build_with_signature(Vec::new())
    }
    .map_err(|e| format!("building staging CoRIM: {e}"))?;

    fs::write(&args.out_tbs, &tbs).map_err(|e| format!("writing {}: {e}", args.out_tbs))?;
    fs::write(&args.out_staging, &staging)
        .map_err(|e| format!("writing {}: {e}", args.out_staging))?;

    eprintln!(
        "Wrote staging CoRIM: {} ({} bytes){}",
        args.out_staging,
        staging.len(),
        if args.detached { " [detached]" } else { "" }
    );
    eprintln!("Wrote to-be-signed: {} ({} bytes)", args.out_tbs, tbs.len());
    eprintln!(
        "Next: sign {} with your {} key, then run `corim-cli sign finalize {} --signature <sig> -o <signed>`",
        args.out_tbs,
        CoseAlgorithm::from_i64(alg).name(),
        args.out_staging
    );
    Ok(())
}

fn run_finalize_impl(args: FinalizeArgs) -> Result<(), String> {
    let staging = fs::read(&args.staging).map_err(|e| format!("reading {}: {e}", args.staging))?;
    let signature =
        fs::read(&args.signature).map_err(|e| format!("reading {}: {e}", args.signature))?;
    if signature.is_empty() {
        return Err("signature file is empty".into());
    }

    let mut envelope =
        decode_signed_corim(&staging).map_err(|e| format!("decoding staging CoRIM: {e}"))?;
    envelope.signature = signature;

    let signed =
        encode_signed_corim(&envelope).map_err(|e| format!("encoding signed CoRIM: {e}"))?;

    fs::write(&args.output, &signed).map_err(|e| format!("writing {}: {e}", args.output))?;
    eprintln!(
        "Wrote signed CoRIM: {} ({} bytes)",
        args.output,
        signed.len()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Parse a COSE algorithm from a name or a raw integer identifier.
fn parse_alg(s: &str) -> Result<i64, String> {
    let name = s.trim();
    let alg = match name.to_ascii_uppercase().as_str() {
        "ES256" => -7,
        "EDDSA" => -8,
        "ESP256" => -9,
        "ED25519" => -19,
        "ES384" => -35,
        "ES512" => -36,
        "PS256" => -37,
        "PS384" => -38,
        "PS512" => -39,
        "ESP384" => -51,
        "ESP512" => -52,
        "ED448" => -53,
        _ => {
            return name.parse::<i64>().map_err(|_| {
                format!("unknown algorithm '{name}': use a COSE name (e.g. ES256) or integer")
            })
        }
    };
    Ok(alg)
}

/// Load one or more certificate files, each DER or PEM, into DER byte
/// vectors preserving order (leaf-first for `x5chain`).
fn load_certs(paths: &[String]) -> Result<Vec<Vec<u8>>, String> {
    let mut out = Vec::new();
    for p in paths {
        let raw = fs::read(p).map_err(|e| format!("reading cert {p}: {e}"))?;
        if raw.is_empty() {
            return Err(format!("cert file {p} is empty"));
        }
        // PEM if the bytes are text beginning with a BEGIN marker.
        let is_pem = raw
            .iter()
            .position(|&b| !b.is_ascii_whitespace())
            .map(|i| raw[i..].starts_with(b"-----BEGIN"))
            .unwrap_or(false);
        if is_pem {
            let text = String::from_utf8_lossy(&raw);
            let certs = parse_pem_certs(&text).map_err(|e| format!("parsing PEM cert {p}: {e}"))?;
            if certs.is_empty() {
                return Err(format!("no CERTIFICATE blocks found in PEM file {p}"));
            }
            out.extend(certs);
        } else {
            out.push(raw);
        }
    }
    Ok(out)
}

/// Extract all `CERTIFICATE` blocks from PEM text and base64-decode each
/// into DER bytes.
fn parse_pem_certs(text: &str) -> Result<Vec<Vec<u8>>, String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut certs = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(BEGIN) {
        let after = &rest[start + BEGIN.len()..];
        let end = after
            .find(END)
            .ok_or_else(|| "unterminated CERTIFICATE block (missing END marker)".to_string())?;
        let b64: String = after[..end].split_whitespace().collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .map_err(|e| format!("invalid base64 in CERTIFICATE block: {e}"))?;
        certs.push(der);
        rest = &after[end + END.len()..];
    }
    Ok(certs)
}

/// Read from a file path, or stdin when `None` or `"-"`.
fn read_input(path: Option<&str>) -> Result<Vec<u8>, String> {
    match path {
        Some(p) if p != "-" => fs::read(p).map_err(|e| format!("reading {p}: {e}")),
        _ => {
            use std::io::Read;
            let mut buf = Vec::new();
            io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| format!("reading stdin: {e}"))?;
            Ok(buf)
        }
    }
}

/// Write bytes to a file path, or stdout when `None` or `"-"`.
fn write_output(path: Option<&str>, bytes: &[u8]) -> Result<(), String> {
    match path {
        Some(p) if p != "-" => {
            fs::write(p, bytes).map_err(|e| format!("writing {p}: {e}"))?;
            eprintln!("Wrote CoRIM payload: {p} ({} bytes)", bytes.len());
        }
        _ => {
            io::stdout()
                .write_all(bytes)
                .map_err(|e| format!("writing stdout: {e}"))?;
        }
    }
    Ok(())
}
