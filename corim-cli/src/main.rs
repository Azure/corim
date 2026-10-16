// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CLI tool for validating and inspecting CoRIM documents.

use std::process;

use clap::{Parser, Subcommand};

mod baseline;
mod convert;
mod display;
mod edn;
mod generate;
mod input;
mod jsonfmt;
mod profiles;
mod prose;
mod sign;
mod validation;

/// Validate, inspect, and generate CoRIM (Concise Reference Integrity
/// Manifest) documents.
#[derive(Parser)]
#[command(name = "corim-cli", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate and inspect a CoRIM CBOR document.
    ///
    /// Reads a CBOR-encoded CoRIM file (tag-501-wrapped), validates its
    /// structure against draft-ietf-rats-corim-11, and outputs the
    /// decoded structure.
    Validate(ValidateArgs),

    /// Generate an unsigned CoRIM CBOR document from a JSON template.
    ///
    /// Reads a hand-authored JSON template describing the CoRIM id,
    /// profile, and CoMID tags (full triples tree), builds the CoRIM
    /// via the builder API, validates it, and writes the CBOR output.
    Generate(generate::GenerateArgs),

    /// Convert an unsigned CoRIM CBOR document to a JSON template.
    ///
    /// The inverse of `generate`: decodes a tag-501 CoRIM and emits a
    /// prose-keyed JSON template that feeds straight back into
    /// `generate`, reproducing the original bytes.
    Convert(convert::ConvertArgs),

    /// Extract the unsigned CoRIM payload from a signed CoRIM.
    ///
    /// Decodes a `#6.18` COSE_Sign1 CoRIM and writes the embedded
    /// `tagged-unsigned-corim-map` bytes. Errors on detached payloads.
    Extract(sign::ExtractArgs),

    /// Prepare and assemble a signed CoRIM (bring-your-own-signer).
    ///
    /// `sign prepare` emits a staging envelope + to-be-signed bytes; you
    /// sign externally; `sign finalize` injects the signature. No
    /// cryptography is performed by the tool.
    Sign(sign::SignArgs),
}

#[derive(Parser)]
struct ValidateArgs {
    /// Path to the CoRIM CBOR file. Use "-" or omit for stdin.
    #[arg(value_name = "FILE")]
    file: Option<String>,

    /// Output format.
    #[arg(short, long, default_value = "text", value_parser = ["text", "json"])]
    format: String,

    /// Skip clock comparisons but retain structural/profile checks. Successful
    /// output is partial validation, not confirmation of temporal validity.
    #[arg(long)]
    skip_expiry: bool,

    /// Show raw hex of tag payloads (CoMID/CoSWID/CoTL bytes) and,
    /// for signed CoRIMs, the four COSE_Sign1 sections (protected /
    /// unprotected / payload / signature).
    #[arg(long)]
    show_raw: bool,

    /// Run a non-aborting structural and profile-semantic diagnose pass and
    /// print a human-readable report (envelope kind, every recognized issue,
    /// summary). Useful when strict decoding fails and you need to see *all*
    /// problems at once.
    /// When set, the strict decode path is skipped; exit code is 0 if no
    /// errors are found, 2 otherwise.
    #[arg(long)]
    diagnose: bool,

    /// Render the input as CBOR Extended Diagnostic Notation (RFC 8949 §8).
    /// Bstr-wrapped CBOR at well-known CoRIM positions (concise-mid /
    /// concise-swid / concise-tl tags, COSE_Sign1 protected header and
    /// payload, corim-meta) is unwrapped using the `<<...>>` notation
    /// (RFC 8610 §G.4). Mutually exclusive with `--diagnose`.
    #[arg(long, conflicts_with = "diagnose")]
    edn: bool,

    /// Compare the input against a known-good **baseline** CoRIM for
    /// structural conformance. The baseline may be a CBOR CoRIM, a signed
    /// CoRIM (attached payload), or a JSON template. Reports structural
    /// mismatches (which fail) and value differences (informational).
    /// Exit code: 0 conformant, 3 structural mismatch, 2 invalid input.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["diagnose", "edn"])]
    baseline: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Validate(args) => run_validate(args),
        Commands::Generate(args) => generate::run(args),
        Commands::Convert(args) => convert::run(args),
        Commands::Extract(args) => sign::run_extract(args),
        Commands::Sign(args) => sign::run_sign(args),
    }
}

fn run_validate(cli: ValidateArgs) {
    let bytes = match input::read_input(cli.file.as_deref()) {
        Ok(b) => b,
        Err(e) => {
            let code = if e.kind() == std::io::ErrorKind::InvalidData && !cli.edn && !cli.diagnose {
                2
            } else {
                1
            };
            validation_failure(&cli.format, &format!("Error reading input: {e}"), code);
        }
    };

    if bytes.is_empty() {
        validation_failure(
            &cli.format,
            "input is empty",
            if cli.edn || cli.diagnose { 1 } else { 2 },
        );
    }

    // --edn: render the raw CBOR as Extended Diagnostic Notation and
    // exit. Runs on the *original* bytes (no compat peeling) so the
    // user sees the wire format as-is.
    if cli.edn {
        match edn::render(&bytes) {
            Ok(s) => {
                print!("{}", s);
                process::exit(0);
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
        }
    }

    // --diagnose: best-effort structural and profile-semantic inspection that
    // does NOT abort on the first error. Prints all issues, then exits.
    //
    // Note: --diagnose runs on the *original* bytes so the report can
    // explicitly call out legacy `#6.500` / `#6.502` outer wrappers.
    if cli.diagnose {
        // Register all first-party profiles enabled for this CLI build
        // so diagnose can label and validate profile-defined content.
        let registry = profiles::build_registry();
        let report = corim::diagnose::inspect(&bytes, &registry);
        print!("{}", report);
        process::exit(if report.error_count() == 0 { 0 } else { 2 });
    }

    let registry = profiles::build_registry();
    let now = if cli.skip_expiry {
        None
    } else {
        Some(validation::now().unwrap_or_else(|error| validation_failure(&cli.format, &error, 1)))
    };
    let document = validation::document(&bytes, now, &registry)
        .unwrap_or_else(|error| validation_failure(&cli.format, &error, 2));
    if document.legacy_wrappers {
        eprintln!("note: accepted legacy outer CBOR tag(s) #6.500 / #6.502");
    }
    let signed_info = document.signed.map(signed_info);
    let corim = document.payload.corim;
    let comid_tags = document.payload.comids;
    let profile_for_render = corim.profile.as_ref().and_then(|pc| registry.get(pc));
    let errors = Vec::new();
    let mut warnings = Vec::new();
    if cli.skip_expiry {
        warnings.push("partial validation: temporal checks skipped".into());
    }
    let mut coswid_count = 0;
    let mut cotl_count = 0;
    let mut unknown_count = 0;
    for (index, tag) in corim.tags.iter().enumerate() {
        use corim::types::ConciseTagChoice;
        match tag {
            ConciseTagChoice::Coswid(_) => coswid_count += 1,
            ConciseTagChoice::Cotl(_) => cotl_count += 1,
            ConciseTagChoice::Comid(_) => {}
            ConciseTagChoice::BareBstr(_) => {
                warnings.push(format!("tags[{index}]: TCG-style untagged CoMID"))
            }
            _ => {
                unknown_count += 1;
                warnings.push(format!("tags[{index}]: unknown tag type"));
            }
        }
    }

    // Baseline conformance mode: compare the (valid) input against a
    // known-good baseline and exit on the conformance result.
    if let Some(baseline_path) = &cli.baseline {
        match baseline::run(
            Some(&corim),
            signed_info.as_ref().map(|i| &i.protected),
            baseline_path,
            &cli.format,
            now,
        ) {
            Ok(true) => process::exit(0),
            Ok(false) => process::exit(3),
            Err(e) => {
                validation_failure(&cli.format, &e.to_string(), e.exit_code());
            }
        }
    }

    // Step 4: Output results
    match cli.format.as_str() {
        "json" => {
            print_json_output(
                &corim,
                &comid_tags,
                &errors,
                &warnings,
                &signed_info,
                cli.show_raw,
                !cli.skip_expiry,
            );
        }
        _ => {
            print_text_output(
                &corim,
                &comid_tags,
                &errors,
                &warnings,
                cli.show_raw,
                coswid_count,
                cotl_count,
                unknown_count,
                &signed_info,
                profile_for_render,
                !cli.skip_expiry,
            );
        }
    }
}

fn validation_failure(format: &str, error: &str, code: i32) -> ! {
    if format == "json" {
        println!(
            "{}",
            serde_json::json!({"valid":false,"time_validated":false,"errors":[error]})
        );
    } else {
        eprintln!("FAIL: {error}");
    }
    process::exit(code)
}

/// Information extracted from a signed CoRIM's COSE_Sign1 wrapper.
///
/// Mirrors the four elements of the RFC 9052 §4 `COSE_Sign1` array:
///   `[ protected, unprotected, payload, signature ]`
struct SignedInfo {
    // -- protected header (decoded fields + raw bstr) --
    alg: corim::types::signed::CoseAlgorithm,
    content_type: Option<String>,
    has_cwt_claims: bool,
    has_corim_meta: bool,
    x5chain_count: usize,
    has_x5t: bool,
    has_kid: bool,
    protected_header_bytes: Vec<u8>,
    /// Full decoded protected header (for `--baseline` header comparison
    /// and the metadata display lines).
    protected: corim::types::signed::ProtectedCorimHeaderMap,

    // -- unprotected header (re-encoded CBOR map) --
    unprotected_entries: usize,
    unprotected_bytes: Vec<u8>,

    // -- payload (raw bstr or nil) --
    is_detached: bool,
    payload_bytes: Vec<u8>,

    // -- signature (raw bstr) --
    signature: Vec<u8>,
}

fn signed_info(signed: corim::types::signed::CoseSign1Corim) -> SignedInfo {
    // Re-encode the unprotected header map so we can display its raw CBOR bytes
    // alongside the other COSE_Sign1 sections. Failures here are non-fatal —
    // an empty Vec just means we won't render bytes for that section.
    let unprotected_bytes =
        corim::cbor::encode(&corim::cbor::value::Value::Map(signed.unprotected.clone()))
            .unwrap_or_default();

    let info = SignedInfo {
        alg: signed.protected.alg,
        content_type: signed.protected.content_type.clone(),
        has_cwt_claims: signed.protected.cwt_claims.is_some(),
        has_corim_meta: signed.protected.corim_meta.is_some(),
        x5chain_count: signed
            .protected
            .x5chain
            .as_ref()
            .map(|x| x.certs().len())
            .unwrap_or(0),
        has_x5t: signed.protected.x5t.is_some(),
        has_kid: signed.protected.kid.is_some(),
        protected_header_bytes: signed.protected_header_bytes.clone(),
        protected: signed.protected.clone(),
        unprotected_entries: signed.unprotected.len(),
        unprotected_bytes,
        is_detached: signed.is_detached(),
        payload_bytes: signed.payload.clone().unwrap_or_default(),
        signature: signed.signature.clone(),
    };

    info
}

/// Render the four COSE_Sign1 elements per RFC 9052 §4:
///   `[ protected, unprotected, payload, signature ]`
///
/// `indent` is the leading whitespace for the section headers (sub-fields
/// are indented further to make the structure visually obvious).
///
/// When `show_raw` is true, each section is followed by a hex dump of its
/// raw CBOR bytes. Otherwise only summary metadata and section sizes are
/// shown to keep the default output readable.
fn print_cose_sign1(info: &SignedInfo, indent: &str, show_raw: bool) {
    let sub = format!("{}  ", indent);
    let hex_indent = format!("{}  ", sub);

    println!("{}═══ COSE_Sign1 (tag 18) ═══", indent);

    // [0] Protected header (bstr .cbor protected-corim-header-map)
    println!(
        "{}[0] Protected header  ({} bytes, bstr .cbor map)",
        indent,
        info.protected_header_bytes.len()
    );
    println!("{}Algorithm:    {}", sub, info.alg);
    if let Some(ref ct) = info.content_type {
        println!("{}Content-Type: {}", sub, ct);
    }
    if let Some(iss) = info.protected.cwt_claims.as_ref().map(|c| &c.iss) {
        println!("{}Issuer:       {}", sub, iss);
    }
    if let Some(subject) = info
        .protected
        .cwt_claims
        .as_ref()
        .and_then(|c| c.sub.as_ref())
    {
        println!("{}Subject:      {}", sub, subject);
    }
    if let Some(meta) = info.protected.corim_meta.as_ref() {
        println!("{}Signer name:  {}", sub, meta.signer.signer_name);
    }
    if let Some(claims) = info.protected.cwt_claims.as_ref() {
        if let Some(exp) = claims.exp {
            println!("{}Expires:      {} (epoch)", sub, exp);
        }
        if let Some(nbf) = claims.nbf {
            println!("{}Not before:   {} (epoch)", sub, nbf);
        }
        for (k, v) in &claims.extra {
            println!("{}CWT claim {}: {}", sub, k, display::value_summary(v));
        }
    }
    let metadata = match (info.has_cwt_claims, info.has_corim_meta) {
        (true, true) => "CWT-Claims + corim-meta",
        (true, false) => "CWT-Claims",
        (false, true) => "corim-meta",
        (false, false) => "(none)",
    };
    println!("{}Metadata:     {}", sub, metadata);
    if info.has_kid {
        println!("{}Key ID (kid): present", sub);
    }
    if info.x5chain_count > 0 {
        println!("{}X.509 chain:  {} certificate(s)", sub, info.x5chain_count);
    }
    if info.has_x5t {
        println!("{}X.509 thumbprint: present", sub);
    }
    if show_raw {
        println!("{}Raw bytes:", sub);
        display::print_hex_block(&info.protected_header_bytes, &hex_indent, 32);
    }

    // [1] Unprotected header (map)
    println!(
        "{}[1] Unprotected header  ({} entries, {} bytes)",
        indent,
        info.unprotected_entries,
        info.unprotected_bytes.len()
    );
    if show_raw {
        println!("{}Raw bytes:", sub);
        display::print_hex_block(&info.unprotected_bytes, &hex_indent, 32);
    }

    // [2] Payload (bstr / nil)
    if info.is_detached {
        println!(
            "{}[2] Payload  detached (nil) — inner CoRIM not embedded",
            indent
        );
    } else {
        println!(
            "{}[2] Payload  ({} bytes, bstr .cbor tagged-unsigned-corim-map)",
            indent,
            info.payload_bytes.len()
        );
        if show_raw {
            println!("{}Raw bytes:", sub);
            display::print_hex_block(&info.payload_bytes, &hex_indent, 32);
        }
    }

    // [3] Signature (bstr)
    println!("{}[3] Signature  ({} bytes)", indent, info.signature.len());
    if show_raw {
        println!("{}Raw bytes:", sub);
        display::print_hex_block(&info.signature, &hex_indent, 32);
    }
    println!(
        "{}note: signature is NOT cryptographically verified — this tool checks \
         structure only (no crypto dependency)",
        indent
    );
    println!();
}

#[allow(clippy::too_many_arguments)]
fn print_text_output(
    corim: &corim::types::corim::CorimMap,
    comids: &[corim::types::comid::ComidTag],
    errors: &[String],
    warnings: &[String],
    show_raw: bool,
    coswid_count: u32,
    cotl_count: u32,
    unknown_count: u32,
    signed_info: &Option<SignedInfo>,
    profile: Option<&(dyn corim::profile::Profile + Send + Sync)>,
    time_validated: bool,
) {
    // Validation result
    if errors.is_empty() && !time_validated {
        println!("PARTIAL: structural and profile checks passed; temporal checks skipped\n");
    } else if errors.is_empty() {
        println!("PASS: structural, temporal and profile checks passed\n");
    } else {
        println!("✗ CoRIM validation failed\n");
        for e in errors {
            println!("  ERROR: {}", e);
        }
        println!();
    }

    println!("Cryptographic verification was not performed.");
    for w in warnings {
        println!("  WARNING: {}", w);
    }
    if !warnings.is_empty() {
        println!();
    }

    // CoRIM header
    println!("═══ CoRIM Map ═══");

    // Show signed CoRIM info if present (four COSE_Sign1 sections)
    if let Some(ref info) = signed_info {
        print_cose_sign1(info, "  ", show_raw);
    }

    display::print_corim(corim, show_raw);

    // Tag summary
    println!(
        "\n  Tags: {} total ({} CoMID, {} CoSWID, {} CoTL, {} unknown)",
        corim.tags.len(),
        comids.len(),
        coswid_count,
        cotl_count,
        unknown_count,
    );

    // Each CoMID
    for (i, comid) in comids.iter().enumerate() {
        println!("\n  ─── CoMID [{}] ───", i);
        display::print_comid(comid, "    ", show_raw, profile);
    }

    println!();
}

fn print_json_output(
    corim: &corim::types::corim::CorimMap,
    comids: &[corim::types::comid::ComidTag],
    errors: &[String],
    warnings: &[String],
    signed_info: &Option<SignedInfo>,
    _show_raw: bool,
    time_validated: bool,
) {
    // Simple JSON output without pulling in serde_json
    println!("{{");
    println!(
        "  \"valid\": {},",
        if !errors.is_empty() {
            "false"
        } else if time_validated {
            "true"
        } else {
            "null"
        }
    );
    println!("  \"time_validated\": {},", time_validated);

    if !errors.is_empty() {
        println!("  \"errors\": [");
        for (i, e) in errors.iter().enumerate() {
            let comma = if i + 1 < errors.len() { "," } else { "" };
            println!("    \"{}\"{}", jsonfmt::escape(e), comma);
        }
        println!("  ],");
    }

    if !warnings.is_empty() {
        println!("  \"warnings\": [");
        for (i, w) in warnings.iter().enumerate() {
            let comma = if i + 1 < warnings.len() { "," } else { "" };
            println!("    \"{}\"{}", jsonfmt::escape(w), comma);
        }
        println!("  ],");
    }

    if let Some(info) = signed_info {
        print_signed_json(info, "  ", true);
    }

    println!("  \"id\": {},", display::corim_id_json(&corim.id));
    println!("  \"tags_count\": {},", corim.tags.len());
    println!("  \"comid_count\": {},", comids.len());

    if let Some(ref profile) = corim.profile {
        println!(
            "  \"profile\": \"{}\",",
            jsonfmt::escape(&display::profile_str(profile))
        );
    }

    // CoMIDs summary
    println!("  \"comids\": [");
    for (i, comid) in comids.iter().enumerate() {
        let comma = if i + 1 < comids.len() { "," } else { "" };
        println!("    {{");
        println!(
            "      \"tag_id\": {},",
            display::tag_id_json(&comid.tag_identity.tag_id)
        );
        if let Some(v) = comid.tag_identity.tag_version {
            println!("      \"tag_version\": {},", v);
        }
        let triple_types = display::triple_type_list(&comid.triples);
        println!("      \"triple_types\": [{}]", triple_types);
        println!("    }}{}", comma);
    }
    println!("  ]");

    println!("}}");
}

/// Emit the `"signed"` object, mirroring the fields the text renderer shows
/// for the four COSE_Sign1 elements (RFC 9052 §4).
fn print_signed_json(info: &SignedInfo, indent: &str, comma: bool) {
    let p = &info.protected;
    println!("{indent}\"signed\": {{");
    println!(
        "{indent}  \"tag\": {},",
        corim::types::tags::TAG_SIGNED_CORIM
    );

    println!(
        "{indent}  \"protected\": {},",
        jsonfmt::protected_header(p, info.protected_header_bytes.len(), &format!("{indent}  "))
    );

    println!(
        "{indent}  \"unprotected\": {{ \"entries\": {}, \"size\": {} }},",
        info.unprotected_entries,
        info.unprotected_bytes.len()
    );
    if info.is_detached {
        println!("{indent}  \"payload\": {{ \"detached\": true }},");
    } else {
        println!(
            "{indent}  \"payload\": {{ \"detached\": false, \"size\": {} }},",
            info.payload_bytes.len()
        );
    }
    println!(
        "{indent}  \"signature\": {{ \"size\": {} }},",
        info.signature.len()
    );
    // Structure-only tool: the signature is never checked.
    println!("{indent}  \"signature_verified\": false");

    println!("{indent}}}{}", if comma { "," } else { "" });
}
