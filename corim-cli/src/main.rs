// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CLI tool for validating and inspecting CoRIM documents.

use std::fs;
use std::io::{self, Read};
use std::process;

use clap::Parser;

mod display;

/// Validate and inspect CoRIM (Concise Reference Integrity Manifest) documents.
///
/// Reads a CBOR-encoded CoRIM file (tag-501-wrapped), validates its structure
/// against draft-ietf-rats-corim-10, and outputs the decoded structure.
#[derive(Parser)]
#[command(name = "corim-cli", version, about)]
struct Cli {
    /// Path to the CoRIM CBOR file. Use "-" or omit for stdin.
    #[arg(value_name = "FILE")]
    file: Option<String>,

    /// Output format.
    #[arg(short, long, default_value = "text", value_parser = ["text", "json"])]
    format: String,

    /// Skip validity-period expiration check.
    #[arg(long)]
    skip_expiry: bool,

    /// Show raw hex of tag payloads (CoMID/CoSWID/CoTL bytes) and,
    /// for signed CoRIMs, the four COSE_Sign1 sections (protected /
    /// unprotected / payload / signature).
    #[arg(long)]
    show_raw: bool,

    /// Run a non-aborting structural diagnose pass and print a human-readable
    /// report (envelope kind, every recognized issue, summary). Useful when
    /// strict decoding fails and you need to see *all* problems at once.
    /// When set, the strict decode path is skipped; exit code is 0 if no
    /// errors are found, 2 otherwise.
    #[arg(long)]
    diagnose: bool,
}

fn main() {
    let cli = Cli::parse();

    let bytes = match read_input(&cli.file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error reading input: {}", e);
            process::exit(1);
        }
    };

    if bytes.is_empty() {
        eprintln!("Error: input is empty");
        process::exit(1);
    }

    // --diagnose: best-effort structural inspection that does NOT abort on
    // the first error. Prints all issues, then exits.
    //
    // Note: --diagnose runs on the *original* bytes so the report can
    // explicitly call out legacy `#6.500` / `#6.502` outer wrappers.
    if cli.diagnose {
        // CLI has no profile registry of its own; pass an empty registry
        // so the walker treats every mval extension key with the generic
        // "extension key {N}" label. Applications embedding the diagnose
        // module can build a registry and pass it directly.
        //
        // When built with `--features intel`, register the Intel profile
        // so Intel tee.* mval keys are labelled by their spec names.
        #[allow(unused_mut)]
        let mut registry = corim::profile::ProfileRegistry::new();
        #[cfg(feature = "intel")]
        registry.register(Box::new(corim::profile::intel::IntelProfile::new()));
        let report = corim::diagnose::inspect(&bytes, &registry);
        print!("{}", report);
        process::exit(if report.error_count() == 0 { 0 } else { 2 });
    }

    // Decode interop: peel legacy `#6.500` / `#6.502` outer wrappers
    // (TCG Endorsement spec / NVIDIA producers) before format detection,
    // so the `0xD2`-first-byte check below sees the inner #6.18.
    let bytes: Vec<u8> = match corim::compat::peel_tcg_wrappers(&bytes) {
        Ok(p) => {
            if p.was_peeled() {
                eprintln!(
                    "note: stripped legacy outer CBOR tag(s) #6.500 / #6.502 \
(TCG Endorsement spec / pre-draft-10 producer)"
                );
            }
            p.as_bytes().to_vec()
        }
        Err(e) => {
            eprintln!("FAIL: legacy-wrapper peel failed: {}", e);
            process::exit(2);
        }
    };

    // Step 1: Detect format — try signed CoRIM (tag 18) first, then unsigned (tag 501)
    let (corim, signed_info) = match try_decode_signed(&bytes) {
        Some(result) => match result {
            Ok((corim_map, info)) => (Some(corim_map), Some(info)),
            Err(SignedDecodeResult::HeaderOnly(info)) => {
                // Signed CoRIM decoded but payload is detached/non-standard.
                // Show header info only.
                print_signed_header_only(&info, cli.show_raw);
                process::exit(0);
            }
            Err(SignedDecodeResult::Failed(e)) => {
                eprintln!("FAIL: Detected signed CoRIM (tag 18) but decode failed");
                eprintln!("  Error: {}", e);
                process::exit(2);
            }
        },
        None => {
            // Try unsigned CoRIM (tag 501)
            let tagged: corim::cbor::value::Tagged<corim::types::corim::CorimMap> =
                match corim::cbor::decode(&bytes) {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("FAIL: Cannot decode as CoRIM");
                        eprintln!("  Not a signed CoRIM (tag 18) or unsigned CoRIM (tag 501)");
                        eprintln!("  CBOR decode error: {}", e);
                        process::exit(2);
                    }
                };

            if tagged.tag != corim::types::tags::TAG_CORIM {
                eprintln!(
                    "FAIL: Expected CBOR tag {} (unsigned) or {} (signed), found tag {}",
                    corim::types::tags::TAG_CORIM,
                    corim::types::tags::TAG_SIGNED_CORIM,
                    tagged.tag
                );
                process::exit(2);
            }
            (Some(tagged.value), None)
        }
    };

    let corim = corim.unwrap(); // safe: HeaderOnly case already exited above

    // Step 2: Structural validation
    let mut warnings: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    // Check rim-validity
    if let Some(ref validity) = corim.rim_validity {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        if let Some(nb) = validity.not_before {
            if now < nb.epoch_secs() && !cli.skip_expiry {
                warnings.push(format!(
                    "rim-validity.not-before ({}) is in the future",
                    nb.epoch_secs()
                ));
            }
        }

        if validity.not_after.epoch_secs() < now && !cli.skip_expiry {
            errors.push(format!(
                "rim-validity.not-after ({}) is in the past — CoRIM is expired",
                validity.not_after.epoch_secs()
            ));
        }
    }

    if corim.tags.is_empty() {
        errors.push("tags array is empty — at least one tag is required".into());
    }

    // Step 3: Decode and validate each tag
    let mut comid_tags: Vec<corim::types::comid::ComidTag> = Vec::new();
    let mut coswid_count = 0u32;
    let mut cotl_count = 0u32;
    let mut unknown_count = 0u32;

    for (i, tag) in corim.tags.iter().enumerate() {
        match tag {
            corim::types::corim::ConciseTagChoice::Comid(comid_bytes) => {
                match corim::cbor::decode::<corim::types::comid::ComidTag>(comid_bytes) {
                    Ok(comid) => {
                        // Validate triples non-empty
                        let t = &comid.triples;
                        let has_triples = t.reference_triples.is_some()
                            || t.endorsed_triples.is_some()
                            || t.identity_triples.is_some()
                            || t.attest_key_triples.is_some()
                            || t.dependency_triples.is_some()
                            || t.membership_triples.is_some()
                            || t.coswid_triples.is_some()
                            || t.conditional_endorsement_series.is_some()
                            || t.conditional_endorsement.is_some();

                        if !has_triples {
                            errors.push(format!("tags[{}] (CoMID): triples-map is empty", i));
                        }
                        comid_tags.push(comid);
                    }
                    Err(e) => {
                        errors.push(format!(
                            "tags[{}] (CoMID): failed to decode inner CBOR — {}",
                            i, e
                        ));
                    }
                }
            }
            corim::types::corim::ConciseTagChoice::Coswid(_) => coswid_count += 1,
            corim::types::corim::ConciseTagChoice::Cotl(_) => cotl_count += 1,
            corim::types::corim::ConciseTagChoice::Unknown(tag_num, _) => {
                warnings.push(format!("tags[{}]: unknown tag type {}", i, tag_num));
                unknown_count += 1;
            }
            corim::types::corim::ConciseTagChoice::BareBstr(bstr) => {
                // TCG-style interop: producers omit the outer `#6.506(bstr)`
                // wrapping. Use the compat helper to surface the inner CoMID.
                warnings.push(format!(
                    "tags[{}]: bare bstr ({} bytes) — TCG-style untagged CoMID; \
decoded via compat::decode_comid_from_tcg_bstr",
                    i,
                    bstr.len()
                ));
                match corim::compat::decode_comid_from_tcg_bstr(bstr) {
                    Ok(comid) => comid_tags.push(comid),
                    Err(e) => errors.push(format!(
                        "tags[{}] (BareBstr): failed to decode as CoMID — {}",
                        i, e
                    )),
                }
            }
            _ => {
                warnings.push(format!("tags[{}]: unrecognized tag variant", i));
                unknown_count += 1;
            }
        }
    }

    // Step 4: Output results
    match cli.format.as_str() {
        "json" => {
            print_json_output(&corim, &comid_tags, &errors, &warnings, cli.show_raw);
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
            );
        }
    }

    if !errors.is_empty() {
        process::exit(2);
    }
}

/// Information extracted from a signed CoRIM's COSE_Sign1 wrapper.
///
/// Mirrors the four elements of the RFC 9052 §4 `COSE_Sign1` array:
///   `[ protected, unprotected, payload, signature ]`
struct SignedInfo {
    // -- protected header (decoded fields + raw bstr) --
    alg: corim::types::signed::CoseAlgorithm,
    signer_name: Option<String>,
    content_type: Option<String>,
    has_cwt_claims: bool,
    has_corim_meta: bool,
    x5chain_count: usize,
    has_x5t: bool,
    has_kid: bool,
    protected_header_bytes: Vec<u8>,

    // -- unprotected header (re-encoded CBOR map) --
    unprotected_entries: usize,
    unprotected_bytes: Vec<u8>,

    // -- payload (raw bstr or nil) --
    is_detached: bool,
    payload_bytes: Vec<u8>,

    // -- signature (raw bstr) --
    signature: Vec<u8>,
}

/// Result when signed CoRIM decode partially fails.
enum SignedDecodeResult {
    /// Protected header decoded but payload is absent/non-standard.
    HeaderOnly(SignedInfo),
    /// Complete failure.
    Failed(String),
}

/// Try to decode the bytes as a signed CoRIM (tag 18).
/// Returns `None` if the first byte doesn't indicate tag 18 (0xD2).
/// Returns `Some(Ok(...))` on success or `Some(Err(...))` on decode failure.
fn try_decode_signed(
    bytes: &[u8],
) -> Option<Result<(corim::types::corim::CorimMap, SignedInfo), SignedDecodeResult>> {
    // Quick check: tag 18 starts with 0xD2
    if bytes.first() != Some(&0xD2) {
        return None;
    }

    let signed = match corim::types::signed::decode_signed_corim(bytes) {
        Ok(s) => s,
        Err(e) => return Some(Err(SignedDecodeResult::Failed(format!("{}", e)))),
    };

    let signer_name = signed
        .protected
        .cwt_claims
        .as_ref()
        .map(|c| c.iss.clone())
        .or_else(|| {
            signed
                .protected
                .corim_meta
                .as_ref()
                .map(|m| m.signer.signer_name.clone())
        });

    // Re-encode the unprotected header map so we can display its raw CBOR bytes
    // alongside the other COSE_Sign1 sections. Failures here are non-fatal —
    // an empty Vec just means we won't render bytes for that section.
    let unprotected_bytes =
        corim::cbor::encode(&corim::cbor::value::Value::Map(signed.unprotected.clone()))
            .unwrap_or_default();

    let info = SignedInfo {
        alg: signed.protected.alg,
        signer_name,
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
        unprotected_entries: signed.unprotected.len(),
        unprotected_bytes,
        is_detached: signed.is_detached(),
        payload_bytes: signed.payload.clone().unwrap_or_default(),
        signature: signed.signature.clone(),
    };

    let payload = match &signed.payload {
        Some(p) => p,
        None => return Some(Err(SignedDecodeResult::HeaderOnly(info))),
    };

    // Decode interop: TCG-style producers (e.g. NVIDIA) emit the inner CoRIM
    // as a bare `corim-map` instead of `#6.501(corim-map)`. Wrap if needed
    // so the strict decode below sees the spec-compliant tagged form.
    let payload_for_decode = corim::compat::wrap_bare_corim_map(payload);
    let payload_bytes = payload_for_decode.as_bytes();

    // Decode the inner CoRIM from the (possibly synthesized) tagged payload
    let tagged: corim::cbor::value::Tagged<corim::types::corim::CorimMap> =
        match corim::cbor::decode(payload_bytes) {
            Ok(t) => t,
            Err(_) => return Some(Err(SignedDecodeResult::HeaderOnly(info))),
        };

    if tagged.tag != corim::types::tags::TAG_CORIM {
        return Some(Err(SignedDecodeResult::HeaderOnly(info)));
    }

    Some(Ok((tagged.value, info)))
}

/// Print signed CoRIM header info when the inner payload can't be decoded.
fn print_signed_header_only(info: &SignedInfo, show_raw: bool) {
    println!("✓ Signed CoRIM (tag 18) — header decoded\n");
    print_cose_sign1(info, "  ", show_raw);
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
    if let Some(ref name) = info.signer_name {
        println!("{}Signer:       {}", sub, name);
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
    println!();
}

fn read_input(path: &Option<String>) -> io::Result<Vec<u8>> {
    match path {
        Some(p) if p != "-" => fs::read(p),
        _ => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            Ok(buf)
        }
    }
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
) {
    // Validation result
    if errors.is_empty() {
        println!("✓ CoRIM is valid\n");
    } else {
        println!("✗ CoRIM validation failed\n");
        for e in errors {
            println!("  ERROR: {}", e);
        }
        println!();
    }

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
        display::print_comid(comid, "    ", show_raw);
    }

    println!();
}

fn print_json_output(
    corim: &corim::types::corim::CorimMap,
    comids: &[corim::types::comid::ComidTag],
    errors: &[String],
    warnings: &[String],
    _show_raw: bool,
) {
    // Simple JSON output without pulling in serde_json
    println!("{{");
    println!("  \"valid\": {},", errors.is_empty());

    if !errors.is_empty() {
        println!("  \"errors\": [");
        for (i, e) in errors.iter().enumerate() {
            let comma = if i + 1 < errors.len() { "," } else { "" };
            println!("    \"{}\"{}", json_escape(e), comma);
        }
        println!("  ],");
    }

    if !warnings.is_empty() {
        println!("  \"warnings\": [");
        for (i, w) in warnings.iter().enumerate() {
            let comma = if i + 1 < warnings.len() { "," } else { "" };
            println!("    \"{}\"{}", json_escape(w), comma);
        }
        println!("  ],");
    }

    println!("  \"id\": {},", display::corim_id_json(&corim.id));
    println!("  \"tags_count\": {},", corim.tags.len());
    println!("  \"comid_count\": {},", comids.len());

    if let Some(ref profile) = corim.profile {
        println!(
            "  \"profile\": \"{}\",",
            json_escape(&display::profile_str(profile))
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

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
