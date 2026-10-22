// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Readable authoring output by default, explicit lossless interchange on request.
//! Known embedded CBOR boundaries share a resource/framing preflight; neither
//! format authenticates signatures.

use clap::Parser;
use std::io::Write;
use std::{fs, process};

#[derive(Parser)]
pub struct ConvertArgs {
    /// CBOR input; "-" or omit for stdin. Detached/hash envelopes require --lossless.
    #[arg(value_name = "FILE")]
    file: Option<String>,
    /// Output path for JSON. Defaults to stdout.
    #[arg(short, long, value_name = "FILE")]
    output: Option<String>,
    /// Preserve the full raw document, including signed or detached envelopes,
    /// instead of projecting an unsigned readable authoring template.
    #[arg(long)]
    lossless: bool,
}

/// Entry point for JSON conversion.
pub fn run(args: ConvertArgs) {
    if let Err(error) = run_impl(args) {
        eprintln!("Error: {error}");
        process::exit(1);
    }
}

fn run_impl(args: ConvertArgs) -> Result<(), String> {
    let bytes = crate::input::read_document(args.file.as_deref())?;
    let root = corim::document::inspect(&bytes, &corim::cbor::DecodeLimits::default())
        .map_err(|e| format!("decoding CBOR: {e}"))?;
    let json = if args.lossless {
        let mut json =
            corim::json::to_json_pretty(&root).map_err(|e| format!("encoding JSON: {e}"))?;
        let limit = corim::json::DEFAULT_MAX_JSON_BYTES;
        if json.len() >= limit {
            return Err(format!(
                "lossless JSON output including trailing newline exceeds maximum size of {limit} bytes"
            ));
        }
        json.try_reserve_exact(1)
            .map_err(|e| format!("allocating JSON newline: {e}"))?;
        json.push('\n');
        json
    } else {
        let template = crate::authoring::to_template(&bytes)?;
        crate::authoring::to_json_pretty(&template)?
    };
    match args.output {
        Some(path) => {
            fs::write(&path, &json).map_err(|e| format!("writing {path}: {e}"))?;
            eprintln!(
                "Wrote {}: {path}",
                if args.lossless {
                    "lossless JSON"
                } else {
                    "readable template"
                }
            );
        }
        None => std::io::stdout()
            .lock()
            .write_all(json.as_bytes())
            .map_err(|e| format!("writing stdout: {e}"))?,
    }
    Ok(())
}
