// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Raw CBOR inspection/transcoding. No signature or document validation is
//! performed and no legacy wrappers, protected bytes, or payloads are changed.
//! Known embedded CBOR boundaries share the root's resource and framing budget.

use clap::Parser;
use std::{fs, process};

#[derive(Parser)]
pub struct ConvertArgs {
    /// CBOR input (including full signed or detached envelopes); "-" or omit for stdin.
    #[arg(value_name = "FILE")]
    file: Option<String>,
    /// Output path for lossless JSON. Defaults to stdout.
    #[arg(short, long, value_name = "FILE")]
    output: Option<String>,
}

/// Entry point for raw lossless JSON conversion.
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
    let json = corim::json::to_json_pretty(&root).map_err(|e| format!("encoding JSON: {e}"))?;
    match args.output {
        Some(path) => {
            fs::write(&path, format!("{json}\n")).map_err(|e| format!("writing {path}: {e}"))?;
            eprintln!("Wrote lossless JSON: {path}");
        }
        None => println!("{json}"),
    }
    Ok(())
}
