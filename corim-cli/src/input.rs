// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bounded input for untrusted CLI documents and auxiliary signing files.

use std::fs::File;
use std::io::{self, Read};

/// Read at most the default document limit plus one byte, including for pipes
/// and files whose metadata does not describe their eventual length.
fn read_bounded(reader: impl Read) -> io::Result<Vec<u8>> {
    let limit = corim::cbor::DecodeLimits::default().max_input_bytes;
    let take = u64::try_from(limit)
        .ok()
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| io::Error::other("input limit is too large"))?;
    let mut bytes = Vec::new();
    reader.take(take).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("input exceeds maximum size of {limit} bytes (16 MiB)"),
        ));
    }
    Ok(bytes)
}

/// Read a literal file path (including a file named `-`).
pub(crate) fn read_file(path: &str) -> io::Result<Vec<u8>> {
    read_bounded(File::open(path)?)
}

/// Read a document from a file, or stdin for an omitted path or `-`.
pub(crate) fn read_input(path: Option<&str>) -> io::Result<Vec<u8>> {
    match path {
        Some(p) if p != "-" => read_file(p),
        _ => read_bounded(io::stdin().lock()),
    }
}

/// Preserve the shared `reading <source>` diagnostic used by subcommands.
pub(crate) fn read_document(path: Option<&str>) -> Result<Vec<u8>, String> {
    read_input(path).map_err(|e| {
        let source = path.filter(|p| *p != "-").unwrap_or("stdin");
        format!("reading {source}: {e}")
    })
}
