// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Readable, prose-keyed authoring projection. The library JSON codec
//! remains the strict lossless wire representation.

#[path = "authoring/decode.rs"]
mod decode;
#[path = "authoring/encode.rs"]
mod encode;
#[path = "authoring/key_maps.rs"]
mod key_maps;
#[path = "authoring/value_conv.rs"]
mod value_conv;

use std::io::{self, Write};

pub(crate) use decode::to_template;
pub(crate) use encode::encode_template;

/// Serialize native authoring JSON, including its final newline, within
/// the same default document budget as the lossless codec.
pub(crate) fn to_json_pretty(template: &serde_json::Value) -> Result<String, String> {
    pretty_with_limit(template, corim::json::DEFAULT_MAX_JSON_BYTES)
}

fn pretty_with_limit(template: &serde_json::Value, limit: usize) -> Result<String, String> {
    let mut writer = CappedWriter {
        bytes: Vec::new(),
        limit: limit.saturating_sub(1),
    };
    serde_json::to_writer_pretty(&mut writer, template)
        .map_err(|e| format!("serializing readable template (default 16 MiB limit): {e}"))?;
    writer.bytes.push(b'\n');
    String::from_utf8(writer.bytes).map_err(|e| format!("serializing readable template: {e}"))
}

fn check_json_budget(template: &serde_json::Value) -> Result<(), String> {
    let mut writer = CappedWriter {
        bytes: Vec::new(),
        limit: corim::json::DEFAULT_MAX_JSON_BYTES,
    };
    serde_json::to_writer(&mut writer, template)
        .map_err(|e| format!("readable template exceeds the default 16 MiB JSON limit: {e}"))
}

struct CappedWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for CappedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("JSON output exceeds document limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "authoring/tests.rs"]
mod tests;
