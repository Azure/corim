// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::error::EncodeError;
use std::io::{self, Write};

pub(super) fn encode(
    value: &serde_json::Value,
    pretty: bool,
    limit: usize,
) -> Result<String, EncodeError> {
    let mut writer = CappedWriter {
        bytes: Vec::new(),
        limit,
    };
    if pretty {
        serde_json::to_writer_pretty(&mut writer, value)
    } else {
        serde_json::to_writer(&mut writer, value)
    }
    .map_err(|error| EncodeError::Serialization(error.to_string()))?;
    String::from_utf8(writer.bytes).map_err(|error| EncodeError::Serialization(error.to_string()))
}

struct CappedWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for CappedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit - self.bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "lossless JSON output exceeds maximum size of {} bytes",
                    self.limit
                ),
            ));
        }
        let length = self.bytes.len() + bytes.len();
        if length > self.bytes.capacity() {
            // Vec's ordinary geometric growth may reserve beyond the cap.
            let capacity = self
                .bytes
                .capacity()
                .saturating_mul(2)
                .max(length)
                .min(self.limit);
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(io::Error::other)?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn compact_and_pretty_serialization_include_escaping_in_exact_limit() {
        let value = json!(["\n\"\\", {"text": "é"}]);
        for pretty in [false, true] {
            let expected = if pretty {
                serde_json::to_string_pretty(&value).unwrap()
            } else {
                serde_json::to_string(&value).unwrap()
            };
            assert_eq!(encode(&value, pretty, expected.len()).unwrap(), expected);
            assert!(encode(&value, pretty, expected.len() - 1).is_err());
        }
    }

    #[test]
    fn rejected_chunks_do_not_allocate_or_append_past_limit() {
        let mut writer = CappedWriter {
            bytes: Vec::new(),
            limit: 13,
        };
        writer.write_all(b"1234567").unwrap();
        assert!(writer.write_all(b"8901234").is_err());
        assert_eq!(writer.bytes, b"1234567");
        writer.write_all(b"890123").unwrap();
        assert_eq!(writer.bytes.len(), 13);
        assert!(writer.bytes.capacity() <= 13);
        assert!(writer.write_all(b"x").is_err());
        assert_eq!(writer.bytes, b"1234567890123");
    }
}
