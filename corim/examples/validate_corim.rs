// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Example: decode and validate a CoRIM from a CBOR file.

use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();
    let path = args.get(1).expect("Usage: validate_corim <file.cbor>");

    let bytes = fs::read(path).expect("failed to read file");
    println!("Read {} bytes from {}", bytes.len(), path);

    match corim::validate::decode_and_validate(&bytes) {
        Ok((corim, comids)) => {
            println!("✓ CoRIM is valid");
            println!("  id: {}", corim.id);
            if let Some(ref p) = corim.profile {
                println!("  profile: {}", p);
            }
            println!("  tags: {}", corim.tags.len());
            for (i, comid) in comids.iter().enumerate() {
                println!("  CoMID[{}]: tag-id={}", i, comid.tag_identity.tag_id);
            }
        }
        Err(e) => {
            eprintln!("✗ Validation failed: {}", e);
            std::process::exit(1);
        }
    }
}
