# corim-macros

Proc-macro derive crate for the [`corim`](https://crates.io/crates/corim) crate.

Provides `CborSerialize` and `CborDeserialize` derive macros for
integer-keyed CBOR map serialization per RFC 8949 §4.2.1 deterministic
encoding.

## ⚠️ Do not depend on this crate directly

This is an internal implementation detail of the `corim` crate. Add `corim`
to your dependencies instead — it re-exports everything you need:

```toml
[dependencies]
corim = "0.1"
```

## What the derives do

```rust
use corim_macros::{CborSerialize, CborDeserialize};

#[derive(CborSerialize, CborDeserialize)]
pub struct MyMap {
    #[cbor(key = 0)]
    pub id: String,
    #[cbor(key = 1, optional)]
    pub version: Option<u64>,
}
```

This generates `Serialize`/`Deserialize` impls that encode `MyMap` as a
CBOR map with integer keys `{0: "...", 1: ...}`, with canonical key
ordering and `non-empty` constraint support.

Use `#[cbor(key = N, optional, non_null)]` when an omitted field is allowed
but a present field must deserialize as its inner `T`, rather than as
`Option<T>`. For null-rejecting types such as `bool` and the measurement
matchers, this rejects an explicit CBOR `null` while preserving absence.
It does not override the inner type's own accepted values. Ordinary
`optional` fields retain their existing null-as-absence behavior.

## License

[MIT](https://github.com/Azure/corim/blob/main/LICENSE)
