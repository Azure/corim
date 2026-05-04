// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! COSE signing algorithm identifiers per IANA "COSE Algorithms" registry,
//! updated by [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html).

#[allow(unused_imports)]
use crate::nostd_prelude::*;

// ===================================================================
// COSE Algorithm Identifiers (IANA "COSE Algorithms" registry)
// Updated per RFC 9864 — fully-specified algorithm identifiers.
// ===================================================================

/// COSE signing algorithm identifier per
/// [IANA COSE Algorithms](https://www.iana.org/assignments/cose/cose.xhtml#algorithms),
/// updated by [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html).
///
/// RFC 9864 deprecates polymorphic algorithm identifiers (ES256, ES384,
/// ES512, EdDSA) and defines fully-specified replacements (ESP256, ESP384,
/// ESP512, Ed25519, Ed448). The deprecated variants are retained for
/// decode interop with existing signed CoRIM documents in the wild and
/// are documented as deprecated in their per-variant doc-comments below.
/// They are intentionally **not** annotated with `#[deprecated]` so that
/// downstream code parsing real-world ES256/EdDSA-signed CoRIMs does not
/// emit spurious warnings. Use [`is_deprecated`](Self::is_deprecated) to
/// check at runtime.
///
/// Used in the `alg` (key 1) field of the COSE_Sign1 protected header.
/// The `Unknown` variant provides forward compatibility with algorithm
/// identifiers not yet modeled here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CoseAlgorithm {
    // --- Fully-specified algorithms (RFC 9864 §2) ---
    /// ESP256 (-9) — ECDSA using P-256 curve and SHA-256. Replaces ES256.
    Esp256,
    /// Ed25519 (-19) — EdDSA using the Ed25519 parameter set. Replaces EdDSA.
    Ed25519,
    /// PS256 (-37) — RSASSA-PSS w/ SHA-256.
    Ps256,
    /// PS384 (-38) — RSASSA-PSS w/ SHA-384.
    Ps384,
    /// PS512 (-39) — RSASSA-PSS w/ SHA-512.
    Ps512,
    /// ESP384 (-51) — ECDSA using P-384 curve and SHA-384. Replaces ES384.
    Esp384,
    /// ESP512 (-52) — ECDSA using P-521 curve and SHA-512. Replaces ES512.
    Esp512,
    /// Ed448 (-53) — EdDSA using the Ed448 parameter set. Replaces EdDSA.
    Ed448,

    // --- Deprecated polymorphic algorithms (RFC 9864 §4.2.2) ---
    // Retained for decode interop with existing signed CoRIM documents.
    /// ES256 (-7) — **Deprecated per RFC 9864.** Use [`Esp256`](Self::Esp256).
    Es256,
    /// EdDSA (-8) — **Deprecated per RFC 9864.** Use [`Ed25519`](Self::Ed25519) or [`Ed448`](Self::Ed448).
    EdDsa,
    /// ES384 (-35) — **Deprecated per RFC 9864.** Use [`Esp384`](Self::Esp384).
    Es384,
    /// ES512 (-36) — **Deprecated per RFC 9864.** Use [`Esp512`](Self::Esp512).
    Es512,

    /// An algorithm identifier not explicitly modeled above.
    Unknown(i64),
}

impl CoseAlgorithm {
    /// Convert from the IANA integer identifier.
    pub fn from_i64(n: i64) -> Self {
        match n {
            -7 => Self::Es256,
            -8 => Self::EdDsa,
            -9 => Self::Esp256,
            -19 => Self::Ed25519,
            -35 => Self::Es384,
            -36 => Self::Es512,
            -37 => Self::Ps256,
            -38 => Self::Ps384,
            -39 => Self::Ps512,
            -51 => Self::Esp384,
            -52 => Self::Esp512,
            -53 => Self::Ed448,
            other => Self::Unknown(other),
        }
    }

    /// Convert to the IANA integer identifier.
    pub fn to_i64(self) -> i64 {
        match self {
            Self::Es256 => -7,
            Self::EdDsa => -8,
            Self::Esp256 => -9,
            Self::Ed25519 => -19,
            Self::Es384 => -35,
            Self::Es512 => -36,
            Self::Ps256 => -37,
            Self::Ps384 => -38,
            Self::Ps512 => -39,
            Self::Esp384 => -51,
            Self::Esp512 => -52,
            Self::Ed448 => -53,
            Self::Unknown(n) => n,
        }
    }

    /// Human-readable name for display.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Esp256 => "ESP256",
            Self::Ed25519 => "Ed25519",
            Self::Ps256 => "PS256",
            Self::Ps384 => "PS384",
            Self::Ps512 => "PS512",
            Self::Esp384 => "ESP384",
            Self::Esp512 => "ESP512",
            Self::Ed448 => "Ed448",
            Self::Es256 => "ES256 (deprecated)",
            Self::EdDsa => "EdDSA (deprecated)",
            Self::Es384 => "ES384 (deprecated)",
            Self::Es512 => "ES512 (deprecated)",
            Self::Unknown(_) => "Unknown",
        }
    }

    /// Returns `true` if this algorithm is deprecated per RFC 9864.
    pub fn is_deprecated(&self) -> bool {
        matches!(self, Self::Es256 | Self::EdDsa | Self::Es384 | Self::Es512)
    }
}

impl core::fmt::Display for CoseAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unknown(n) => write!(f, "Unknown({})", n),
            _ => write!(f, "{} ({})", self.name(), self.to_i64()),
        }
    }
}

impl From<i64> for CoseAlgorithm {
    fn from(n: i64) -> Self {
        Self::from_i64(n)
    }
}

impl From<CoseAlgorithm> for i64 {
    fn from(alg: CoseAlgorithm) -> Self {
        alg.to_i64()
    }
}
