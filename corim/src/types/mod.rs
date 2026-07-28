// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CDDL-derived Rust types for CoRIM / CoMID.
//!
//! The type hierarchy mirrors the CDDL productions in `corim.cddl`.
//! Map types use `CborSerialize`/`CborDeserialize` derives for integer-keyed
//! CBOR encoding. Array types (triple records) use standard serde derives.

#[allow(unused_imports)]
use crate::nostd_prelude::*;
pub mod comid;
pub mod common;
pub mod corim;
pub mod coswid;
pub mod environment;
pub mod measurement;
pub mod signed;
pub mod tags;
pub mod triples;

// Selective re-exports of the most commonly used types.
// Users can always access the full set via the submodules (e.g., `types::common::*`).
pub use self::comid::ComidTag;
pub use self::common::{
    CborTime, ClassIdChoice, CryptoKey, EntityMap, GroupIdChoice, InstanceIdChoice, LinkedTagMap,
    MeasuredElement, TagIdChoice, TagIdentity, ValidityMap, VersionMap,
};
pub use self::corim::{
    ConciseTagChoice, ConciseTlTag, CorimId, CorimLocator, CorimMap, CorimMetaMap, CorimSignerMap,
    ProfileChoice,
};
pub use self::coswid::{ConciseSwidTag, SwidEntity, SwidLink};
pub use self::environment::{ClassMap, EnvironmentMap};
pub use self::measurement::{
    Digest, DigestAlg, FlagsMap, IntRangeChoice, IntegrityRegisters, IpAddr, MacAddr,
    MeasurementMap, MeasurementValuesMap, RawValueChoice, SvnChoice,
};
pub use self::signed::{
    CoseAlgorithm, CoseCertHash, CoseSign1Corim, CoseX509, CwtClaims, ProtectedCorimHeaderMap,
    ProtectedCorimHeaderMapBuilder, SignedCorimBuilder,
};
pub use self::triples::{
    AttestKeyTriple, CesCommonCondition, ConditionalEndorsementSeriesTriple,
    ConditionalEndorsementTriple, ConditionalSeriesRecord, CoswidTriple, DomainMembershipTriple,
    EndorsedTriple, IdentityTriple, KeyTripleConditions, ReferenceTriple,
    StatefulEnvironmentRecord, TriplesMap, TrustDependencyTriple,
};
