// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Triple types from `triples-map`.
//!
//! All triple record types are CBOR arrays (not maps), so they use standard
//! serde tuple serialization.

use corim_macros::{CborDeserialize, CborSerialize};
use serde::{Deserialize, Serialize};

use super::common::{CryptoKey, MeasuredElement, TagIdChoice};
use super::environment::EnvironmentMap;
use super::measurement::MeasurementMap;
use crate::Validate;

// ---------------------------------------------------------------------------
// triples-map
// ---------------------------------------------------------------------------

/// `triples-map` — the core payload of a CoMID.
///
/// At least one triple type must be present (`non-empty`).
#[derive(Clone, Debug, PartialEq, CborSerialize, CborDeserialize)]
#[cbor(non_empty)]
pub struct TriplesMap {
    /// `reference-triples` (key 0).
    #[cbor(key = 0, optional)]
    pub reference_triples: Option<Vec<ReferenceTriple>>,
    /// `endorsed-triples` (key 1).
    #[cbor(key = 1, optional)]
    pub endorsed_triples: Option<Vec<EndorsedTriple>>,
    /// `identity-triples` (key 2).
    #[cbor(key = 2, optional)]
    pub identity_triples: Option<Vec<IdentityTriple>>,
    /// `attest-key-triples` (key 3).
    #[cbor(key = 3, optional)]
    pub attest_key_triples: Option<Vec<AttestKeyTriple>>,
    /// `dependency-triples` (key 4).
    #[cbor(key = 4, optional)]
    pub dependency_triples: Option<Vec<DomainDependencyTriple>>,
    /// `membership-triples` (key 5).
    #[cbor(key = 5, optional)]
    pub membership_triples: Option<Vec<DomainMembershipTriple>>,
    /// `coswid-triples` (key 6).
    #[cbor(key = 6, optional)]
    pub coswid_triples: Option<Vec<CoswidTriple>>,
    /// `conditional-endorsement-series-triples` (key 8).
    #[cbor(key = 8, optional)]
    pub conditional_endorsement_series: Option<Vec<ConditionalEndorsementSeriesTriple>>,
    /// `conditional-endorsement-triples` (key 10).
    #[cbor(key = 10, optional)]
    pub conditional_endorsement: Option<Vec<ConditionalEndorsementTriple>>,
}

// ---------------------------------------------------------------------------
// reference-triple-record = [ environment-map, [+ measurement-map] ]
// ---------------------------------------------------------------------------

/// `reference-triple-record` — reference values for a target environment.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReferenceTriple(pub EnvironmentMap, pub Vec<MeasurementMap>);

impl ReferenceTriple {
    /// Create a new reference triple.
    pub fn new(environment: EnvironmentMap, measurements: Vec<MeasurementMap>) -> Self {
        Self(environment, measurements)
    }
    /// Get the target environment.
    pub fn environment(&self) -> &EnvironmentMap {
        &self.0
    }
    /// Get the reference measurements.
    pub fn measurements(&self) -> &[MeasurementMap] {
        &self.1
    }
}

// ---------------------------------------------------------------------------
// endorsed-triple-record = [ environment-map, [+ measurement-map] ]
// ---------------------------------------------------------------------------

/// `endorsed-triple-record` — endorsed values for a target environment.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EndorsedTriple(pub EnvironmentMap, pub Vec<MeasurementMap>);

impl EndorsedTriple {
    /// Create a new endorsed triple.
    pub fn new(condition: EnvironmentMap, endorsement: Vec<MeasurementMap>) -> Self {
        Self(condition, endorsement)
    }
    /// Get the condition environment.
    pub fn condition(&self) -> &EnvironmentMap {
        &self.0
    }
    /// Get the endorsement measurements.
    pub fn endorsement(&self) -> &[MeasurementMap] {
        &self.1
    }
}

// ---------------------------------------------------------------------------
// Key triple conditions (shared by identity and attest-key triples)
// ---------------------------------------------------------------------------

/// Conditions map for identity/attest-key triples.
///
/// CDDL: `non-empty<{ ?mkey: 0, ?authorized-by: 1 }>`
#[derive(Clone, Debug, PartialEq, CborSerialize, CborDeserialize)]
#[cbor(non_empty)]
pub struct KeyTripleConditions {
    /// `mkey` (key 0): optional measured element key.
    #[cbor(key = 0, optional)]
    pub mkey: Option<MeasuredElement>,
    /// `authorized-by` (key 1): optional authority keys.
    #[cbor(key = 1, optional)]
    pub authorized_by: Option<Vec<CryptoKey>>,
}

// ---------------------------------------------------------------------------
// identity-triple-record
// ---------------------------------------------------------------------------

/// `identity-triple-record` — device identity keys.
///
/// CDDL:
/// ```text
/// identity-triple-record = [
///   environment: environment-map,
///   key-list: [+ $crypto-key-type-choice],
///   ? conditions: non-empty<{ ?mkey, ?authorized-by }>,
/// ]
/// ```
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IdentityTriple(
    pub EnvironmentMap,
    pub Vec<CryptoKey>,
    #[serde(skip_serializing_if = "Option::is_none", default)] pub Option<KeyTripleConditions>,
);

impl IdentityTriple {
    /// Create a new identity triple.
    pub fn new(
        environment: EnvironmentMap,
        keys: Vec<CryptoKey>,
        conditions: Option<KeyTripleConditions>,
    ) -> Self {
        Self(environment, keys, conditions)
    }
    /// Get the environment.
    pub fn environment(&self) -> &EnvironmentMap {
        &self.0
    }
    /// Get the key list.
    pub fn keys(&self) -> &[CryptoKey] {
        &self.1
    }
    /// Get optional conditions.
    pub fn conditions(&self) -> Option<&KeyTripleConditions> {
        self.2.as_ref()
    }
}

// ---------------------------------------------------------------------------
// attest-key-triple-record
// ---------------------------------------------------------------------------

/// `attest-key-triple-record` — attestation key endorsement.
///
/// Same structure as identity-triple-record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AttestKeyTriple(
    pub EnvironmentMap,
    pub Vec<CryptoKey>,
    #[serde(skip_serializing_if = "Option::is_none", default)] pub Option<KeyTripleConditions>,
);

impl AttestKeyTriple {
    /// Create a new attest-key triple.
    pub fn new(
        environment: EnvironmentMap,
        keys: Vec<CryptoKey>,
        conditions: Option<KeyTripleConditions>,
    ) -> Self {
        Self(environment, keys, conditions)
    }
    /// Get the environment.
    pub fn environment(&self) -> &EnvironmentMap {
        &self.0
    }
    /// Get the key list.
    pub fn keys(&self) -> &[CryptoKey] {
        &self.1
    }
    /// Get optional conditions.
    pub fn conditions(&self) -> Option<&KeyTripleConditions> {
        self.2.as_ref()
    }
}

// ---------------------------------------------------------------------------
// domain-dependency-triple-record
// ---------------------------------------------------------------------------

/// `domain-dependency-triple-record` — trust dependencies between domains.
///
/// CDDL: `[domain-id: domain-type, trustees: [+ domain-type]]`
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DomainDependencyTriple(pub EnvironmentMap, pub Vec<EnvironmentMap>);

impl DomainDependencyTriple {
    /// Create a new domain dependency triple.
    pub fn new(domain_id: EnvironmentMap, trustees: Vec<EnvironmentMap>) -> Self {
        Self(domain_id, trustees)
    }
    /// Get the domain identifier.
    pub fn domain_id(&self) -> &EnvironmentMap {
        &self.0
    }
    /// Get the trustee domains.
    pub fn trustees(&self) -> &[EnvironmentMap] {
        &self.1
    }
}

// ---------------------------------------------------------------------------
// domain-membership-triple-record
// ---------------------------------------------------------------------------

/// `domain-membership-triple-record` — domain composition.
///
/// CDDL: `[domain-id: domain-type, members: [+ domain-type]]`
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DomainMembershipTriple(pub EnvironmentMap, pub Vec<EnvironmentMap>);

impl DomainMembershipTriple {
    /// Create a new domain membership triple.
    pub fn new(domain_id: EnvironmentMap, members: Vec<EnvironmentMap>) -> Self {
        Self(domain_id, members)
    }
    /// Get the domain identifier.
    pub fn domain_id(&self) -> &EnvironmentMap {
        &self.0
    }
    /// Get the member environments.
    pub fn members(&self) -> &[EnvironmentMap] {
        &self.1
    }
}

// ---------------------------------------------------------------------------
// coswid-triple-record = [ environment-map, [+ coswid.tag-id] ]
// ---------------------------------------------------------------------------

/// `coswid-triple-record` — links an environment to CoSWID tags.
///
/// The tag-ids are `text / bstr .size 16` (string or UUID).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CoswidTriple(pub EnvironmentMap, pub Vec<TagIdChoice>);

impl CoswidTriple {
    /// Create a new CoSWID triple.
    pub fn new(environment: EnvironmentMap, tag_ids: Vec<TagIdChoice>) -> Self {
        Self(environment, tag_ids)
    }
    /// Get the environment.
    pub fn environment(&self) -> &EnvironmentMap {
        &self.0
    }
    /// Get the CoSWID tag identifiers.
    pub fn tag_ids(&self) -> &[TagIdChoice] {
        &self.1
    }
}

// ---------------------------------------------------------------------------
// conditional-endorsement-series
// ---------------------------------------------------------------------------

/// Condition block for conditional-endorsement-series triples.
///
/// CDDL (this is a CBOR **array**, not a map):
/// ```text
/// condition: [
///   environment: environment-map,
///   claims-list: [* measurement-map],
///   ? authorized-by: [+ $crypto-key-type-choice],
/// ]
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct CesCondition {
    /// The target environment.
    pub environment: EnvironmentMap,
    /// Measurement conditions (may be empty).
    pub claims_list: Vec<MeasurementMap>,
    /// Optional authority condition.
    pub authorized_by: Option<Vec<CryptoKey>>,
}

// Custom Serialize/Deserialize for CesCondition — it is a CBOR array [env, claims, ?auth]
impl Serialize for CesCondition {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let len = if self.authorized_by.is_some() { 3 } else { 2 };
        let mut seq = serializer.serialize_seq(Some(len))?;
        seq.serialize_element(&self.environment)?;
        seq.serialize_element(&self.claims_list)?;
        if let Some(ref auth) = self.authorized_by {
            seq.serialize_element(auth)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for CesCondition {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct CesCondVisitor;
        impl<'de> serde::de::Visitor<'de> for CesCondVisitor {
            type Value = CesCondition;
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("a CBOR array [environment, claims-list, ?authorized-by]")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let environment: EnvironmentMap = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let claims_list: Vec<MeasurementMap> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                let authorized_by: Option<Vec<CryptoKey>> = seq.next_element()?;
                Ok(CesCondition {
                    environment,
                    claims_list,
                    authorized_by,
                })
            }
        }
        deserializer.deserialize_seq(CesCondVisitor)
    }
}

/// `conditional-endorsement-series-triple-record`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConditionalEndorsementSeriesTriple(pub CesCondition, pub Vec<ConditionalSeriesRecord>);

impl ConditionalEndorsementSeriesTriple {
    /// Create a new CES triple.
    pub fn new(condition: CesCondition, series: Vec<ConditionalSeriesRecord>) -> Self {
        Self(condition, series)
    }
    /// Get the condition.
    pub fn condition(&self) -> &CesCondition {
        &self.0
    }
    /// Get the series records.
    pub fn series(&self) -> &[ConditionalSeriesRecord] {
        &self.1
    }
}

/// `conditional-series-record = [selection: [+ measurement-map], addition: [+ measurement-map]]`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConditionalSeriesRecord(pub Vec<MeasurementMap>, pub Vec<MeasurementMap>);

impl ConditionalSeriesRecord {
    /// Create a new conditional series record.
    pub fn new(selection: Vec<MeasurementMap>, addition: Vec<MeasurementMap>) -> Self {
        Self(selection, addition)
    }
    /// Get the selection criteria.
    pub fn selection(&self) -> &[MeasurementMap] {
        &self.0
    }
    /// Get the addition values.
    pub fn addition(&self) -> &[MeasurementMap] {
        &self.1
    }
}

// ---------------------------------------------------------------------------
// conditional-endorsement-triple-record
// ---------------------------------------------------------------------------

/// `stateful-environment-record = [environment-map, [+ measurement-map]]`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StatefulEnvironmentRecord(pub EnvironmentMap, pub Vec<MeasurementMap>);

/// `conditional-endorsement-triple-record`.
///
/// CDDL:
/// ```text
/// conditional-endorsement-triple-record = [
///   conditions: [+ stateful-environment-record],
///   endorsements: [+ endorsed-triple-record],
/// ]
/// ```
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConditionalEndorsementTriple(
    pub Vec<StatefulEnvironmentRecord>,
    pub Vec<EndorsedTriple>,
);

// ---------------------------------------------------------------------------
// Validate implementations
// ---------------------------------------------------------------------------

impl Validate for TriplesMap {
    fn valid(&self) -> Result<(), String> {
        fn non_empty<T>(v: &Option<Vec<T>>) -> bool {
            v.as_ref().is_some_and(|v| !v.is_empty())
        }

        let has_triples = non_empty(&self.reference_triples)
            || non_empty(&self.endorsed_triples)
            || non_empty(&self.identity_triples)
            || non_empty(&self.attest_key_triples)
            || non_empty(&self.dependency_triples)
            || non_empty(&self.membership_triples)
            || non_empty(&self.coswid_triples)
            || non_empty(&self.conditional_endorsement_series)
            || non_empty(&self.conditional_endorsement);

        if !has_triples {
            return Err("triples struct must not be empty".into());
        }

        if let Some(ref triples) = self.reference_triples {
            for (i, t) in triples.iter().enumerate() {
                t.valid()
                    .map_err(|e| format!("reference value at index {i}: {e}"))?;
            }
        }
        if let Some(ref triples) = self.endorsed_triples {
            for (i, t) in triples.iter().enumerate() {
                t.valid()
                    .map_err(|e| format!("endorsed value at index {i}: {e}"))?;
            }
        }
        if let Some(ref triples) = self.identity_triples {
            for (i, t) in triples.iter().enumerate() {
                t.valid()
                    .map_err(|e| format!("identity triple at index {i}: {e}"))?;
            }
        }
        if let Some(ref triples) = self.attest_key_triples {
            for (i, t) in triples.iter().enumerate() {
                t.valid()
                    .map_err(|e| format!("attest-key triple at index {i}: {e}"))?;
            }
        }
        if let Some(ref triples) = self.dependency_triples {
            for (i, t) in triples.iter().enumerate() {
                t.valid()
                    .map_err(|e| format!("dependency triple at index {i}: {e}"))?;
            }
        }
        if let Some(ref triples) = self.membership_triples {
            for (i, t) in triples.iter().enumerate() {
                t.valid()
                    .map_err(|e| format!("membership triple at index {i}: {e}"))?;
            }
        }
        Ok(())
    }
}

impl Validate for ReferenceTriple {
    fn valid(&self) -> Result<(), String> {
        self.0
            .valid()
            .map_err(|e| format!("environment validation failed: {e}"))?;
        if self.1.is_empty() {
            return Err("measurements validation failed: no measurement entries".into());
        }
        for (i, m) in self.1.iter().enumerate() {
            m.valid()
                .map_err(|e| format!("measurement at index {i}: {e}"))?;
        }
        Ok(())
    }
}

impl Validate for EndorsedTriple {
    fn valid(&self) -> Result<(), String> {
        self.0
            .valid()
            .map_err(|e| format!("environment validation failed: {e}"))?;
        if self.1.is_empty() {
            return Err("measurements validation failed: no measurement entries".into());
        }
        for (i, m) in self.1.iter().enumerate() {
            m.valid()
                .map_err(|e| format!("measurement at index {i}: {e}"))?;
        }
        Ok(())
    }
}

impl Validate for IdentityTriple {
    fn valid(&self) -> Result<(), String> {
        self.0
            .valid()
            .map_err(|e| format!("environment validation failed: {e}"))?;
        if self.1.is_empty() {
            return Err("verification keys validation failed: no keys".into());
        }
        Ok(())
    }
}

impl Validate for AttestKeyTriple {
    fn valid(&self) -> Result<(), String> {
        self.0
            .valid()
            .map_err(|e| format!("environment validation failed: {e}"))?;
        if self.1.is_empty() {
            return Err("verification keys validation failed: no keys".into());
        }
        Ok(())
    }
}

impl Validate for DomainDependencyTriple {
    fn valid(&self) -> Result<(), String> {
        self.0.valid().map_err(|e| format!("domain-id: {e}"))?;
        if self.1.is_empty() {
            return Err("at least one trustee required".into());
        }
        for (i, t) in self.1.iter().enumerate() {
            t.valid()
                .map_err(|e| format!("trustee at index {i}: {e}"))?;
        }
        // Check domain-id does not appear in trustees (§5.1.11.2 constraint)
        for trustee in &self.1 {
            if self.0 == *trustee {
                return Err("domain-id must not appear in trustees".into());
            }
        }
        Ok(())
    }
}

impl Validate for DomainMembershipTriple {
    fn valid(&self) -> Result<(), String> {
        self.0.valid().map_err(|e| format!("domain-id: {e}"))?;
        if self.1.is_empty() {
            return Err("at least one member required".into());
        }
        for (i, m) in self.1.iter().enumerate() {
            m.valid().map_err(|e| format!("member at index {i}: {e}"))?;
        }
        Ok(())
    }
}

impl Validate for CoswidTriple {
    fn valid(&self) -> Result<(), String> {
        self.0
            .valid()
            .map_err(|e| format!("environment validation failed: {e}"))?;
        if self.1.is_empty() {
            return Err("at least one CoSWID tag-id required".into());
        }
        Ok(())
    }
}

impl Validate for ConditionalEndorsementSeriesTriple {
    fn valid(&self) -> Result<(), String> {
        self.0
            .environment
            .valid()
            .map_err(|e| format!("condition environment: {e}"))?;
        if self.1.is_empty() {
            return Err("no measurement entries in series".into());
        }
        Ok(())
    }
}

impl Validate for StatefulEnvironmentRecord {
    fn valid(&self) -> Result<(), String> {
        self.0
            .valid()
            .map_err(|e| format!("environment validation failed: {e}"))?;
        if self.1.is_empty() {
            return Err("measurements must not be empty".into());
        }
        Ok(())
    }
}

impl Validate for ConditionalEndorsementTriple {
    fn valid(&self) -> Result<(), String> {
        if self.0.is_empty() {
            return Err("conditions must not be empty".into());
        }
        for (i, c) in self.0.iter().enumerate() {
            c.valid()
                .map_err(|e| format!("condition at index {i}: {e}"))?;
        }
        if self.1.is_empty() {
            return Err("endorsements must not be empty".into());
        }
        for (i, e) in self.1.iter().enumerate() {
            e.valid()
                .map_err(|e| format!("endorsement at index {i}: {e}"))?;
        }
        Ok(())
    }
}
