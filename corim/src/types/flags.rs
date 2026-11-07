//! Typed operational flag labels and retained extensions (draft-12 §5.1.4.5).
//!
//! ```text
//! flags-map = non-empty<{ ? 0 => bool, ..., ? 10 => bool, * extension }>
//! ```

use super::tags::*;
use crate::cbor::value::Value;
use crate::nostd_prelude::*;
use crate::Validate;
use serde::{Deserialize, Serialize};

/// Flag labels defined by draft-12 §11.10, with forward-compatible extensions.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Flag {
    /// `is-configured`, key 0.
    IsConfigured,
    /// `is-secure`, key 1.
    IsSecure,
    /// `is-recovery`, key 2.
    IsRecovery,
    /// `is-debug`, key 3.
    IsDebug,
    /// `is-replay-protected`, key 4.
    IsReplayProtected,
    /// `is-integrity-protected`, key 5.
    IsIntegrityProtected,
    /// `is-runtime-meas`, key 6.
    IsRuntimeMeas,
    /// `is-immutable`, key 7.
    IsImmutable,
    /// `is-tcb`, key 8.
    IsTcb,
    /// `is-confidentiality-protected`, key 9.
    IsConfidentialityProtected,
    /// `is-runtime-updatable`, key 10.
    IsRuntimeUpdatable,
    /// An integer extension label; modeled labels canonicalize to named flags.
    Extension(i64),
    /// A text extension label, distinct from the same-looking integer.
    Text(String),
}

impl Flag {
    fn from_int(key: i64) -> Self {
        match key {
            FLAG_KEY_IS_CONFIGURED => Self::IsConfigured,
            FLAG_KEY_IS_SECURE => Self::IsSecure,
            FLAG_KEY_IS_RECOVERY => Self::IsRecovery,
            FLAG_KEY_IS_DEBUG => Self::IsDebug,
            FLAG_KEY_IS_REPLAY_PROTECTED => Self::IsReplayProtected,
            FLAG_KEY_IS_INTEGRITY_PROTECTED => Self::IsIntegrityProtected,
            FLAG_KEY_IS_RUNTIME_MEAS => Self::IsRuntimeMeas,
            FLAG_KEY_IS_IMMUTABLE => Self::IsImmutable,
            FLAG_KEY_IS_TCB => Self::IsTcb,
            FLAG_KEY_IS_CONFIDENTIALITY_PROTECTED => Self::IsConfidentialityProtected,
            FLAG_KEY_IS_RUNTIME_UPDATABLE => Self::IsRuntimeUpdatable,
            key => Self::Extension(key),
        }
    }
    fn normalized(self) -> Self {
        match self {
            Self::Extension(key) => Self::from_int(key),
            flag => flag,
        }
    }
    fn value(&self) -> Value {
        let key = match self {
            Self::IsConfigured => FLAG_KEY_IS_CONFIGURED,
            Self::IsSecure => FLAG_KEY_IS_SECURE,
            Self::IsRecovery => FLAG_KEY_IS_RECOVERY,
            Self::IsDebug => FLAG_KEY_IS_DEBUG,
            Self::IsReplayProtected => FLAG_KEY_IS_REPLAY_PROTECTED,
            Self::IsIntegrityProtected => FLAG_KEY_IS_INTEGRITY_PROTECTED,
            Self::IsRuntimeMeas => FLAG_KEY_IS_RUNTIME_MEAS,
            Self::IsImmutable => FLAG_KEY_IS_IMMUTABLE,
            Self::IsTcb => FLAG_KEY_IS_TCB,
            Self::IsConfidentialityProtected => FLAG_KEY_IS_CONFIDENTIALITY_PROTECTED,
            Self::IsRuntimeUpdatable => FLAG_KEY_IS_RUNTIME_UPDATABLE,
            Self::Extension(key) => *key,
            Self::Text(text) => return Value::Text(text.clone()),
        };
        Value::Integer(i128::from(key))
    }
    /// Whether a label needs an extension-specific comparison algorithm (§8.3.4.4.5).
    pub fn is_extension(&self) -> bool {
        match self {
            Self::Extension(key) => matches!(Self::from_int(*key), Self::Extension(_)),
            Self::Text(_) => true,
            _ => false,
        }
    }
    /// Standard diagnostic name, or no name for extension labels (§11.10).
    pub fn name(&self) -> Option<&'static str> {
        let flag = match self {
            Self::Text(_) => return None,
            Self::Extension(key) => Self::from_int(*key),
            flag => flag.clone(),
        };
        match flag {
            Self::IsConfigured => Some("configured"),
            Self::IsSecure => Some("secure"),
            Self::IsRecovery => Some("recovery"),
            Self::IsDebug => Some("debug"),
            Self::IsReplayProtected => Some("replay-protected"),
            Self::IsIntegrityProtected => Some("integrity-protected"),
            Self::IsRuntimeMeas => Some("runtime-meas"),
            Self::IsImmutable => Some("immutable"),
            Self::IsTcb => Some("tcb"),
            Self::IsConfidentialityProtected => Some("confidentiality-protected"),
            Self::IsRuntimeUpdatable => Some("runtime-updatable"),
            Self::Extension(_) | Self::Text(_) => None,
        }
    }
}

/// A non-empty typed flag map retaining every integer/text extension path.
///
/// Known flags require boolean values; unknown values survive decode/encode
/// but require a profile comparator before they can satisfy a condition.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct FlagsMap(BTreeMap<Flag, Value>);

impl FlagsMap {
    /// Read a flag value, treating modeled integer aliases as the named flag.
    pub fn get(&self, flag: &Flag) -> Option<&Value> {
        match flag {
            Flag::Extension(key) => self.0.get(&Flag::from_int(*key)),
            _ => self.0.get(flag),
        }
    }
    /// Insert a flag, enforcing boolean types for modeled labels (§5.1.4.5).
    ///
    /// Returns the previous value on replacement. Integer aliases are
    /// canonicalized so callers cannot emit duplicate known labels.
    pub fn insert(&mut self, flag: Flag, value: Value) -> Result<Option<Value>, String> {
        let flag = flag.normalized();
        if !flag.is_extension() && !matches!(value, Value::Bool(_)) {
            return Err(format!("flag {flag:?} must be boolean"));
        }
        Ok(self.0.insert(flag, value))
    }
    /// Remove a flag by typed label.
    pub fn remove(&mut self, flag: &Flag) -> Option<Value> {
        match flag {
            Flag::Extension(key) => self.0.remove(&Flag::from_int(*key)),
            _ => self.0.remove(flag),
        }
    }
    /// Iterate all known and extension flags; no decoded paths are discarded.
    pub fn iter(&self) -> impl Iterator<Item = (&Flag, &Value)> {
        self.0.iter()
    }
}

impl Validate for FlagsMap {
    fn valid(&self) -> Result<(), String> {
        if self.0.is_empty() {
            return Err("flags-map must not be empty".into());
        }
        Ok(())
    }
}
impl Serialize for FlagsMap {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.valid().map_err(serde::ser::Error::custom)?;
        Value::Map(
            self.0
                .iter()
                .map(|(flag, value)| (flag.value(), value.clone()))
                .collect(),
        )
        .serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for FlagsMap {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        crate::cbor::map_keys::check(&value).map_err(serde::de::Error::custom)?;
        let Value::Map(entries) = value else {
            return Err(serde::de::Error::custom("flags-map must be a map"));
        };
        let mut flags = Self::default();
        for (key, value) in entries {
            let flag = match key {
                Value::Integer(key) => Flag::from_int(
                    i64::try_from(key)
                        .map_err(|_| serde::de::Error::custom("flag key out of range"))?,
                ),
                Value::Text(key) => Flag::Text(key),
                _ => {
                    return Err(serde::de::Error::custom(
                        "flag label must be integer or text",
                    ))
                }
            };
            flags
                .insert(flag, value)
                .map_err(serde::de::Error::custom)?;
        }
        flags.valid().map_err(serde::de::Error::custom)?;
        Ok(flags)
    }
}
