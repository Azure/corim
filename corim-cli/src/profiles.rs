// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! First-party profile registration shared by all CLI commands.

pub(crate) fn build_registry() -> corim::profile::ProfileRegistry {
    #[allow(unused_mut)]
    let mut registry = corim::profile::ProfileRegistry::new();
    #[cfg(feature = "intel")]
    registry.register(Box::new(corim::profile::intel::IntelProfile::new()));
    #[cfg(feature = "azure")]
    registry.register(Box::new(corim::profile::azure::AzureProfile::new()));
    #[cfg(feature = "psa")]
    registry.register(Box::new(corim::profile::psa::PsaProfile::new()));
    #[cfg(feature = "cca")]
    registry.register(Box::new(corim::profile::cca::CcaPlatformProfile::new()));
    #[cfg(feature = "cca")]
    registry.register(Box::new(corim::profile::cca::CcaRealmProfile::new()));
    registry
}
