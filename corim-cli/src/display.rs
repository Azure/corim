// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Pretty-printing helpers for CoRIM/CoMID structures.

use corim::types::comid::ComidTag;
use corim::types::common::*;
use corim::types::corim::*;
use corim::types::environment::*;
use corim::types::measurement::*;
use corim::types::triples::*;

// ── Top-level CoRIM ──────────────────────────────────────────────────────

pub fn print_corim(corim: &CorimMap, show_raw: bool) {
    println!("  id: {}", corim_id_str(&corim.id));

    if let Some(ref profile) = corim.profile {
        println!("  profile: {}", profile_str(profile));
    }

    if let Some(ref validity) = corim.rim_validity {
        print_validity(validity, "  ");
    }

    if let Some(ref entities) = corim.entities {
        println!("  entities:");
        for e in entities {
            print_entity(e, "    ");
        }
    }

    if let Some(ref deps) = corim.dependent_rims {
        println!("  dependent-rims: ({} locators)", deps.len());
        for (i, loc) in deps.iter().enumerate() {
            print!("    [{}] href: ", i);
            match &loc.href {
                CorimLocatorHref::Single(u) => println!("{}", u),
                CorimLocatorHref::Multiple(us) => println!("{}", us.join(", ")),
                _ => println!("(unknown href variant)"),
            }
        }
    }

    if show_raw {
        for (i, tag) in corim.tags.iter().enumerate() {
            let (label, bytes) = match tag {
                ConciseTagChoice::Comid(b) => (format!("tags[{}] (CoMID)", i), b),
                ConciseTagChoice::Coswid(b) => (format!("tags[{}] (CoSWID)", i), b),
                ConciseTagChoice::Cotl(b) => (format!("tags[{}] (CoTL)", i), b),
                ConciseTagChoice::Unknown(t, b) => (format!("tags[{}] (unknown tag {})", i, t), b),
                _ => continue,
            };
            println!("  {}: {} bytes", label, bytes.len());
            print_hex_block(bytes, "    ", 32);
        }
    }
}

// ── CoMID ────────────────────────────────────────────────────────────────

pub fn print_comid(comid: &ComidTag, indent: &str, _show_raw: bool) {
    println!(
        "{}tag-id: {}",
        indent,
        tag_id_str(&comid.tag_identity.tag_id)
    );
    if let Some(v) = comid.tag_identity.tag_version {
        println!("{}tag-version: {}", indent, v);
    }
    if let Some(ref lang) = comid.language {
        println!("{}language: {}", indent, lang);
    }
    if let Some(ref entities) = comid.entities {
        println!("{}entities:", indent);
        for e in entities {
            print_entity(e, &format!("{}  ", indent));
        }
    }
    if let Some(ref links) = comid.linked_tags {
        println!("{}linked-tags:", indent);
        for lt in links {
            let rel = match lt.tag_rel {
                0 => "supplements",
                1 => "replaces",
                n => &format!("{}", n),
            };
            println!("{}  {} → {}", indent, rel, tag_id_str(&lt.linked_tag_id));
        }
    }

    print_triples(&comid.triples, indent);
}

// ── Triples ──────────────────────────────────────────────────────────────

fn print_triples(triples: &TriplesMap, indent: &str) {
    println!("{}triples:", indent);
    let ti = format!("{}  ", indent);

    if let Some(ref v) = triples.reference_triples {
        println!("{}reference-triples: ({} entries)", ti, v.len());
        for (i, t) in v.iter().enumerate() {
            println!("{}  [{}]", ti, i);
            print_env(&t.0, &format!("{}    ", ti));
            println!("{}    measurements: ({} entries)", ti, t.1.len());
            for m in &t.1 {
                print_measurement(m, &format!("{}      ", ti));
            }
        }
    }

    if let Some(ref v) = triples.endorsed_triples {
        println!("{}endorsed-triples: ({} entries)", ti, v.len());
        for (i, t) in v.iter().enumerate() {
            println!("{}  [{}]", ti, i);
            print_env(&t.0, &format!("{}    ", ti));
            println!("{}    endorsements: ({} entries)", ti, t.1.len());
            for m in &t.1 {
                print_measurement(m, &format!("{}      ", ti));
            }
        }
    }

    if let Some(ref v) = triples.identity_triples {
        println!("{}identity-triples: ({} entries)", ti, v.len());
        for (i, t) in v.iter().enumerate() {
            println!("{}  [{}]", ti, i);
            print_env(&t.0, &format!("{}    ", ti));
            println!("{}    keys: ({} entries)", ti, t.1.len());
            for k in &t.1 {
                println!("{}      {}", ti, crypto_key_str(k));
            }
        }
    }

    if let Some(ref v) = triples.attest_key_triples {
        println!("{}attest-key-triples: ({} entries)", ti, v.len());
        for (i, t) in v.iter().enumerate() {
            println!("{}  [{}]", ti, i);
            print_env(&t.0, &format!("{}    ", ti));
            println!("{}    keys: ({} entries)", ti, t.1.len());
            for k in &t.1 {
                println!("{}      {}", ti, crypto_key_str(k));
            }
        }
    }

    if let Some(ref v) = triples.dependency_triples {
        println!("{}dependency-triples: ({} entries)", ti, v.len());
        for (i, t) in v.iter().enumerate() {
            println!("{}  [{}] domain:", ti, i);
            print_env(&t.0, &format!("{}    ", ti));
            println!("{}    trustees: ({} entries)", ti, t.1.len());
        }
    }

    if let Some(ref v) = triples.membership_triples {
        println!("{}membership-triples: ({} entries)", ti, v.len());
        for (i, t) in v.iter().enumerate() {
            println!("{}  [{}] domain:", ti, i);
            print_env(&t.0, &format!("{}    ", ti));
            println!("{}    members: ({} entries)", ti, t.1.len());
        }
    }

    if let Some(ref v) = triples.coswid_triples {
        println!("{}coswid-triples: ({} entries)", ti, v.len());
        for (i, t) in v.iter().enumerate() {
            println!("{}  [{}]", ti, i);
            print_env(&t.0, &format!("{}    ", ti));
            let ids: Vec<String> = t.1.iter().map(tag_id_str).collect();
            println!("{}    tag-ids: [{}]", ti, ids.join(", "));
        }
    }

    if let Some(ref v) = triples.conditional_endorsement_series {
        println!(
            "{}conditional-endorsement-series: ({} entries)",
            ti,
            v.len()
        );
        for (i, t) in v.iter().enumerate() {
            let cond = t.condition();
            println!("{}  [{}] condition:", ti, i);
            print_env(&cond.environment, &format!("{}    ", ti));
            if !cond.claims_list.is_empty() {
                println!(
                    "{}    claims-list: ({} entries)",
                    ti,
                    cond.claims_list.len()
                );
            }
            println!("{}    series: ({} entries)", ti, t.series().len());
            for (j, sr) in t.series().iter().enumerate() {
                println!(
                    "{}      [{}] selection: {} meas → addition: {} meas",
                    ti,
                    j,
                    sr.selection().len(),
                    sr.addition().len()
                );
            }
        }
    }

    if let Some(ref v) = triples.conditional_endorsement {
        println!("{}conditional-endorsement: ({} entries)", ti, v.len());
    }
}

// ── Environment ──────────────────────────────────────────────────────────

fn print_env(env: &EnvironmentMap, indent: &str) {
    println!("{}environment:", indent);
    let ei = format!("{}  ", indent);
    if let Some(ref class) = env.class {
        print_class(class, &ei);
    }
    if let Some(ref inst) = env.instance {
        println!("{}instance: {}", ei, instance_id_str(inst));
    }
    if let Some(ref grp) = env.group {
        println!("{}group: {}", ei, group_id_str(grp));
    }
}

fn print_class(class: &ClassMap, indent: &str) {
    if let Some(ref cid) = class.class_id {
        println!("{}class-id: {}", indent, class_id_str(cid));
    }
    if let Some(ref v) = class.vendor {
        println!("{}vendor: {}", indent, v);
    }
    if let Some(ref m) = class.model {
        println!("{}model: {}", indent, m);
    }
    if let Some(l) = class.layer {
        println!("{}layer: {}", indent, l);
    }
    if let Some(idx) = class.index {
        println!("{}index: {}", indent, idx);
    }
}

// ── Measurement ──────────────────────────────────────────────────────────

fn print_measurement(m: &MeasurementMap, indent: &str) {
    if let Some(ref mkey) = m.mkey {
        println!("{}mkey: {}", indent, measured_element_str(mkey));
    }
    println!("{}mval:", indent);
    let mi = format!("{}  ", indent);
    let mv = &m.mval;

    if let Some(ref ver) = mv.version {
        print!("{}version: \"{}\"", mi, ver.version);
        if let Some(scheme) = ver.version_scheme {
            print!(" (scheme: {})", version_scheme_str(scheme));
        }
        println!();
    }

    if let Some(ref svn) = mv.svn {
        match svn {
            SvnChoice::ExactValue(v) => println!("{}svn: {} (exact)", mi, v),
            SvnChoice::MinValue(v) => println!("{}svn: {} (min)", mi, v),
            _ => println!("{}svn: (unknown variant)", mi),
        }
    }

    if let Some(ref digests) = mv.digests {
        println!("{}digests:", mi);
        for d in digests {
            println!("{}  [alg={}] {}", mi, d.alg(), hex_short(d.value()));
        }
    }

    if let Some(ref flags) = mv.flags {
        print_flags(flags, &mi);
    }

    if let Some(ref raw) = mv.raw_value {
        match raw {
            RawValueChoice::Bytes(b) => println!("{}raw-value: {}", mi, hex_short(b)),
            RawValueChoice::Masked { value, mask } => {
                println!("{}raw-value (masked):", mi);
                println!("{}  value: {}", mi, hex_short(value));
                println!("{}  mask:  {}", mi, hex_short(mask));
            }
            _ => println!("{}raw-value: (unknown variant)", mi),
        }
    }

    if let Some(ref mac) = mv.mac_addr {
        match mac {
            MacAddr::Eui48(b) => println!("{}mac-addr: {} (EUI-48)", mi, hex::encode(b)),
            MacAddr::Eui64(b) => println!("{}mac-addr: {} (EUI-64)", mi, hex::encode(b)),
            _ => println!("{}mac-addr: (unknown variant)", mi),
        }
    }

    if let Some(ref ip) = mv.ip_addr {
        match ip {
            IpAddr::V4(b) => println!("{}ip-addr: {}.{}.{}.{}", mi, b[0], b[1], b[2], b[3]),
            IpAddr::V6(b) => println!("{}ip-addr: {}", mi, hex::encode(b)),
            _ => println!("{}ip-addr: (unknown variant)", mi),
        }
    }

    if let Some(ref sn) = mv.serial_number {
        println!("{}serial-number: \"{}\"", mi, sn);
    }

    if let Some(ref ueid) = mv.ueid {
        println!("{}ueid: {}", mi, hex::encode(ueid));
    }

    if let Some(ref uuid) = mv.uuid {
        println!("{}uuid: {}", mi, format_uuid(uuid));
    }

    if let Some(ref name) = mv.name {
        println!("{}name: \"{}\"", mi, name);
    }

    if let Some(ref keys) = mv.cryptokeys {
        println!("{}cryptokeys: ({} entries)", mi, keys.len());
        for k in keys {
            println!("{}  {}", mi, crypto_key_str(k));
        }
    }

    if let Some(ref regs) = mv.integrity_registers {
        println!("{}integrity-registers: ({} entries)", mi, regs.0.len());
        for (id, digests) in &regs.0 {
            let id_str = match id {
                IntegrityRegisterId::Uint(n) => n.to_string(),
                IntegrityRegisterId::Text(t) => format!("\"{}\"", t),
                _ => "(unknown)".to_string(),
            };
            print!("{}  {}: ", mi, id_str);
            let ds: Vec<String> = digests
                .iter()
                .map(|d| format!("[alg={} {}]", d.alg(), hex_short(d.value())))
                .collect();
            println!("{}", ds.join(", "));
        }
    }

    if let Some(ref range) = mv.int_range {
        match range {
            IntRangeChoice::Int(v) => println!("{}int-range: {}", mi, v),
            IntRangeChoice::Range { min, max } => {
                let min_s = match min {
                    Some(n) => n.to_string(),
                    None => "-∞".into(),
                };
                let max_s = match max {
                    Some(n) => n.to_string(),
                    None => "+∞".into(),
                };
                println!("{}int-range: [{}..{}]", mi, min_s, max_s);
            }
            _ => println!("{}int-range: (unknown variant)", mi),
        }
    }

    if let Some(ref auth) = m.authorized_by {
        println!("{}authorized-by: ({} keys)", indent, auth.len());
    }
}

fn print_flags(flags: &FlagsMap, indent: &str) {
    let mut parts = Vec::new();
    if let Some(v) = flags.is_configured {
        parts.push(format!("configured={}", v));
    }
    if let Some(v) = flags.is_secure {
        parts.push(format!("secure={}", v));
    }
    if let Some(v) = flags.is_recovery {
        parts.push(format!("recovery={}", v));
    }
    if let Some(v) = flags.is_debug {
        parts.push(format!("debug={}", v));
    }
    if let Some(v) = flags.is_replay_protected {
        parts.push(format!("replay-protected={}", v));
    }
    if let Some(v) = flags.is_integrity_protected {
        parts.push(format!("integrity-protected={}", v));
    }
    if let Some(v) = flags.is_runtime_meas {
        parts.push(format!("runtime-meas={}", v));
    }
    if let Some(v) = flags.is_immutable {
        parts.push(format!("immutable={}", v));
    }
    if let Some(v) = flags.is_tcb {
        parts.push(format!("tcb={}", v));
    }
    if let Some(v) = flags.is_confidentiality_protected {
        parts.push(format!("confidentiality-protected={}", v));
    }
    if !parts.is_empty() {
        println!("{}flags: {{{}}}", indent, parts.join(", "));
    }
}

// ── Entity / Validity ────────────────────────────────────────────────────

fn print_entity(e: &EntityMap, indent: &str) {
    let roles: Vec<String> = e.role.iter().map(|r| role_str(*r)).collect();
    print!("{}{} [{}]", indent, e.entity_name, roles.join(", "));
    if let Some(ref uri) = e.reg_id {
        print!(" <{}>", uri);
    }
    println!();
}

pub fn print_validity(v: &ValidityMap, indent: &str) {
    if let Some(nb) = v.not_before {
        println!("{}not-before: {} (epoch)", indent, nb.epoch_secs());
    }
    println!("{}not-after:  {} (epoch)", indent, v.not_after.epoch_secs());
}

// ── String formatters ────────────────────────────────────────────────────

pub fn corim_id_str(id: &CorimId) -> String {
    match id {
        CorimId::Text(t) => format!("\"{}\"", t),
        CorimId::Uuid(u) => format_uuid(u),
        _ => "(unknown)".to_string(),
    }
}

/// JSON-safe CoRIM ID: always properly quoted.
pub fn corim_id_json(id: &CorimId) -> String {
    match id {
        CorimId::Text(t) => format!("\"{}\"", t.replace('\\', "\\\\").replace('"', "\\\"")),
        CorimId::Uuid(u) => format!("\"{}\"", format_uuid(u)),
        _ => "\"unknown\"".to_string(),
    }
}

pub fn profile_str(p: &ProfileChoice) -> String {
    match p {
        ProfileChoice::Uri(u) => u.clone(),
        ProfileChoice::Oid(b) => format!("OID({})", hex::encode(b)),
        _ => "(unknown)".to_string(),
    }
}

pub fn tag_id_str(id: &TagIdChoice) -> String {
    match id {
        TagIdChoice::Text(t) => format!("\"{}\"", t),
        TagIdChoice::Uuid(u) => format_uuid(u),
        _ => "(unknown)".to_string(),
    }
}

/// JSON-safe tag ID: always properly quoted.
pub fn tag_id_json(id: &TagIdChoice) -> String {
    match id {
        TagIdChoice::Text(t) => format!("\"{}\"", t.replace('\\', "\\\\").replace('"', "\\\"")),
        TagIdChoice::Uuid(u) => format!("\"{}\"", format_uuid(u)),
        _ => "\"unknown\"".to_string(),
    }
}

pub fn triple_type_list(triples: &TriplesMap) -> String {
    let mut types = Vec::new();
    if triples.reference_triples.is_some() {
        types.push("\"reference\"");
    }
    if triples.endorsed_triples.is_some() {
        types.push("\"endorsed\"");
    }
    if triples.identity_triples.is_some() {
        types.push("\"identity\"");
    }
    if triples.attest_key_triples.is_some() {
        types.push("\"attest-key\"");
    }
    if triples.dependency_triples.is_some() {
        types.push("\"dependency\"");
    }
    if triples.membership_triples.is_some() {
        types.push("\"membership\"");
    }
    if triples.coswid_triples.is_some() {
        types.push("\"coswid\"");
    }
    if triples.conditional_endorsement_series.is_some() {
        types.push("\"cond-endorsement-series\"");
    }
    if triples.conditional_endorsement.is_some() {
        types.push("\"cond-endorsement\"");
    }
    types.join(", ")
}

fn class_id_str(id: &ClassIdChoice) -> String {
    match id {
        ClassIdChoice::Oid(b) => format!("OID({})", hex::encode(b)),
        ClassIdChoice::Uuid(u) => format_uuid(u),
        ClassIdChoice::Bytes(b) => format!("bytes({})", hex_short(b)),
        _ => "(unknown)".to_string(),
    }
}

fn instance_id_str(id: &InstanceIdChoice) -> String {
    match id {
        InstanceIdChoice::Ueid(b) => format!("UEID({})", hex::encode(b)),
        InstanceIdChoice::Uuid(u) => format_uuid(u),
        InstanceIdChoice::Bytes(b) => format!("bytes({})", hex_short(b)),
        InstanceIdChoice::PkixBase64Key(s) => format!("pkix-key({}...)", &s[..s.len().min(32)]),
        InstanceIdChoice::PkixBase64Cert(s) => format!("pkix-cert({}...)", &s[..s.len().min(32)]),
        InstanceIdChoice::CoseKey(b) => format!("cose-key({} bytes)", b.len()),
        InstanceIdChoice::KeyThumbprint(d) => {
            format!("key-thumbprint(alg={}, {})", d.alg(), hex_short(d.value()))
        }
        InstanceIdChoice::CertThumbprint(d) => {
            format!("cert-thumbprint(alg={}, {})", d.alg(), hex_short(d.value()))
        }
        InstanceIdChoice::PkixAsn1DerCert(b) => format!("asn1der-cert({} bytes)", b.len()),
        _ => "(unknown)".to_string(),
    }
}

fn group_id_str(id: &GroupIdChoice) -> String {
    match id {
        GroupIdChoice::Uuid(u) => format_uuid(u),
        GroupIdChoice::Bytes(b) => format!("bytes({})", hex_short(b)),
        _ => "(unknown)".to_string(),
    }
}

fn measured_element_str(me: &MeasuredElement) -> String {
    match me {
        MeasuredElement::Oid(b) => format!("OID({})", hex::encode(b)),
        MeasuredElement::Uuid(u) => format_uuid(u),
        MeasuredElement::Uint(n) => n.to_string(),
        MeasuredElement::Text(t) => format!("\"{}\"", t),
        _ => "(unknown)".to_string(),
    }
}

fn crypto_key_str(k: &CryptoKey) -> String {
    match k {
        CryptoKey::PkixBase64Key(s) => format!("pkix-base64-key({}...)", &s[..s.len().min(40)]),
        CryptoKey::PkixBase64Cert(s) => format!("pkix-base64-cert({}...)", &s[..s.len().min(40)]),
        CryptoKey::PkixBase64CertPath(s) => {
            format!("pkix-base64-cert-path({}...)", &s[..s.len().min(40)])
        }
        CryptoKey::KeyThumbprint(d) => {
            format!("key-thumbprint(alg={}, {})", d.alg(), hex_short(d.value()))
        }
        CryptoKey::CoseKey(b) => format!("cose-key({} bytes)", b.len()),
        CryptoKey::CertThumbprint(d) => {
            format!("cert-thumbprint(alg={}, {})", d.alg(), hex_short(d.value()))
        }
        CryptoKey::CertPathThumbprint(d) => {
            format!(
                "cert-path-thumbprint(alg={}, {})",
                d.alg(),
                hex_short(d.value())
            )
        }
        CryptoKey::PkixAsn1DerCert(b) => format!("pkix-asn1der-cert({} bytes)", b.len()),
        CryptoKey::Bytes(b) => format!("bytes({})", hex_short(b)),
        _ => "(unknown)".to_string(),
    }
}

fn role_str(role: i64) -> String {
    match role {
        0 => "tag-creator".into(),
        1 => "creator/manifest-creator".into(),
        2 => "maintainer/manifest-signer".into(),
        _ => format!("role({})", role),
    }
}

fn version_scheme_str(scheme: i64) -> String {
    match scheme {
        1 => "multipartnumeric".into(),
        2 => "multipartnumeric-suffix".into(),
        3 => "alphanumeric".into(),
        4 => "decimal".into(),
        16384 => "semver".into(),
        _ => format!("{}", scheme),
    }
}

// ── Hex / UUID helpers ───────────────────────────────────────────────────

fn hex_short(bytes: &[u8]) -> String {
    if bytes.len() <= 32 {
        hex::encode(bytes)
    } else {
        format!("{}...({} bytes)", hex::encode(&bytes[..16]), bytes.len())
    }
}

/// Print a byte buffer as lowercase hex with line wrapping.
///
/// Each line is prefixed with `indent` and contains at most
/// `bytes_per_line` bytes (`bytes_per_line * 2` hex characters).
/// An empty buffer prints `(empty)`.
pub fn print_hex_block(bytes: &[u8], indent: &str, bytes_per_line: usize) {
    if bytes.is_empty() {
        println!("{}(empty)", indent);
        return;
    }
    let chunk_chars = bytes_per_line * 2;
    let hex = hex::encode(bytes);
    for line in hex.as_bytes().chunks(chunk_chars) {
        // Safe: hex::encode produces ASCII only.
        println!("{}{}", indent, core::str::from_utf8(line).unwrap());
    }
}

fn format_uuid(bytes: &[u8]) -> String {
    if bytes.len() == 16 {
        format!(
            "{}-{}-{}-{}-{}",
            hex::encode(&bytes[0..4]),
            hex::encode(&bytes[4..6]),
            hex::encode(&bytes[6..8]),
            hex::encode(&bytes[8..10]),
            hex::encode(&bytes[10..16]),
        )
    } else {
        hex::encode(bytes)
    }
}
