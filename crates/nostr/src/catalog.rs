// SPDX-License-Identifier: AGPL-3.0-or-later
//! Versioned author-signed catalog and rating evidence. No install authority.

use crate::{Event, EventId, PublicKey, Refusal, Result, SecretKey, VerifiedEvent};
use base64::{engine::general_purpose::STANDARD, Engine};
use canon::{digest::Digest32, json};
use serde::Serialize;
use std::collections::BTreeMap;

pub const PUBLICATION_KIND: u16 = 30_078;
pub const RATING_KIND: u16 = 1_985;
pub const PUBLICATION_SCHEMA: &str = "aukora-app-publication-v1";
pub const RATING_SCHEMA: &str = "aukora-app-rating-v1";
pub const CATALOG_TOPIC: &str = "aukora-app";
pub const MAX_MANIFEST_BYTES: usize = 16_384;
pub const MAX_CATALOG_EVENTS: usize = 1_024;
pub const MAX_RESULTS: u16 = 100;
pub const MAX_RATING_TEXT_BYTES: usize = 1_024;
const MANIFEST_SCHEMA: &str = "aukora-app-manifest-v1";
const MANIFEST_DOMAIN: &[u8] = b"aukora:app-manifest:v1\0";
const SIGNATURE_ALGORITHM: &str = "secp256k1-schnorr";
const MAX_SECONDS: u64 = 9_007_199_254_740_991;

/// Signed publication evidence only; no grant, passkey or installation capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogEntry {
    pub format_version: u16,
    pub author: PublicKey,
    pub package_sha256: Digest32,
    pub manifest_bytes: Vec<u8>,
}

/// The signature is checked by `VerifiedEvent`; content is canonical C1 JSON.
/// Manifest bytes remain exact, untrusted data for the install verifier.
pub fn decode(event: &VerifiedEvent) -> Result<CatalogEntry> {
    let event = event.event();
    if event.kind != PUBLICATION_KIND {
        return Err(refusal("catalog-kind"));
    }
    let content = canonical(event.content.as_bytes(), "catalog-content")?;
    exact_object(&content, &["body", "schema"])?;
    if text(&content, "schema")? != PUBLICATION_SCHEMA {
        return Err(refusal("catalog-version"));
    }
    let body = field(&content, "body")?;
    exact_object(body, &["algorithm", "manifest_b64", "package_sha256"])?;
    check_algorithm(body)?;
    let package_sha256 = digest(body, "package_sha256")?;
    if event.tags != publication_tags(package_sha256) {
        return Err(refusal("catalog-tags"));
    }
    let encoded = text(body, "manifest_b64")?;
    if encoded.len() > MAX_MANIFEST_BYTES.div_ceil(3) * 4 {
        return Err(refusal("catalog-manifest-bounds"));
    }
    let manifest_bytes = STANDARD
        .decode(encoded)
        .map_err(|_| refusal("catalog-manifest-encoding"))?;
    if STANDARD.encode(&manifest_bytes) != encoded {
        return Err(refusal("catalog-manifest-encoding"));
    }
    check_manifest(&manifest_bytes, event.pubkey, package_sha256)?;
    Ok(CatalogEntry {
        format_version: 1,
        author: event.pubkey,
        package_sha256,
        manifest_bytes,
    })
}

/// Signs a publication with the author key. Does not publish or open a socket.
pub fn publication(
    author: &SecretKey,
    created_at_seconds: u64,
    package_sha256: Digest32,
    manifest_bytes: &[u8],
) -> Result<VerifiedEvent> {
    check_manifest(manifest_bytes, author.public_key()?, package_sha256)?;
    let content = encode(&Envelope {
        schema: PUBLICATION_SCHEMA,
        body: PublicationBody {
            algorithm: SIGNATURE_ALGORITHM,
            manifest_b64: STANDARD.encode(manifest_bytes),
            package_sha256: package_sha256.to_string(),
        },
    })?;
    Event::sign(
        author,
        created_at_seconds,
        PUBLICATION_KIND,
        publication_tags(package_sha256),
        content,
    )
}

/// Local discovery parameters. Relay I/O remains the relay crate's work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogQuery {
    pub author: Option<PublicKey>,
    pub text: String,
    pub since_seconds: Option<u64>,
    pub until_seconds: Option<u64>,
    pub limit: u16,
}

/// The event identity and time are retained so ratings can name exact evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Publication {
    pub id: EventId,
    pub created_at_seconds: u64,
    pub entry: CatalogEntry,
}

/// Emits a Nostr subscription filter. Text search is local to signed manifests.
pub fn discovery_filter(query: &CatalogQuery) -> Result<Vec<u8>> {
    check_query(query)?;
    let mut filter = BTreeMap::new();
    filter.insert("#t", serde_json::json!([CATALOG_TOPIC]));
    filter.insert("kinds", serde_json::json!([PUBLICATION_KIND]));
    filter.insert("limit", serde_json::json!(query.limit));
    if let Some(author) = query.author {
        filter.insert(
            "authors",
            serde_json::json!([hex::encode(author.as_bytes())]),
        );
    }
    if let Some(since) = query.since_seconds {
        filter.insert("since", serde_json::json!(since));
    }
    if let Some(until) = query.until_seconds {
        filter.insert("until", serde_json::json!(until));
    }
    let bytes = serde_json::to_vec(&filter).map_err(|_| refusal("catalog-encoding"))?;
    Ok(canonical(&bytes, "catalog-encoding")?.canonical_bytes())
}

/// Refuses malformed evidence; selects one newest publication per author/hash.
/// Equal timestamps use the lower event id. Sorting never considers ratings.
pub fn discover(events: &[VerifiedEvent], query: &CatalogQuery) -> Result<Vec<Publication>> {
    check_query(query)?;
    if events.len() > MAX_CATALOG_EVENTS {
        return Err(refusal("catalog-bounds"));
    }
    let needle = query.text.to_lowercase();
    let mut publications: BTreeMap<(PublicKey, Digest32), Publication> = BTreeMap::new();
    for signed in events {
        let entry = decode(signed)?;
        let event = signed.event();
        if query.author.is_some_and(|author| author != entry.author)
            || query
                .since_seconds
                .is_some_and(|since| event.created_at < since)
            || query
                .until_seconds
                .is_some_and(|until| event.created_at > until)
        {
            continue;
        }
        if !needle.is_empty() {
            let manifest = canonical(&entry.manifest_bytes, "catalog-manifest")?;
            let body = field(&manifest, "body")?;
            let matches = ["id", "name", "version"]
                .into_iter()
                .map(|name| text(body, name))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .any(|value| value.to_lowercase().contains(&needle));
            if !matches {
                continue;
            }
        }
        let key = (entry.author, entry.package_sha256);
        let candidate = Publication {
            id: event.id,
            created_at_seconds: event.created_at,
            entry,
        };
        let replace = publications.get(&key).is_none_or(|current| {
            candidate.created_at_seconds > current.created_at_seconds
                || (candidate.created_at_seconds == current.created_at_seconds
                    && candidate.id < current.id)
        });
        if replace {
            publications.insert(key, candidate);
        }
    }
    let mut publications: Vec<_> = publications.into_values().collect();
    publications.sort_by(|left, right| {
        right
            .created_at_seconds
            .cmp(&left.created_at_seconds)
            .then(left.id.cmp(&right.id))
    });
    publications.truncate(usize::from(query.limit));
    Ok(publications)
}

/// A signed review of one publication. This type carries no owner capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RatingEvidence {
    pub id: EventId,
    pub reviewer: PublicKey,
    pub publication: EventId,
    pub package_sha256: Digest32,
    pub created_at_seconds: u64,
    pub rating: u8,
    pub text: String,
}

/// Requires both publication and rating to be verified author signatures.
pub fn decode_rating(event: &VerifiedEvent, published: &VerifiedEvent) -> Result<RatingEvidence> {
    let entry = decode(published)?;
    let event = event.event();
    if event.kind != RATING_KIND {
        return Err(refusal("catalog-kind"));
    }
    if event.tags != rating_tags(published) {
        return Err(refusal("catalog-rating-target"));
    }
    let content = canonical(event.content.as_bytes(), "catalog-content")?;
    exact_object(&content, &["body", "schema"])?;
    if text(&content, "schema")? != RATING_SCHEMA {
        return Err(refusal("catalog-version"));
    }
    let body = field(&content, "body")?;
    exact_object(body, &["algorithm", "package_sha256", "rating", "text"])?;
    check_algorithm(body)?;
    if digest(body, "package_sha256")? != entry.package_sha256 {
        return Err(refusal("catalog-rating-target"));
    }
    let json::ValueView::Integer(score) = field(body, "rating")?.view() else {
        return Err(refusal("catalog-rating-value"));
    };
    let rating = u8::try_from(score.get()).map_err(|_| refusal("catalog-rating-value"))?;
    let text = text(body, "text")?.to_owned();
    check_rating(rating, &text)?;
    Ok(RatingEvidence {
        id: event.id,
        reviewer: event.pubkey,
        publication: published.event().id,
        package_sha256: entry.package_sha256,
        created_at_seconds: event.created_at,
        rating,
        text,
    })
}

/// Emits a Nostr filter for reviews naming this exact signed publication.
pub fn rating_filter(published: &VerifiedEvent, limit: u16) -> Result<Vec<u8>> {
    decode(published)?;
    if limit == 0 || limit > MAX_RESULTS {
        return Err(refusal("catalog-query"));
    }
    let filter = serde_json::json!({
        "#e": [hex::encode(published.event().id.as_bytes())],
        "#t": [CATALOG_TOPIC],
        "kinds": [RATING_KIND],
        "limit": limit,
    });
    let bytes = serde_json::to_vec(&filter).map_err(|_| refusal("catalog-encoding"))?;
    Ok(json::parse_strict(&bytes)
        .map_err(|_| refusal("catalog-encoding"))?
        .canonical_bytes())
}

/// Creates signed rating evidence; it has no bearing on install authorization.
pub fn rating(
    reviewer: &SecretKey,
    created_at_seconds: u64,
    published: &VerifiedEvent,
    rating: u8,
    text: &str,
) -> Result<VerifiedEvent> {
    let entry = decode(published)?;
    check_rating(rating, text)?;
    Event::sign(
        reviewer,
        created_at_seconds,
        RATING_KIND,
        rating_tags(published),
        encode(&Envelope {
            schema: RATING_SCHEMA,
            body: RatingBody {
                algorithm: SIGNATURE_ALGORITHM,
                package_sha256: entry.package_sha256.to_string(),
                rating,
                text,
            },
        })?,
    )
}

/// Keeps at most one latest rating per reviewer, without computing trust.
pub fn ratings(events: &[VerifiedEvent], published: &VerifiedEvent) -> Result<Vec<RatingEvidence>> {
    if events.len() > MAX_CATALOG_EVENTS {
        return Err(refusal("catalog-bounds"));
    }
    decode(published)?;
    let mut by_reviewer: BTreeMap<PublicKey, RatingEvidence> = BTreeMap::new();
    for signed in events {
        let candidate = decode_rating(signed, published)?;
        let replace = by_reviewer.get(&candidate.reviewer).is_none_or(|current| {
            candidate.created_at_seconds > current.created_at_seconds
                || (candidate.created_at_seconds == current.created_at_seconds
                    && candidate.id < current.id)
        });
        if replace {
            by_reviewer.insert(candidate.reviewer, candidate);
        }
    }
    Ok(by_reviewer.into_values().collect())
}

#[derive(Serialize)]
struct Envelope<T> {
    schema: &'static str,
    body: T,
}

#[derive(Serialize)]
struct PublicationBody {
    algorithm: &'static str,
    manifest_b64: String,
    package_sha256: String,
}

#[derive(Serialize)]
struct RatingBody<'a> {
    algorithm: &'static str,
    package_sha256: String,
    rating: u8,
    text: &'a str,
}

fn encode<T: Serialize>(value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value).map_err(|_| refusal("catalog-encoding"))?;
    let canonical = json::parse_strict(&bytes)
        .map_err(|_| refusal("catalog-encoding"))?
        .canonical_bytes();
    String::from_utf8(canonical).map_err(|_| refusal("catalog-encoding"))
}

fn canonical(bytes: &[u8], reason: &'static str) -> Result<json::Value> {
    let value = json::parse_strict(bytes).map_err(|_| refusal(reason))?;
    if value.canonical_bytes() != bytes {
        return Err(refusal(reason));
    }
    Ok(value)
}

fn check_manifest(bytes: &[u8], expected_author: PublicKey, package: Digest32) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_MANIFEST_BYTES {
        return Err(refusal("catalog-manifest-bounds"));
    }
    let value = canonical(bytes, "catalog-manifest")?;
    exact_object(&value, &["body", "schema", "signature"])?;
    if text(&value, "schema")? != MANIFEST_SCHEMA {
        return Err(refusal("catalog-manifest"));
    }
    let body = field(&value, "body")?;
    exact_object(
        body,
        &[
            "face",
            "grants",
            "id",
            "name",
            "package_sha256",
            "runtime",
            "version",
        ],
    )?;
    if digest(body, "package_sha256")? != package {
        return Err(refusal("catalog-manifest-package"));
    }
    let id = text(body, "id")?;
    if id.len() != 32
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(refusal("catalog-manifest-id"));
    }
    let name = text(body, "name")?;
    if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
        return Err(refusal("catalog-manifest-name"));
    }
    let version = text(body, "version")?;
    if version.is_empty()
        || version.len() > 64
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(refusal("catalog-manifest-version"));
    }
    check_grants(field(body, "grants")?)?;
    let runtime = field(body, "runtime")?;
    exact_object(runtime, &["entry", "exec", "kind", "network", "wasi"])?;
    if text(runtime, "kind")? != "user-app" {
        return Err(refusal("catalog-manifest-runtime"));
    }
    for denied in ["exec", "network", "wasi"] {
        if !matches!(
            field(runtime, denied)?.view(),
            json::ValueView::Boolean(false)
        ) {
            return Err(refusal("catalog-manifest-runtime"));
        }
    }
    let runtime_entry = text(runtime, "entry")?;
    check_entry(runtime_entry)?;
    if !runtime_entry.ends_with(".wasm") {
        return Err(refusal("catalog-manifest-runtime"));
    }
    let face = field(body, "face")?;
    exact_object(face, &["entry"])?;
    let face_entry = text(face, "entry")?;
    check_entry(face_entry)?;
    if !face_entry.ends_with(".html") {
        return Err(refusal("catalog-manifest-face"));
    }
    let signature = field(&value, "signature")?;
    exact_object(signature, &["algorithm", "public_key", "signature", "v"])?;
    check_algorithm(signature)?;
    if !matches!(field(signature, "v")?.view(), json::ValueView::Integer(version) if version.get() == 1)
    {
        return Err(refusal("catalog-manifest-signature"));
    }
    let author = PublicKey::from_hex(text(signature, "public_key")?)
        .map_err(|_| refusal("catalog-manifest-signature"))?;
    if author != expected_author {
        return Err(refusal("catalog-manifest-author"));
    }
    let encoded = text(signature, "signature")?;
    if encoded.len() != 128
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(refusal("catalog-manifest-signature"));
    }
    let mut sig = [0u8; 64];
    hex::decode_to_slice(encoded, &mut sig).map_err(|_| refusal("catalog-manifest-signature"))?;
    let mut commitment = MANIFEST_DOMAIN.to_vec();
    commitment.extend(body.canonical_bytes());
    let commitment = Digest32::sha256(&commitment);
    crate::keys::verify(&author, commitment.as_bytes(), &sig)
        .map_err(|_| refusal("catalog-manifest-signature"))?;
    Ok(())
}

fn check_algorithm(value: &json::Value) -> Result<()> {
    if text(value, "algorithm")? != SIGNATURE_ALGORITHM {
        return Err(refusal("catalog-algorithm"));
    }
    Ok(())
}

fn check_grants(value: &json::Value) -> Result<()> {
    let json::ValueView::Array(grants) = value.view() else {
        return Err(refusal("catalog-manifest-grants"));
    };
    let allowed = [
        "app.clock",
        "app.random",
        "app.storage.read",
        "app.storage.write",
    ];
    if grants.len() > allowed.len() {
        return Err(refusal("catalog-manifest-grants"));
    }
    let mut previous = None;
    for grant in grants {
        let json::ValueView::Text(grant) = grant.view() else {
            return Err(refusal("catalog-manifest-grants"));
        };
        if !allowed.contains(&grant) || previous.is_some_and(|prior| prior >= grant) {
            return Err(refusal("catalog-manifest-grants"));
        }
        previous = Some(grant);
    }
    Ok(())
}

fn check_entry(entry: &str) -> Result<()> {
    if entry.is_empty()
        || entry.len() > 128
        || !entry
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
        || entry
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return Err(refusal("catalog-manifest-entry"));
    }
    Ok(())
}

fn check_query(query: &CatalogQuery) -> Result<()> {
    if query.limit == 0
        || query.limit > MAX_RESULTS
        || query.text.len() > 256
        || query.text.chars().any(char::is_control)
        || query.since_seconds.is_some_and(|time| time > MAX_SECONDS)
        || query.until_seconds.is_some_and(|time| time > MAX_SECONDS)
        || matches!((query.since_seconds, query.until_seconds), (Some(since), Some(until)) if since > until)
    {
        return Err(refusal("catalog-query"));
    }
    Ok(())
}

fn check_rating(rating: u8, text: &str) -> Result<()> {
    if !(1..=5).contains(&rating) || text.len() > MAX_RATING_TEXT_BYTES {
        return Err(refusal("catalog-rating-value"));
    }
    if text
        .chars()
        .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\r' | '\t'))
    {
        return Err(refusal("catalog-rating-value"));
    }
    Ok(())
}

fn exact_object(value: &json::Value, names: &[&str]) -> Result<()> {
    let json::ValueView::Object(members) = value.view() else {
        return Err(refusal("catalog-fields"));
    };
    if members.len() != names.len()
        || members
            .iter()
            .any(|(key, _)| !names.contains(&key.as_str()))
    {
        return Err(refusal("catalog-fields"));
    }
    Ok(())
}

fn field<'a>(object: &'a json::Value, name: &str) -> Result<&'a json::Value> {
    object.get(name).ok_or_else(|| refusal("catalog-fields"))
}

fn text<'a>(object: &'a json::Value, name: &str) -> Result<&'a str> {
    match field(object, name)?.view() {
        json::ValueView::Text(value) => Ok(value),
        _ => Err(refusal("catalog-fields")),
    }
}

fn digest(object: &json::Value, name: &str) -> Result<Digest32> {
    Digest32::from_hex(text(object, name)?).map_err(|_| refusal("catalog-digest"))
}

fn publication_tags(package: Digest32) -> Vec<Vec<String>> {
    vec![
        vec!["d".into(), package.to_string()],
        vec!["t".into(), CATALOG_TOPIC.into()],
    ]
}

fn rating_tags(publication: &VerifiedEvent) -> Vec<Vec<String>> {
    vec![
        vec!["e".into(), hex::encode(publication.event().id.as_bytes())],
        vec![
            "p".into(),
            hex::encode(publication.event().pubkey.as_bytes()),
        ],
        vec!["t".into(), CATALOG_TOPIC.into()],
    ]
}

const fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "nostr",
        reason,
    }
}
