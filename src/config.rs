use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use url::Url;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// A validated two-tenant testing scenario loaded from YAML.
pub struct Config {
    pub target: Target,
    pub tenants: Vec<Tenant>,
    pub resources: Vec<Resource>,
    pub execution: Execution,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// Network scope and hard per-response execution bounds.
pub struct Target {
    pub label: String,
    pub spec: PathBuf,
    pub base_url: Url,
    pub allowed_origins: Vec<String>,
    pub timeout_ms: u64,
    pub max_response_bytes: usize,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// Controlled test identity; credentials are referenced by environment name.
pub struct Tenant {
    pub name: String,
    pub token_env: String,
    pub selector: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// Explicit operation, fixture and private-evidence mappings.
pub struct Resource {
    pub name: String,
    pub discovery: Option<String>,
    #[serde(default)]
    pub fixtures: BTreeMap<String, Vec<String>>,
    pub collection_pointer: String,
    pub id_pointer: String,
    pub read: String,
    pub id_parameter: String,
    pub owner_pointer: String,
    pub marker_pointer: String,
    pub collection: Option<String>,
    pub tenant_parameter: Option<String>,
    pub export: Option<String>,
    #[serde(default)]
    pub export_format: ExportFormat,
    pub mutation: Option<Mutation>,
    pub denial_statuses: Vec<u16>,
    #[serde(default)]
    pub empty_collection_allowed: bool,
    #[serde(default)]
    pub parameters: BTreeMap<String, String>,
}
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
/// Supported synchronous export encodings.
pub enum ExportFormat {
    #[default]
    Json,
    Csv,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// An explicitly authorized reversible PATCH on a disposable fixture.
pub struct Mutation {
    pub operation: String,
    pub disposable: bool,
    pub value_pointer: String,
    pub body_pointer: String,
    pub body: Value,
    #[serde(default)]
    pub body_parameters: BTreeMap<String, String>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// Global limits and required coverage categories.
pub struct Execution {
    pub max_requests: usize,
    pub max_resources_per_tenant: usize,
    pub max_concurrency: usize,
    pub requests_per_second: u32,
    pub safe_retries: u8,
    pub writes: bool,
    pub exports: bool,
    pub required: Vec<String>,
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).context("read configuration")?;
        let mut c: Self = serde_saphyr::from_str(&raw).context("parse tenantfence YAML")?;
        c.target.spec = path.parent().unwrap_or(Path::new(".")).join(&c.target.spec);
        c.validate()?;
        Ok(c)
    }
    pub fn validate(&self) -> Result<()> {
        let u = &self.target.base_url;
        ensure!(
            u.username().is_empty()
                && u.password().is_none()
                && u.query().is_none()
                && u.fragment().is_none(),
            "target.base_url: credentials, query and fragment are forbidden"
        );
        ensure!(
            u.path() == "/",
            "target.base_url: use an origin with no path prefix; include prefixes in OpenAPI paths"
        );
        let local = matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        ensure!(
            u.scheme() == "https" || (u.scheme() == "http" && local),
            "target.base_url: HTTPS required except literal loopback hosts"
        );
        ensure!(
            self.target
                .allowed_origins
                .contains(&u.origin().ascii_serialization()),
            "target.allowed_origins: must explicitly contain base URL origin"
        );
        ensure!(
            self.target.timeout_ms > 0 && self.target.timeout_ms <= 120_000,
            "target.timeout_ms: use 1..120000"
        );
        ensure!(
            (1..=16_777_216).contains(&self.target.max_response_bytes),
            "target.max_response_bytes: use 1..16777216"
        );
        ensure!(self.tenants.len() == 2, "tenants: exactly two required");
        ensure!(
            self.tenants[0].name != self.tenants[1].name
                && self.tenants[0].selector != self.tenants[1].selector,
            "tenants: names and selectors must be distinct"
        );
        for t in &self.tenants {
            ensure!(
                !t.name.is_empty() && !t.selector.is_empty(),
                "tenants: name and selector cannot be empty"
            );
            ensure!(
                !t.token_env.is_empty()
                    && t.token_env.bytes().enumerate().all(|(i, b)| b == b'_'
                        || b.is_ascii_alphabetic()
                        || (i > 0 && b.is_ascii_digit())),
                "tenants.token_env: expected environment variable name"
            );
            for (k, v) in &t.headers {
                ensure!(
                    k.to_ascii_lowercase().starts_with("x-")
                        && !k.to_ascii_lowercase().contains("token")
                        && !k.to_ascii_lowercase().contains("key")
                        && !k.to_ascii_lowercase().contains("auth"),
                    "tenants.headers: only nonsecret X- headers allowed"
                );
                reqwest::header::HeaderName::from_bytes(k.as_bytes())
                    .context("tenants.headers: invalid name")?;
                reqwest::header::HeaderValue::from_str(v)
                    .context("tenants.headers: invalid value")?;
            }
        }
        let e = &self.execution;
        ensure!(
            e.max_requests > 0 && e.max_requests <= 100_000,
            "execution.max_requests: use 1..100000"
        );
        ensure!(
            (1..=100).contains(&e.max_resources_per_tenant),
            "execution.max_resources_per_tenant: use 1..100"
        );
        ensure!(
            e.max_concurrency == 1,
            "execution.max_concurrency: MVP supports 1 (serial fixture safety)"
        );
        ensure!(
            (1..=100).contains(&e.requests_per_second) && e.safe_retries <= 2,
            "execution: requests_per_second must be 1..100 and safe_retries 0..2"
        );
        for k in &e.required {
            ensure!(
                ["read", "collection", "export", "mutation"].contains(&k.as_str()),
                "execution.required: unknown category {k}"
            );
        }
        ensure!(
            !self.resources.is_empty(),
            "resources: at least one explicit mapping required"
        );
        let mut names = std::collections::BTreeSet::new();
        for r in &self.resources {
            ensure!(
                names.insert(&r.name),
                "resources.name: duplicate {}",
                r.name
            );
            ensure!(
                r.discovery.is_some()
                    || self
                        .tenants
                        .iter()
                        .all(|t| r.fixtures.get(&t.name).is_some_and(|v| !v.is_empty())),
                "resources.{}: supply discovery or fixtures for both tenants",
                r.name
            );
            ensure!(
                r.denial_statuses.iter().all(|s| *s == 403 || *s == 404)
                    && !r.denial_statuses.is_empty(),
                "resources.denial_statuses: explicit 403 and/or 404 required"
            );
            for p in [
                &r.collection_pointer,
                &r.id_pointer,
                &r.owner_pointer,
                &r.marker_pointer,
            ] {
                ensure!(
                    p.is_empty() || p.starts_with('/'),
                    "resources: expected JSON Pointer, got {p}"
                );
            }
            ensure!(
                !r.owner_pointer.is_empty() && !r.marker_pointer.is_empty(),
                "resources: owner_pointer and unique marker_pointer are required"
            );
            ensure!(
                r.collection.is_none() || r.tenant_parameter.is_some(),
                "resources.tenant_parameter: required for collection"
            );
            if let Some(m) = &r.mutation {
                for (pointer, name) in &m.body_parameters {
                    ensure!(
                        m.body.pointer(pointer).is_some(),
                        "resources.mutation.body_parameters: pointer must exist in body"
                    );
                    ensure!(
                        name == &r.id_parameter
                            || Some(name) == r.tenant_parameter.as_ref()
                            || r.parameters.contains_key(name),
                        "resources.mutation.body_parameters: unknown mapped parameter"
                    );
                    ensure!(
                        pointer != &m.body_pointer,
                        "resources.mutation.body_parameters: cannot replace mutable value pointer"
                    );
                }
                ensure!(
                    m.disposable,
                    "resources.mutation.disposable: must explicitly be true"
                );
                ensure!(
                    m.value_pointer.starts_with('/') && m.body_pointer.starts_with('/'),
                    "resources.mutation: pointers must be non-root JSON pointers"
                );
                ensure!(
                    m.body.pointer(&m.body_pointer).is_some(),
                    "resources.mutation.body_pointer: must exist in body template"
                );
            }
        }
        for category in &e.required {
            let supported = match category.as_str() {
                "read" => true,
                "collection" => self.resources.iter().any(|r| r.collection.is_some()),
                "export" => e.exports && self.resources.iter().any(|r| r.export.is_some()),
                "mutation" => e.writes && self.resources.iter().any(|r| r.mutation.is_some()),
                _ => false,
            };
            ensure!(
                supported,
                "execution.required: {category} is disabled or unmapped"
            );
        }
        Ok(())
    }
    pub fn credentials(&self) -> Result<Vec<String>> {
        let mut tokens = Vec::new();
        for t in &self.tenants {
            let value = std::env::var(&t.token_env).with_context(|| {
                format!("missing credential environment variable {}", t.token_env)
            })?;
            if value.trim().is_empty()
                || reqwest::header::HeaderValue::from_str(&format!("Bearer {value}")).is_err()
            {
                bail!("invalid credential in {}", t.token_env);
            }
            tokens.push(value);
        }
        ensure!(
            tokens[0] != tokens[1],
            "tenant credentials must be distinct"
        );
        Ok(tokens)
    }
}
