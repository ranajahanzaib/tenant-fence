use crate::{
    config::{Config, Tenant},
    spec::Operation,
};
use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use url::Url;

#[derive(Debug)]
/// A bounded in-memory response; never serialized as raw report evidence.
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
    pub elapsed_ms: u128,
}
impl Response {
    pub fn json(&self) -> Result<Value> {
        serde_json::from_slice(&self.body).context("response is not valid JSON")
    }
    pub fn success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}
/// Serial authenticated transport enforcing scope, rate, time and request budgets.
pub struct Executor {
    client: reqwest::Client,
    pub config: Config,
    tokens: Vec<String>,
    pub used: usize,
    last: Option<Instant>,
}
/// Safely substitute declared path/query parameters and verify the final origin.
pub fn request_url(base: &Url, op: &Operation, values: &BTreeMap<String, String>) -> Result<Url> {
    let mut path = op.path.clone();
    for p in &op.parameters {
        if p.location == "path" {
            let value = values
                .get(&p.name)
                .with_context(|| format!("missing path parameter {}", p.name))?;
            ensure!(
                !value.is_empty() && value != "." && value != "..",
                "unsafe empty/dot path parameter"
            );
            let encoded: String = url::form_urlencoded::byte_serialize(value.as_bytes()).collect();
            path = path.replace(&format!("{{{}}}", p.name), &encoded.replace('+', "%20"));
        }
    }
    ensure!(!path.contains(['{', '}']), "unresolved path parameters");
    let mut url = base.join(&path).context("construct request URL")?;
    ensure!(
        url.origin() == base.origin(),
        "request URL escaped authorized origin"
    );
    for p in &op.parameters {
        if p.location == "query" {
            if let Some(value) = values.get(&p.name) {
                url.query_pairs_mut().append_pair(&p.name, value);
            } else {
                ensure!(!p.required, "missing query parameter {}", p.name);
            }
        }
    }
    Ok(url)
}
impl Executor {
    pub fn new(config: Config, tokens: Vec<String>) -> Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(Duration::from_millis(config.target.timeout_ms))
            .build()
            .context("create TLS HTTP client")?;
        Ok(Self {
            client,
            config,
            tokens,
            used: 0,
            last: None,
        })
    }
    pub fn remaining(&self) -> usize {
        self.config.execution.max_requests.saturating_sub(self.used)
    }
    pub async fn send(
        &mut self,
        tenant: usize,
        op: &Operation,
        values: &BTreeMap<String, String>,
        body: Option<&Value>,
    ) -> Result<Response> {
        let retries = if op.method == "GET" {
            self.config.execution.safe_retries
        } else {
            0
        };
        for attempt in 0..=retries {
            let result = self.once(tenant, op, values, body).await;
            match result {
                Ok(r) if r.status != 429 && r.status < 500 => return Ok(r),
                Ok(r) if attempt == retries => return Ok(r),
                Err(e) if attempt == retries => return Err(e),
                _ => {}
            }
        }
        bail!("safe request retries exhausted")
    }
    async fn once(
        &mut self,
        tenant: usize,
        op: &Operation,
        values: &BTreeMap<String, String>,
        body: Option<&Value>,
    ) -> Result<Response> {
        ensure!(self.remaining() > 0, "request budget exhausted");
        let url = request_url(&self.config.target.base_url, op, values)?;
        ensure!(
            self.config
                .target
                .allowed_origins
                .contains(&url.origin().ascii_serialization()),
            "request origin is not allowlisted"
        );
        let interval =
            Duration::from_secs_f64(1.0 / self.config.execution.requests_per_second as f64);
        if let Some(last) = self.last {
            tokio::time::sleep(interval.saturating_sub(last.elapsed())).await;
        }
        self.last = Some(Instant::now());
        self.used += 1;
        let t: &Tenant = &self.config.tenants[tenant];
        let mut request = self
            .client
            .request(reqwest::Method::from_bytes(op.method.as_bytes())?, url)
            .bearer_auth(&self.tokens[tenant]);
        for (k, v) in &t.headers {
            request = request.header(k, v);
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let start = Instant::now();
        // Intentionally discard reqwest error strings: they may contain URLs or headers.
        let mut response = request
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("HTTP transport failure or timeout"))?;
        let status = response.status().as_u16();
        let max = self.config.target.max_response_bytes;
        ensure!(
            response.content_length().is_none_or(|n| n <= max as u64),
            "response exceeds configured size limit"
        );
        let mut data = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow::anyhow!("response stream failure"))?
        {
            ensure!(
                data.len().saturating_add(chunk.len()) <= max,
                "response exceeds configured size limit"
            );
            data.extend_from_slice(&chunk);
        }
        Ok(Response {
            status,
            body: data,
            elapsed_ms: start.elapsed().as_millis(),
        })
    }
}
