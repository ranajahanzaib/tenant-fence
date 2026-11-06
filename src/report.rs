use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Evidence-based outcome; uncertainty is distinct from a confirmed failure.
pub enum Status {
    Passed,
    Failure,
    Inconclusive,
    Skipped,
    Error,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Sanitized observation, reproduction context and cleanup outcome for one test.
pub struct TestResult {
    pub id: String,
    pub category: String,
    pub resource: String,
    pub operation_id: String,
    pub method: String,
    pub path: String,
    pub attacker: String,
    pub owner: String,
    pub expected: String,
    pub actual: String,
    pub status: Status,
    pub severity: String,
    pub confidence: String,
    pub evidence: BTreeMap<String, String>,
    pub reproduction: String,
    pub remediation: String,
    pub impact: String,
    pub cleanup: Option<String>,
    pub required: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Version-one portable report shared by JSON, HTML and terminal output.
pub struct Report {
    pub schema_version: u32,
    pub tool_version: String,
    pub target: String,
    pub started_unix_seconds: u64,
    pub duration_ms: u128,
    pub requests: usize,
    pub safe_settings: crate::config::Execution,
    pub safe_network: BTreeMap<String, String>,
    pub coverage: Vec<String>,
    pub results: Vec<TestResult>,
    pub errors: Vec<String>,
}
impl Report {
    pub fn exit_code(&self) -> i32 {
        if !self.errors.is_empty()
            || self.results.iter().any(|r| {
                r.status == Status::Error
                    || (r.required && matches!(r.status, Status::Inconclusive | Status::Skipped))
            })
        {
            2
        } else if self.results.iter().any(|r| r.status == Status::Failure) {
            1
        } else {
            0
        }
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "report.schema_version: only version 1 supported"
        );
        ensure!(
            !self.tool_version.is_empty() && !self.target.is_empty(),
            "report metadata missing"
        );
        let mut ids = std::collections::BTreeSet::new();
        for r in &self.results {
            ensure!(ids.insert(&r.id), "report.results: duplicate test ID");
            ensure!(
                ["read", "collection", "export", "mutation"].contains(&r.category.as_str()),
                "report.results.category: invalid"
            );
            ensure!(
                ["high", "info"].contains(&r.severity.as_str()),
                "report.results.severity: invalid"
            );
            ensure!(
                r.status != Status::Failure || r.confidence == "confirmed",
                "report failure must have confirmed evidence"
            );
        }
        Ok(())
    }
    pub fn write(&self, directory: &Path) -> Result<()> {
        self.validate()?;
        std::fs::create_dir_all(directory)?;
        std::fs::write(
            directory.join("report.json"),
            serde_json::to_vec_pretty(self)?,
        )?;
        std::fs::write(directory.join("report.html"), self.html())?;
        Ok(())
    }
    /// Replace known credential values throughout every serialized report field.
    pub fn redact(&mut self, secrets: &[String]) -> Result<()> {
        let mut patterns = Vec::new();
        for secret in secrets.iter().filter(|s| !s.is_empty()) {
            patterns.push(secret.clone());
            let encoded: String = url::form_urlencoded::byte_serialize(secret.as_bytes()).collect();
            patterns.push(encoded.replace('+', "%20"));
            patterns.push(encoded);
        }
        patterns.sort_by_key(|p| std::cmp::Reverse(p.len()));
        patterns.dedup();
        let scrub = |s: &mut String| {
            for pattern in &patterns {
                *s = s.replace(pattern, "[REDACTED]");
            }
        };
        // Scrub all data-bearing strings, preserving schema enums even if a token
        // happens to equal a public category name such as "read".
        scrub(&mut self.target);
        for s in self.safe_network.values_mut() {
            scrub(s);
        }
        for s in self.coverage.iter_mut().chain(self.errors.iter_mut()) {
            scrub(s);
        }
        for r in &mut self.results {
            for s in [
                &mut r.id,
                &mut r.resource,
                &mut r.operation_id,
                &mut r.path,
                &mut r.attacker,
                &mut r.owner,
                &mut r.expected,
                &mut r.actual,
                &mut r.reproduction,
                &mut r.remediation,
                &mut r.impact,
            ] {
                scrub(s);
            }
            for s in r.evidence.values_mut() {
                scrub(s);
            }
            if let Some(s) = &mut r.cleanup {
                scrub(s);
            }
        }
        Ok(())
    }
    pub fn summary(&self) -> String {
        format!(
            "{} tests · {} passed · {} confirmed failures · {} inconclusive · {} skipped · {} errors · {} requests · {} ms · exit {}",
            self.results.len(),
            self.count(Status::Passed),
            self.count(Status::Failure),
            self.count(Status::Inconclusive),
            self.count(Status::Skipped),
            self.count(Status::Error) + self.errors.len(),
            self.requests,
            self.duration_ms,
            self.exit_code()
        )
    }
    fn count(&self, status: Status) -> usize {
        self.results.iter().filter(|r| r.status == status).count()
    }
    pub fn html(&self) -> String {
        let date = chrono::DateTime::from_timestamp(
            self.started_unix_seconds.min(i64::MAX as u64) as i64,
            0,
        )
        .map(|d| d.to_rfc3339())
        .unwrap_or_else(|| self.started_unix_seconds.to_string());
        let mut cards = String::new();
        for r in &self.results {
            let status = serde_json::to_value(&r.status)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default();
            let mut evidence = String::new();
            for (k, v) in &r.evidence {
                evidence.push_str(&format!("<dt>{}</dt><dd>{}</dd>", escape(k), escape(v)));
            }
            cards.push_str(&format!(r#"<article data-status="{}" data-severity="{}"><div class="row"><span class="badge {}">{}</span><span>{} · {}</span></div><h2>{} / {}</h2><p><code>{} {}</code></p><p>Requester <strong>{}</strong> → owner <strong>{}</strong></p><dl><dt>Expected</dt><dd>{}</dd><dt>Observed</dt><dd>{}</dd><dt>Confidence</dt><dd>{}</dd><dt>Cleanup</dt><dd>{}</dd></dl><details><summary>Evidence and reproduction</summary><dl>{}</dl><pre><code>{}</code></pre><button type="button" class="copy">Copy reproduction</button><p>{}</p><p>{}</p></details></article>"#,status,escape(&r.severity),status,status,escape(&r.severity),escape(&r.operation_id),escape(&r.resource),escape(&r.category),escape(&r.method),escape(&r.path),escape(&r.attacker),escape(&r.owner),escape(&r.expected),escape(&r.actual),escape(&r.confidence),escape(r.cleanup.as_deref().unwrap_or("not applicable")),evidence,escape(&r.reproduction),escape(&r.impact),escape(&r.remediation)));
        }
        format!(
            r##"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>TenantFence report</title><style>
:root{{color-scheme:light dark;--bg:#10151c;--panel:#18202b;--fg:#e5ecf3;--muted:#abbacc;--line:#364355}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 system-ui,sans-serif}}main{{max-width:1060px;margin:auto;padding:48px 24px}}header{{border-bottom:1px solid var(--line);padding-bottom:24px}}.eyebrow{{color:#87dccc;letter-spacing:.14em;font-size:12px}}h1{{font-size:36px;letter-spacing:-.04em;margin:10px 0}}h2{{font-size:21px;margin:12px 0}}p{{overflow-wrap:anywhere}}.muted,dt{{color:var(--muted)}}.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(125px,1fr));gap:12px;margin:24px 0}}.stat,article{{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:20px}}.stat strong{{font-size:30px;display:block}}nav{{display:flex;gap:12px;flex-wrap:wrap;margin:24px 0}}input,select,button{{font:inherit;background:var(--panel);color:var(--fg);border:1px solid #718299;border-radius:4px;padding:8px}}input{{flex:1;min-width:180px}}article{{margin:18px 0}}.row{{display:flex;justify-content:space-between;gap:16px;font-size:13px;color:var(--muted)}}.badge{{padding:1px 9px;border:1px solid currentColor;border-radius:4px;text-transform:uppercase}}.failure,.error{{color:#ffb1ad}}.passed{{color:#87dccc}}.inconclusive{{color:#f8d58e}}dl{{display:grid;grid-template-columns:130px 1fr;gap:6px 18px}}dd{{margin:0;overflow-wrap:anywhere}}code,pre{{font-family:ui-monospace,monospace;font-size:13px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:var(--bg);padding:16px;border-radius:4px}}summary,button{{cursor:pointer}}:focus-visible{{outline:3px solid #87dccc;outline-offset:3px}}[hidden]{{display:none}}@media(max-width:600px){{dl{{grid-template-columns:1fr}}.row{{flex-wrap:wrap}}main{{padding:24px 16px}}}}
</style></head><body><main><header><div class="eyebrow">TENANTFENCE / ISOLATION REPORT / V1</div><h1>{}</h1><p class="muted">{} · {} ms · {} bounded HTTP requests</p></header><div class="stats"><div class="stat"><strong>{}</strong>Total tests</div><div class="stat"><strong>{}</strong>Passed</div><div class="stat"><strong>{}</strong>Confirmed failures</div><div class="stat"><strong>{}</strong>Inconclusive</div><div class="stat"><strong>{}</strong>Skipped</div><div class="stat"><strong>{}</strong>Errors</div></div><details><summary>Scope and operation coverage</summary><pre>{}</pre></details><p class="muted">{}</p><nav aria-label="Filter results"><input id="search" aria-label="Search results" placeholder="Search operations, tenants, evidence…"><select id="status" aria-label="Status"><option value="">All statuses</option><option>passed</option><option>failure</option><option>inconclusive</option><option>error</option><option>skipped</option></select><select id="severity" aria-label="Severity"><option value="">All severities</option><option>high</option><option>info</option></select></nav><div id="results">{}</div><footer class="muted">Black-box observations establish fixture exposure or state change, never the underlying SQL cause. Test only APIs you are authorized to assess.</footer></main><script>
const controls=['search','status','severity'].map(id=>document.getElementById(id));function filter(){{const [q,s,v]=controls.map(x=>x.value.toLowerCase());document.querySelectorAll('article').forEach(a=>a.hidden=!(a.textContent.toLowerCase().includes(q)&&(!s||a.dataset.status===s)&&(!v||a.dataset.severity===v)))}}controls.forEach(c=>c.addEventListener('input',filter));document.querySelectorAll('.copy').forEach(b=>b.addEventListener('click',async()=>{{try{{await navigator.clipboard.writeText(b.previousElementSibling.textContent);b.textContent='Copied'}}catch{{b.textContent='Select the command above to copy'}}}}));
</script></body></html>"##,
            escape(&self.target),
            escape(&date),
            self.duration_ms,
            self.requests,
            self.results.len(),
            self.count(Status::Passed),
            self.count(Status::Failure),
            self.count(Status::Inconclusive),
            self.count(Status::Skipped),
            self.count(Status::Error) + self.errors.len(),
            escape(&self.coverage.join("\n")),
            escape(&self.errors.join("; ")),
            cards
        )
    }
}
/// Escape dynamic text for HTML text and quoted attribute contexts.
pub fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
