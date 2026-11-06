use crate::{
    config::{Config, ExportFormat, Resource},
    http::{Executor, Response, request_url},
    report::{Report, Status, TestResult},
    spec::{Spec, scalar_id},
};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone)]
struct Fixture {
    owner: usize,
    id: String,
    marker: String,
    baseline: Value,
}
fn values(c: &Config, r: &Resource, owner: usize, id: &str) -> BTreeMap<String, String> {
    let mut v = r.parameters.clone();
    v.insert(r.id_parameter.clone(), id.into());
    if let Some(p) = &r.tenant_parameter {
        v.insert(p.clone(), c.tenants[owner].selector.clone());
    }
    v
}
fn protected_json(v: &Value, marker: &str) -> bool {
    match v {
        Value::String(s) => s == marker,
        Value::Array(a) => a.iter().any(|x| protected_json(x, marker)),
        Value::Object(o) => o.values().any(|x| protected_json(x, marker)),
        _ => false,
    }
}
/// Status alone never confirms exposure; exact known synthetic markers do.
pub fn evaluate(
    response: &Response,
    markers: &[String],
    denials: &[u16],
    csv: bool,
    empty_pointer: Option<&str>,
) -> (Status, String) {
    let parsed = response.json();
    // Inspect JSON even when CSV is the expected export format: APIs sometimes
    // return a JSON error envelope for a denied CSV request.
    let json_exposed = parsed
        .as_ref()
        .is_ok_and(|v| markers.iter().any(|m| protected_json(v, m)));
    let csv_records = csv.then(|| {
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(false)
            .from_reader(response.body.as_slice());
        reader.records().collect::<std::result::Result<Vec<_>, _>>()
    });
    let csv_exposed = csv_records.as_ref().is_some_and(|records| {
        records.as_ref().is_ok_and(|rows| {
            rows.iter()
                .any(|row| row.iter().any(|cell| markers.iter().any(|m| m == cell)))
        })
    });
    if json_exposed || csv_exposed {
        return (
            Status::Failure,
            "Verified private fixture marker exposed in response".into(),
        );
    }
    let body_inspected = parsed.is_ok() || csv_records.is_some_and(|records| records.is_ok());
    if denials.contains(&response.status) && (response.body.is_empty() || body_inspected) {
        return (
            Status::Passed,
            format!(
                "Denied with HTTP {}; no known private marker",
                response.status
            ),
        );
    }
    if let Some(pointer) = empty_pointer
        && response.success()
        && parsed
            .as_ref()
            .ok()
            .and_then(|v| v.pointer(pointer))
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
    {
        return (
            Status::Passed,
            "Declared empty filtered collection policy enforced".into(),
        );
    }
    (
        Status::Inconclusive,
        format!(
            "HTTP {} without sufficient proof of exposure or declared denial",
            response.status
        ),
    )
}
fn result(
    c: &Config,
    spec: &Spec,
    r: &Resource,
    f: &Fixture,
    category: &str,
    opid: &str,
) -> Result<TestResult> {
    let attacker = 1 - f.owner;
    let op = spec.op(opid)?;
    let url = request_url(&c.target.base_url, op, &values(c, r, f.owner, &f.id))?;
    let path = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().into(),
    };
    let token = &c.tenants[attacker].token_env;
    let escaped = url.as_str().replace('\'', "'\\''");
    Ok(TestResult {
        id:format!("{}:{}:{}:{}",r.name,category,f.owner,f.id),category:category.into(),resource:r.name.clone(),operation_id:opid.into(),method:op.method.clone(),path,
        attacker:c.tenants[attacker].name.clone(),owner:c.tenants[f.owner].name.clone(),expected:format!("Deny with {:?} without private data{}",r.denial_statuses,if category=="mutation"{" and preserve fixture state"}else{""}),
        actual:String::new(),status:Status::Inconclusive,severity:"info".into(),confidence:"inconclusive".into(),evidence:BTreeMap::new(),
        reproduction:if category=="mutation" {"Active test: repeat the explicitly configured disposable-fixture PATCH with a fresh marker; owner-read before and after, restore original value and verify. Use tenantfence run --authorized; do not replay blind writes.".into()} else {format!("curl --max-time 10 --max-redirs 0 -H \"Authorization: Bearer ${{{token}}}\" '{escaped}'")},
        impact: if category == "mutation" { "Failure of this boundary allows an authenticated tenant to alter another tenant’s private fixture state." } else { "Failure of this boundary allows an authenticated tenant to obtain another tenant’s private fixture data." }.into(),
        remediation:"Authorize each resource against the authenticated tenant on reads, updates, collections and exports. For D1, bind both id and tenant_id in every SELECT/UPDATE predicate. Parameterization alone does not enforce ownership. This observation cannot establish the underlying SQL cause.".into(),cleanup:None,required:c.execution.required.iter().any(|s|s==category),
    })
}
fn finish(result: &mut TestResult, status: Status, actual: String) {
    result.severity = if status == Status::Failure {
        "high"
    } else {
        "info"
    }
    .into();
    result.confidence = if status == Status::Failure {
        "confirmed"
    } else if status == Status::Passed {
        "verified"
    } else {
        "inconclusive"
    }
    .into();
    result.status = status;
    result.actual = actual;
}
fn record_response(result: &mut TestResult, response: &Response) {
    result
        .evidence
        .insert("http_status".into(), response.status.to_string());
    result
        .evidence
        .insert("response_bytes".into(), response.body.len().to_string());
    result
        .evidence
        .insert("duration_ms".into(), response.elapsed_ms.to_string());
}
fn verify_owner_identity(
    c: &Config,
    r: &Resource,
    owner: usize,
    id: &str,
    response: &Response,
) -> Result<Value> {
    ensure!(
        response.success(),
        "owner read-back rejected with HTTP {}",
        response.status
    );
    let value = response.json()?;
    ensure!(
        scalar_id(
            value
                .pointer(&r.id_pointer)
                .context("owner read-back ID pointer missing")?
        )? == id,
        "owner read-back returned a different resource ID"
    );
    ensure!(
        value.pointer(&r.owner_pointer).and_then(Value::as_str)
            == Some(c.tenants[owner].selector.as_str()),
        "owner read-back ownership does not match the fixture tenant"
    );
    Ok(value)
}

fn baseline(
    c: &Config,
    r: &Resource,
    owner: usize,
    id: &str,
    response: &Response,
) -> Result<Fixture> {
    let v = verify_owner_identity(c, r, owner, id, response).context("owner baseline")?;
    let marker = v
        .pointer(&r.marker_pointer)
        .and_then(Value::as_str)
        .context("baseline marker must be a unique synthetic string")?;
    ensure!(
        marker.len() >= 12,
        "baseline marker must contain at least 12 bytes"
    );
    Ok(Fixture {
        owner,
        id: id.into(),
        marker: marker.into(),
        baseline: v,
    })
}
async fn discover(ex: &mut Executor, spec: &Spec, r: &Resource) -> Result<Vec<Fixture>> {
    let mut fixtures = Vec::new();
    let mut known_ids = BTreeSet::new();
    let mut known_markers = BTreeSet::new();
    for owner in 0..2 {
        let ids = if let Some(ids) = r.fixtures.get(&ex.config.tenants[owner].name) {
            ids.clone()
        } else {
            let op = spec.op(r
                .discovery
                .as_deref()
                .context("discovery operation missing")?)?;
            let response = ex
                .send(owner, op, &values(&ex.config, r, owner, ""), None)
                .await?;
            ensure!(
                response.success(),
                "discovery credentials rejected or endpoint unavailable (HTTP {})",
                response.status
            );
            let json = response.json()?;
            let items = json
                .pointer(&r.collection_pointer)
                .and_then(Value::as_array)
                .context("discovery collection_pointer: expected array")?;
            items
                .iter()
                .take(ex.config.execution.max_resources_per_tenant)
                .map(|v| {
                    scalar_id(
                        v.pointer(&r.id_pointer)
                            .context("discovery id_pointer missing")?,
                    )
                })
                .collect::<Result<Vec<_>>>()?
        };
        ensure!(
            !ids.is_empty(),
            "discovery returned no fixtures; dependent tests cannot establish a baseline"
        );
        for id in ids
            .into_iter()
            .take(ex.config.execution.max_resources_per_tenant)
        {
            ensure!(
                known_ids.insert(id.clone()),
                "duplicate fixture ID across discovery/tenants; ownership ambiguous"
            );
            let response = ex
                .send(
                    owner,
                    spec.op(&r.read)?,
                    &values(&ex.config, r, owner, &id),
                    None,
                )
                .await?;
            let fixture = baseline(&ex.config, r, owner, &id, &response)?;
            ensure!(
                known_markers.insert(fixture.marker.clone()),
                "private fixture markers must be unique across tenants/resources"
            );
            fixtures.push(fixture);
        }
    }
    Ok(fixtures)
}
async fn mutation(
    ex: &mut Executor,
    spec: &Spec,
    r: &Resource,
    f: &Fixture,
    known_owner_markers: &[String],
    result: &mut TestResult,
) -> Result<()> {
    let m = r.mutation.as_ref().context("missing mutation mapping")?;
    let vals = values(&ex.config, r, f.owner, &f.id);
    let read = spec.op(&r.read)?;
    let patch = spec.op(&m.operation)?;
    // Reserve attack + readback + restore + verification, including every safe retry.
    let reserve = 2 + 3 * (1 + ex.config.execution.safe_retries as usize);
    ensure!(
        ex.remaining() >= reserve,
        "insufficient request budget for mutation plus guaranteed cleanup attempts"
    );
    let before = ex.send(f.owner, read, &vals, None).await?;
    let current = baseline(&ex.config, r, f.owner, &f.id, &before)?;
    ensure!(
        current.marker == f.marker,
        "fixture identity changed before mutation"
    );
    let original = current
        .baseline
        .pointer(&m.value_pointer)
        .context("mutation.value_pointer missing in owner response")?
        .clone();
    let marker = format!(
        "TENANTFENCE_{}_{}_{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
        f.owner
    );
    let mut body = m.body.clone();
    for (pointer, name) in &m.body_parameters {
        *body
            .pointer_mut(pointer)
            .context("missing mapped body field")? = Value::String(
            vals.get(name)
                .context("missing body parameter value")?
                .clone(),
        );
    }
    *body
        .pointer_mut(&m.body_pointer)
        .context("mutation.body_pointer missing")? = Value::String(marker.clone());
    let attack = ex.send(1 - f.owner, patch, &vals, Some(&body)).await;
    let leaked_in_response = if let Ok(response) = &attack {
        record_response(result, response);
        let (status, _) = evaluate(response, known_owner_markers, &[], false, None);
        if status == Status::Failure {
            result.evidence.insert(
                "proof".into(),
                "Unauthorized PATCH response contained an exact owner-verified private marker; raw data omitted".into(),
            );
            true
        } else {
            false
        }
    } else {
        false
    };
    // Always inspect and attempt cleanup after a dispatched write, including timeout/error.
    let observed = ex.send(f.owner, read, &vals, None).await;
    let observed_json = observed
        .as_ref()
        .ok()
        .and_then(|response| verify_owner_identity(&ex.config, r, f.owner, &f.id, response).ok());
    let after = observed_json
        .as_ref()
        .and_then(|v| v.pointer(&m.value_pointer));
    let confirmed = after == Some(&Value::String(marker));
    let unchanged = after == Some(&original);
    if confirmed {
        finish(
            result,
            Status::Failure,
            "Owner read-back confirmed unauthorized fixture state change".into(),
        );
        result.evidence.insert(
            "state_change".into(),
            "unique test marker verified via owner credentials; original value omitted".into(),
        );
    } else if leaked_in_response {
        finish(
            result,
            Status::Failure,
            "Unauthorized PATCH response exposed a verified private fixture marker".into(),
        );
    } else if unchanged
        && attack
            .as_ref()
            .is_ok_and(|a| r.denial_statuses.contains(&a.status))
    {
        finish(
            result,
            Status::Passed,
            "Declared denial and unchanged owner state verified".into(),
        );
    } else {
        finish(
            result,
            Status::Inconclusive,
            "Write response or owner read-back ambiguous; no confirmed unauthorized state change"
                .into(),
        );
    }
    if unchanged {
        result.cleanup = Some("not needed: original value verified".into());
        return Ok(());
    }
    let mut restore = m.body.clone();
    for (pointer, name) in &m.body_parameters {
        *restore
            .pointer_mut(pointer)
            .context("missing mapped body field")? = Value::String(
            vals.get(name)
                .context("missing body parameter value")?
                .clone(),
        );
    }
    *restore
        .pointer_mut(&m.body_pointer)
        .context("mutation body pointer missing")? = original.clone();
    let restored = ex.send(f.owner, patch, &vals, Some(&restore)).await;
    let verify = ex.send(f.owner, read, &vals, None).await;
    let verified = restored.as_ref().is_ok_and(Response::success)
        && verify
            .as_ref()
            .ok()
            .and_then(|response| {
                verify_owner_identity(&ex.config, r, f.owner, &f.id, response).ok()
            })
            .and_then(|v| v.pointer(&m.value_pointer).cloned())
            == Some(original);
    result.cleanup = Some(
        if verified {
            "restored and verified"
        } else {
            "FAILED: original fixture state could not be verified; stop and reset fixtures"
        }
        .into(),
    );
    ensure!(
        verified,
        "fixture cleanup failed; stop testing and reset disposable data"
    );
    Ok(())
}
/// Execute an already authorized scenario and return a sanitized report.
///
/// Callers must obtain authorization themselves; the CLI enforces its explicit flag.
pub async fn run(c: Config, spec: Spec, tokens: Vec<String>) -> Result<Report> {
    c.validate()?;
    ensure!(
        tokens.len() == 2 && tokens.iter().all(|t| !t.trim().is_empty()) && tokens[0] != tokens[1],
        "two distinct nonempty tenant credentials are required"
    );
    spec.validate(&c)?;
    let start = Instant::now();
    let mut report = Report {
        schema_version: 1,
        tool_version: env!("CARGO_PKG_VERSION").into(),
        target: c.target.label.clone(),
        started_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        duration_ms: 0,
        requests: 0,
        safe_settings: c.execution.clone(),
        safe_network: BTreeMap::from([
            (
                "origin".into(),
                c.target.base_url.origin().ascii_serialization(),
            ),
            ("timeout_ms".into(), c.target.timeout_ms.to_string()),
            (
                "max_response_bytes".into(),
                c.target.max_response_bytes.to_string(),
            ),
            ("redirects".into(), "disabled".into()),
            ("tls_verification".into(), "enabled".into()),
            ("environment_proxies".into(), "disabled".into()),
        ]),
        coverage: vec![
            "Explicit mappings only; both tenant directions".into(),
            "Initial collection page only; no brute force or async exports".into(),
            "TLS verified; redirects disabled; serial rate-limited execution".into(),
        ],
        results: Vec::new(),
        errors: Vec::new(),
    };
    let secrets = tokens.clone();
    let mut ex = Executor::new(c.clone(), tokens)?;
    'resources: for r in &c.resources {
        let fixtures = match discover(&mut ex, &spec, r).await {
            Ok(f) => f,
            Err(e) => {
                report.errors.push(format!("{} baseline: {e:#}", r.name));
                continue;
            }
        };
        for f in &fixtures {
            let vals = values(&c, r, f.owner, &f.id);
            for (category, opid, enabled) in [
                ("read", Some(&r.read), true),
                ("collection", r.collection.as_ref(), true),
                ("export", r.export.as_ref(), c.execution.exports),
                (
                    "mutation",
                    r.mutation.as_ref().map(|m| &m.operation),
                    c.execution.writes,
                ),
            ] {
                let Some(opid) = opid else { continue };
                let mut test = result(&c, &spec, r, f, category, opid)?;
                if !enabled {
                    finish(
                        &mut test,
                        Status::Skipped,
                        "Category explicitly disabled in execution settings".into(),
                    );
                    report.results.push(test);
                    continue;
                }
                if category == "mutation" {
                    let known_owner_markers: Vec<_> = fixtures
                        .iter()
                        .filter(|known| known.owner == f.owner)
                        .map(|known| known.marker.clone())
                        .collect();
                    if let Err(e) =
                        mutation(&mut ex, &spec, r, f, &known_owner_markers, &mut test).await
                    {
                        if test
                            .cleanup
                            .as_ref()
                            .is_some_and(|s| s.starts_with("FAILED"))
                        {
                            report.errors.push(e.to_string());
                            report.results.push(test);
                            break 'resources;
                        }
                        finish(&mut test, Status::Error, e.to_string());
                    }
                } else {
                    // Refresh owner identity before every adversarial read/collection/export.
                    let owner = ex.send(f.owner, spec.op(&r.read)?, &vals, None).await;
                    let verified = owner
                        .and_then(|o| baseline(&c, r, f.owner, &f.id, &o))
                        .is_ok_and(|b| b.marker == f.marker);
                    if !verified {
                        finish(
                            &mut test,
                            Status::Inconclusive,
                            "Owner baseline unavailable or fixture identity changed".into(),
                        );
                        report.results.push(test);
                        continue;
                    }
                    if category == "collection" {
                        let owner_collection = ex.send(f.owner, spec.op(opid)?, &vals, None).await;
                        let valid = owner_collection.as_ref().is_ok_and(|o| {
                            o.success()
                                && evaluate(o, std::slice::from_ref(&f.marker), &[], false, None).0
                                    == Status::Failure
                        });
                        if !valid {
                            finish(&mut test, Status::Inconclusive, "Owner collection baseline could not verify protected marker on configured initial page".into());
                            report.results.push(test);
                            continue;
                        }
                    }
                    // Exports require their own owner baseline; marker must be present in actual export format.
                    if category == "export" {
                        let owner_export = ex.send(f.owner, spec.op(opid)?, &vals, None).await;
                        if let Ok(response) = &owner_export {
                            let foreign_markers: Vec<_> = fixtures
                                .iter()
                                .filter(|known| known.owner != f.owner)
                                .map(|known| known.marker.clone())
                                .collect();
                            if evaluate(
                                response,
                                &foreign_markers,
                                &[],
                                matches!(r.export_format, ExportFormat::Csv),
                                None,
                            )
                            .0 == Status::Failure
                            {
                                let mut mixed = test.clone();
                                mixed.id.push_str(":mixed-tenant-owner-export");
                                mixed.attacker = c.tenants[f.owner].name.clone();
                                mixed.owner = c.tenants[1 - f.owner].name.clone();
                                mixed.expected = "Legitimate owner export must contain only authorized tenant data".into();
                                mixed.reproduction = mixed.reproduction.replace(
                                    &format!("${{{}}}", c.tenants[1 - f.owner].token_env),
                                    &format!("${{{}}}", c.tenants[f.owner].token_env),
                                );
                                record_response(&mut mixed, response);
                                mixed.evidence.insert("proof".into(), "Owner export contained an exact private marker independently verified using the other tenant's credentials; raw data omitted".into());
                                finish(&mut mixed, Status::Failure, "Legitimate export included verified private data belonging to another tenant".into());
                                report.results.push(mixed);
                            }
                        }
                        let valid = owner_export.as_ref().is_ok_and(|o| {
                            o.success()
                                && evaluate(
                                    o,
                                    std::slice::from_ref(&f.marker),
                                    &[],
                                    matches!(r.export_format, ExportFormat::Csv),
                                    None,
                                )
                                .0 == Status::Failure
                        });
                        if !valid {
                            finish(
                                &mut test,
                                Status::Inconclusive,
                                "Owner export baseline could not verify protected marker".into(),
                            );
                            report.results.push(test);
                            continue;
                        }
                    }
                    match ex.send(1 - f.owner, spec.op(opid)?, &vals, None).await {
                        Ok(response) => {
                            record_response(&mut test, &response);
                            let markers: Vec<_> = fixtures
                                .iter()
                                .filter(|known| known.owner == f.owner)
                                .map(|known| known.marker.clone())
                                .collect();
                            let (status, actual) = evaluate(
                                &response,
                                &markers,
                                &r.denial_statuses,
                                category == "export"
                                    && matches!(r.export_format, ExportFormat::Csv),
                                if category == "collection" && r.empty_collection_allowed {
                                    Some(&r.collection_pointer)
                                } else {
                                    None
                                },
                            );
                            if status == Status::Failure {
                                test.evidence.insert("proof".into(),"Exact private marker from authenticated owner baseline found; raw protected data omitted".into());
                            }
                            finish(&mut test, status, actual);
                        }
                        Err(e) => finish(&mut test, Status::Error, e.to_string()),
                    }
                }
                report.results.push(test);
            }
        }
    }
    report
        .coverage
        .extend(spec.inspect(&c).lines().skip(1).map(str::to_owned));
    report.requests = ex.used;
    report.duration_ms = start.elapsed().as_millis();
    report.redact(&secrets)?;
    report.validate()?;
    Ok(report)
}
