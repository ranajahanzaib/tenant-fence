use axum::{
    Router,
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tenantfence::{
    config::Config,
    http::{Executor, request_url},
    report::Status,
    spec::Spec,
};
#[derive(Clone)]
struct Server {
    mode: &'static str,
    titles: Arc<Mutex<BTreeMap<String, String>>>,
    forged: Arc<Mutex<BTreeMap<String, String>>>,
}
async fn handler(State(s): State<Server>, request: Request) -> Response {
    let path = request.uri().path().to_string();
    let attacker = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .strip_prefix("Bearer ")
        .unwrap_or("")
        .to_string();
    if attacker != "alpha-token" && attacker != "beta-token" {
        return (StatusCode::UNAUTHORIZED, axum::Json(json!({}))).into_response();
    }
    let tenant = attacker.trim_end_matches("-token").to_string();
    if path == "/v1/documents" {
        if s.mode == "empty" {
            return axum::Json(json!({"items":[]})).into_response();
        }
        return axum::Json(json!({"items":[{"id":format!("{tenant}-doc")}]})).into_response();
    }
    if path.contains(&format!("/tenants/{tenant}/")) {
        return axum::Json(json!({"items":[{"id":format!("{tenant}-doc"),"content":format!("{}_PRIVATE_DOCUMENT_MARKER",tenant.to_uppercase())}]})).into_response();
    }
    if path.contains("/tenants/") && s.mode == "collection-leak" {
        let selected = path.split('/').nth(3).unwrap();
        return axum::Json(json!({"items":[{"id":format!("{selected}-doc"),"content":format!("{}_PRIVATE_DOCUMENT_MARKER",selected.to_uppercase())}]})).into_response();
    }
    if path.contains("/tenants/") && s.mode == "filtered" {
        return axum::Json(json!({"items":[]})).into_response();
    }
    if path.contains("/tenants/") {
        return (StatusCode::FORBIDDEN, axum::Json(json!({}))).into_response();
    }
    let id = path.split('/').nth(3).unwrap_or("").to_string();
    let owner = if id.starts_with("alpha") {
        "alpha"
    } else {
        "beta"
    };
    let foreign = owner != tenant;
    if s.mode == "missing" {
        return (StatusCode::NOT_FOUND, axum::Json(json!({}))).into_response();
    }
    if foreign {
        match s.mode {
            "timeout" => {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
            "redirect" => {
                return (
                    StatusCode::FOUND,
                    [("location", "http://127.0.0.1:1/escaped")],
                )
                    .into_response();
            }
            "invalid" => return (StatusCode::OK, "not-json").into_response(),
            "oversize" => return (StatusCode::OK, "x".repeat(5000)).into_response(),
            "ambiguous" => return axum::Json(json!({"message":"ok"})).into_response(),
            "secure" | "mixed-export" => {
                return (StatusCode::NOT_FOUND, axum::Json(json!({}))).into_response();
            }
            "patch-leak" if request.method() == "PATCH" => {
                return (StatusCode::FORBIDDEN, axum::Json(json!({"content":format!("{}_PRIVATE_DOCUMENT_MARKER", owner.to_uppercase())}))).into_response();
            }
            "csv-json-leak" if path.ends_with("/export") => {
                return (StatusCode::FORBIDDEN, axum::Json(json!({"content":format!("{}_PRIVATE_DOCUMENT_MARKER", owner.to_uppercase())}))).into_response();
            }
            _ => {}
        }
    }
    let is_patch = request.method() == "PATCH";
    if is_patch {
        if !foreign && s.mode == "cleanup-fail" {
            return (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(json!({}))).into_response();
        }

        let body = axum::body::to_bytes(request.into_body(), 4096)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        if foreign && s.mode == "wrong-readback" {
            s.forged
                .lock()
                .unwrap()
                .insert(id.clone(), json["title"].as_str().unwrap().into());
        } else if !(foreign && s.mode == "no-change") {
            s.titles
                .lock()
                .unwrap()
                .insert(id.clone(), json["title"].as_str().unwrap().into());
        }
    }
    if is_patch && foreign && s.mode == "attack-timeout" {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    if is_patch {
        return axum::Json(json!({"ok":true})).into_response();
    }
    let title = s
        .titles
        .lock()
        .unwrap()
        .get(&id)
        .cloned()
        .unwrap_or("original".into());
    let mut doc = json!({"id":id,"tenant_id":owner,"title":title,"content":format!("{}_PRIVATE_DOCUMENT_MARKER",owner.to_uppercase())});
    if s.mode == "wrong-readback"
        && !foreign
        && let Some(forged) = s.forged.lock().unwrap().get(&id).cloned()
    {
        doc["id"] = json!("unrelated-doc");
        doc["tenant_id"] = json!("unrelated-tenant");
        doc["title"] = json!(forged);
    }
    if path.ends_with("/export") && s.mode == "csv" {
        return (
            StatusCode::OK,
            format!(
                "id,content\n{id},{}_PRIVATE_DOCUMENT_MARKER\n",
                owner.to_uppercase()
            ),
        )
            .into_response();
    }
    if path.ends_with("/export") && s.mode == "mixed-export" {
        let other = if owner == "alpha" { "BETA" } else { "ALPHA" };
        return axum::Json(
            json!({"documents":[doc,{"content":format!("{other}_PRIVATE_DOCUMENT_MARKER")}]}),
        )
        .into_response();
    }
    if path.ends_with("/export") && s.mode == "csv-json-leak" {
        return (
            StatusCode::OK,
            format!(
                "id,content\n{id},{}_PRIVATE_DOCUMENT_MARKER\n",
                owner.to_uppercase()
            ),
        )
            .into_response();
    }
    axum::Json(if path.ends_with("/export") {
        json!({"documents":[doc]})
    } else {
        doc
    })
    .into_response()
}
async fn setup(mode: &'static str) -> (Config, Server, tokio::task::JoinHandle<()>) {
    let server = Server {
        mode,
        titles: Arc::new(Mutex::new(BTreeMap::new())),
        forged: Arc::new(Mutex::new(BTreeMap::new())),
    };
    let app = Router::new().fallback(handler).with_state(server.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut c = Config::load(std::path::Path::new(
        "examples/cloudflare-d1/tenantfence.yaml",
    ))
    .unwrap();
    c.target.base_url = format!("http://{addr}").parse().unwrap();
    c.target.allowed_origins = vec![format!("http://{addr}")];
    c.execution.requests_per_second = 100;
    c.execution.max_resources_per_tenant = 1;
    (c, server, handle)
}
async fn scan(mode: &'static str) -> tenantfence::report::Report {
    let (mut c, server, handle) = setup(mode).await;
    if mode == "timeout" {
        c.target.timeout_ms = 40;
    }
    if mode == "oversize" {
        c.target.max_response_bytes = 1024;
    }
    let spec = Spec::load(&c.target.spec).unwrap();
    let report = tenantfence::engine::run(c, spec, vec!["alpha-token".into(), "beta-token".into()])
        .await
        .unwrap();
    if mode == "vulnerable" {
        assert!(
            report
                .results
                .iter()
                .filter(|r| r.category == "mutation")
                .all(|r| r.cleanup.as_deref() == Some("restored and verified"))
        );
        assert!(
            server
                .titles
                .lock()
                .unwrap()
                .values()
                .all(|v| v == "original")
        );
    }
    handle.abort();
    report
}
#[tokio::test]
async fn secure_denial() {
    let r = scan("secure").await;
    assert_eq!(r.exit_code(), 0);
    assert!(r.results.iter().all(|r| r.status == Status::Passed));
}
#[tokio::test]
async fn real_read_export_update_and_cleanup() {
    let r = scan("vulnerable").await;
    assert_eq!(r.exit_code(), 1);
    for category in ["read", "export", "mutation"] {
        assert_eq!(
            r.results
                .iter()
                .filter(|r| r.category == category && r.status == Status::Failure)
                .count(),
            2
        );
    }
}
#[tokio::test]
async fn ambiguous_is_never_confirmed() {
    let r = scan("ambiguous").await;
    assert_eq!(r.exit_code(), 2);
    assert!(!r.results.iter().any(|r| r.status == Status::Failure));
}
#[tokio::test]
async fn unchanged_successful_patch_is_inconclusive() {
    let r = scan("no-change").await;
    assert!(
        r.results
            .iter()
            .filter(|r| r.category == "mutation")
            .all(|r| r.status == Status::Inconclusive)
    );
}
#[tokio::test]
async fn failed_and_empty_baselines() {
    for mode in ["empty", "missing"] {
        let r = scan(mode).await;
        assert_eq!(r.exit_code(), 2);
        assert!(!r.errors.is_empty());
        assert!(r.results.is_empty());
    }
}
#[tokio::test]
async fn bounded_transport_failures() {
    for mode in ["timeout", "oversize", "invalid", "redirect"] {
        let r = scan(mode).await;
        assert_eq!(r.exit_code(), 2, "{mode}");
        assert!(
            !r.results.iter().any(|r| r.status == Status::Failure),
            "{mode}"
        );
    }
}
#[tokio::test]
async fn budget_enforcement() {
    let (mut c, _, handle) = setup("secure").await;
    c.execution.max_requests = 1;
    let spec = Spec::load(&c.target.spec).unwrap();
    let mut ex = Executor::new(c.clone(), vec!["alpha-token".into(), "beta-token".into()]).unwrap();
    let op = spec.op("listDocuments").unwrap();
    let vals = BTreeMap::new();
    assert!(request_url(&c.target.base_url, op, &vals).is_ok());
    assert!(ex.send(0, op, &vals, None).await.is_ok());
    assert!(
        ex.send(0, op, &vals, None)
            .await
            .unwrap_err()
            .to_string()
            .contains("budget")
    );
    assert_eq!(ex.used, 1);
    handle.abort();
}
#[tokio::test]
async fn invalid_credentials_stop_baseline() {
    let (c, _, handle) = setup("secure").await;
    let spec = Spec::load(&c.target.spec).unwrap();
    let r = tenantfence::engine::run(c, spec, vec!["bad-token".into(), "beta-token".into()])
        .await
        .unwrap();
    assert_eq!(r.exit_code(), 2);
    assert!(r.results.is_empty());
    handle.abort();
}
#[tokio::test]
async fn report_roundtrip_redaction_and_escaping() {
    let mut r = scan("vulnerable").await;
    r.target = "<script>alert('x')</script>secret-value".into();
    r.redact(&["secret-value".into()]).unwrap();
    let json = serde_json::to_string(&r).unwrap();
    assert!(!json.contains("secret-value"));
    assert!(!json.contains("alpha-token"));
    let restored: tenantfence::report::Report = serde_json::from_str(&json).unwrap();
    restored.validate().unwrap();
    let html = restored.html();
    assert!(!html.contains("<script>alert"));
    assert!(html.contains("&lt;script&gt;"));
    r.schema_version = 999;
    assert!(r.validate().is_err());
}

#[tokio::test]
async fn collection_policies() {
    let leaked = scan("collection-leak").await;
    assert!(
        leaked
            .results
            .iter()
            .filter(|r| r.category == "collection")
            .all(|r| r.status == Status::Failure)
    );
    let filtered = scan("filtered").await;
    assert!(
        filtered
            .results
            .iter()
            .filter(|r| r.category == "collection")
            .all(|r| r.status == Status::Passed)
    );
}
#[tokio::test]
async fn cleanup_failure_is_prominent_and_stops_run() {
    let r = scan("cleanup-fail").await;
    assert_eq!(r.exit_code(), 2);
    assert!(r.errors.iter().any(|e| e.contains("cleanup failed")));
    assert!(r.results.iter().any(|r| r.status == Status::Failure
        && r.cleanup.as_ref().is_some_and(|s| s.starts_with("FAILED"))));
    assert_eq!(
        r.results
            .iter()
            .filter(|r| r.category == "mutation")
            .count(),
        1
    );
}
#[tokio::test]
async fn write_timeout_still_reads_back_and_restores() {
    let (mut c, server, handle) = setup("attack-timeout").await;
    c.target.timeout_ms = 50;
    let spec = Spec::load(&c.target.spec).unwrap();
    let r = tenantfence::engine::run(c, spec, vec!["alpha-token".into(), "beta-token".into()])
        .await
        .unwrap();
    assert!(
        r.results
            .iter()
            .filter(|r| r.category == "mutation")
            .all(|r| r.status == Status::Failure
                && r.cleanup.as_deref() == Some("restored and verified"))
    );
    assert!(
        server
            .titles
            .lock()
            .unwrap()
            .values()
            .all(|v| v == "original")
    );
    handle.abort();
}
#[tokio::test]
async fn csv_exports_over_http() {
    let (mut c, _, handle) = setup("csv").await;
    c.resources[0].export_format = tenantfence::config::ExportFormat::Csv;
    let spec = Spec::load(&c.target.spec).unwrap();
    let r = tenantfence::engine::run(c, spec, vec!["alpha-token".into(), "beta-token".into()])
        .await
        .unwrap();
    assert_eq!(
        r.results
            .iter()
            .filter(|r| r.category == "export" && r.status == Status::Failure)
            .count(),
        2
    );
    handle.abort();
}

#[tokio::test]
async fn csv_export_denial_json_body_still_checks_private_markers() {
    let (mut c, _, handle) = setup("csv-json-leak").await;
    c.resources[0].export_format = tenantfence::config::ExportFormat::Csv;
    let spec = Spec::load(&c.target.spec).unwrap();
    let r = tenantfence::engine::run(c, spec, vec!["alpha-token".into(), "beta-token".into()])
        .await
        .unwrap();
    assert_eq!(
        r.results
            .iter()
            .filter(|r| r.category == "export" && r.status == Status::Failure)
            .count(),
        2
    );
    handle.abort();
}

#[tokio::test]
async fn denied_patch_response_is_scanned_for_private_markers() {
    let r = scan("patch-leak").await;
    assert_eq!(r.exit_code(), 1);
    assert!(
        r.results
            .iter()
            .filter(|r| r.category == "mutation")
            .all(|r| {
                r.status == Status::Failure
                    && r.actual
                        .contains("exposed a verified private fixture marker")
                    && r.cleanup.as_deref() == Some("not needed: original value verified")
            })
    );
}

#[tokio::test]
async fn wrong_identity_readback_cannot_confirm_mutation_or_cleanup() {
    let r = scan("wrong-readback").await;
    assert_eq!(r.exit_code(), 2);
    let mutation = r.results.iter().find(|r| r.category == "mutation").unwrap();
    assert_eq!(mutation.status, Status::Inconclusive);
    assert!(
        mutation
            .cleanup
            .as_deref()
            .is_some_and(|s| s.starts_with("FAILED"))
    );
    assert!(
        !mutation
            .actual
            .contains("confirmed unauthorized fixture state change")
    );
}

#[tokio::test]
async fn redaction_handles_encoded_values_and_preserves_schema_enums() {
    let mut r = scan("secure").await;
    r.target = "token%2Fvalue token/value".into();
    r.redact(&["token/value".into(), "read".into()]).unwrap();
    assert_eq!(r.target, "[REDACTED] [REDACTED]");
    r.validate().unwrap();
    assert!(r.results.iter().any(|r| r.category == "read"));
}

#[tokio::test]
async fn legitimate_export_must_not_include_another_tenant() {
    let r = scan("mixed-export").await;
    assert_eq!(r.exit_code(), 1);
    let findings: Vec<_> = r
        .results
        .iter()
        .filter(|r| r.id.ends_with(":mixed-tenant-owner-export"))
        .collect();
    assert_eq!(findings.len(), 2);
    assert!(
        findings
            .iter()
            .all(|r| r.status == Status::Failure && r.attacker != r.owner)
    );
    assert!(
        r.results
            .iter()
            .filter(|r| !r.id.ends_with(":mixed-tenant-owner-export"))
            .all(|r| r.status == Status::Passed)
    );
}
