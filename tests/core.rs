use serde_json::json;
use tenantfence::{
    config::Config,
    engine::evaluate,
    http::{Response, request_url},
    report::{Status, escape},
    spec::{Spec, scalar_id},
};
fn config() -> Config {
    Config::load(std::path::Path::new(
        "examples/cloudflare-d1/tenantfence.yaml",
    ))
    .unwrap()
}
fn response(status: u16, body: &str) -> Response {
    Response {
        status,
        body: body.as_bytes().into(),
        elapsed_ms: 0,
    }
}
#[test]
fn valid_config_and_mapping() {
    let c = config();
    let s = Spec::load(&c.target.spec).unwrap();
    s.validate(&c).unwrap();
    assert_eq!(s.operations.len(), 6);
    assert!(s.inspect(&c).contains("SKIPPED"));
}
#[test]
fn config_rejects_unsafe_settings() {
    let mut c = config();
    c.target.base_url = "http://example.com".parse().unwrap();
    assert!(c.validate().is_err());
    let mut c = config();
    c.execution.max_concurrency = 100;
    assert!(c.validate().is_err());
    let mut c = config();
    c.resources[0].mutation.as_mut().unwrap().disposable = false;
    assert!(c.validate().is_err());
    let mut c = config();
    c.tenants[1].selector = "alpha".into();
    assert!(c.validate().is_err());
}
#[test]
fn missing_credentials() {
    let mut c = config();
    c.tenants[0].token_env = "TENANTFENCE_TEST_NONEXISTENT_91".into();
    assert!(
        c.credentials()
            .unwrap_err()
            .to_string()
            .contains("TENANTFENCE_TEST_NONEXISTENT_91")
    );
}
#[test]
fn invalid_yaml_and_unknown_fields() {
    assert!(serde_saphyr::from_str::<Config>("garbage: true").is_err());
}
#[test]
fn local_refs_and_version_support() {
    for version in ["3.0.3", "3.1.0"] {
        let s=Spec::parse(json!({"openapi":version,"paths":{"/a":{"get":{"operationId":"a","parameters":[{"$ref":"#/components/parameters/Id"}]}}},"components":{"parameters":{"Id":{"name":"id","in":"query","required":true}}}})).unwrap();
        assert_eq!(s.op("a").unwrap().parameters[0].name, "id");
    }
}
#[test]
fn reject_external_cyclic_and_missing_refs() {
    for reference in ["https://example.com/a", "#/missing", "#/paths/~1a"] {
        assert!(Spec::parse(json!({"openapi":"3.1.0","paths":{"/a":{"$ref":reference}}})).is_err());
    }
}
#[test]
fn mapping_validation() {
    let mut c = config();
    let s = Spec::load(&c.target.spec).unwrap();
    c.resources[0].read = "missing".into();
    assert!(s.validate(&c).is_err());
}
#[test]
fn ids_and_safe_generation() {
    assert_eq!(scalar_id(&json!(42)).unwrap(), "42");
    assert!(scalar_id(&json!(null)).is_err());
    let c = config();
    let s = Spec::load(&c.target.spec).unwrap();
    let op = s.op("getDocument").unwrap();
    let mut p = std::collections::BTreeMap::new();
    p.insert("documentId".into(), "//evil.test/a?token=foo".into());
    let u = request_url(&c.target.base_url, op, &p).unwrap();
    assert_eq!(u.origin(), c.target.base_url.origin());
    assert!(u.query().is_none());
    p.insert("documentId".into(), "..".into());
    assert!(request_url(&c.target.base_url, op, &p).is_err());
}
#[test]
fn deterministic_evaluation() {
    let markers = vec!["BETA_PRIVATE_DOCUMENT_MARKER".into()];
    for (s, b, expected) in [
        (404, "{}", Status::Passed),
        (200, "{}", Status::Inconclusive),
        (
            200,
            "{\"content\":\"BETA_PRIVATE_DOCUMENT_MARKER\"}",
            Status::Failure,
        ),
        (
            403,
            "{\"content\":\"BETA_PRIVATE_DOCUMENT_MARKER\"}",
            Status::Failure,
        ),
        (404, "not json", Status::Inconclusive),
        (500, "{}", Status::Inconclusive),
    ] {
        assert_eq!(
            evaluate(&response(s, b), &markers, &[403, 404], false, None).0,
            expected
        );
    }
}
#[test]
fn csv_and_empty_collection() {
    let m = vec!["BETA_PRIVATE_DOCUMENT_MARKER".into()];
    assert_eq!(
        evaluate(
            &response(200, "id,content\nbeta,BETA_PRIVATE_DOCUMENT_MARKER\n"),
            &m,
            &[],
            true,
            None
        )
        .0,
        Status::Failure
    );
    assert_eq!(
        evaluate(
            &response(200, "{\"items\":[]}"),
            &m,
            &[],
            false,
            Some("/items")
        )
        .0,
        Status::Passed
    );
}
#[test]
fn html_escape() {
    assert_eq!(escape("<script>\"'&"), "&lt;script&gt;&quot;&#39;&amp;");
}

#[test]
fn query_identifiers_are_encoded() {
    let c = Config::load(std::path::Path::new(
        "examples/generic-api/tenantfence.yaml",
    ))
    .unwrap();
    let s = Spec::load(&c.target.spec).unwrap();
    let values = std::collections::BTreeMap::from([("id".into(), "a&tenant=other".into())]);
    let url = request_url(&c.target.base_url, s.op("item").unwrap(), &values).unwrap();
    assert_eq!(
        url.query_pairs().collect::<Vec<_>>(),
        vec![("id".into(), "a&tenant=other".into())]
    );
}
