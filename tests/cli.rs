use std::{path::PathBuf, process::Command};
fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tenantfence"))
}
fn temp(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("tenantfence-{}-{label}", std::process::id()))
}
#[test]
fn authorization_is_mandatory() {
    let r = bin()
        .args(["run", "--config", "examples/cloudflare-d1/tenantfence.yaml"])
        .output()
        .unwrap();
    assert_eq!(r.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&r.stderr).contains("--authorized"));
}
#[test]
fn init_never_overwrites_without_force() {
    let path = temp("init.yaml");
    let _ = std::fs::remove_file(&path);
    assert!(
        bin()
            .arg("init")
            .arg("--output")
            .arg(&path)
            .output()
            .unwrap()
            .status
            .success()
    );
    let generated = std::fs::read_to_string(&path).unwrap();
    assert!(generated.contains("writes: false"));
    assert!(!generated.contains("writes: true"));
    std::fs::write(&path, "preserve-me").unwrap();
    assert_eq!(
        bin()
            .arg("init")
            .arg("--output")
            .arg(&path)
            .output()
            .unwrap()
            .status
            .code(),
        Some(2)
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "preserve-me");
    assert!(
        bin()
            .arg("init")
            .arg("--force")
            .arg("--output")
            .arg(&path)
            .output()
            .unwrap()
            .status
            .success()
    );
    std::fs::remove_file(path).unwrap();
}
#[test]
fn malformed_report_is_rejected() {
    let path = temp("invalid.json");
    let out = temp("invalid.html");
    std::fs::write(&path, "{\"schema_version\":1}").unwrap();
    assert_eq!(
        bin()
            .arg("report")
            .arg("--input")
            .arg(&path)
            .arg("--output")
            .arg(&out)
            .output()
            .unwrap()
            .status
            .code(),
        Some(2)
    );
    assert!(!out.exists());
    std::fs::remove_file(path).unwrap();
}
#[test]
fn inspect_is_offline_and_does_not_require_credentials() {
    assert!(
        bin()
            .args([
                "inspect",
                "--config",
                "examples/generic-api/tenantfence.yaml"
            ])
            .env_remove("TENANTFENCE_ALPHA_TOKEN")
            .env_remove("TENANTFENCE_BETA_TOKEN")
            .output()
            .unwrap()
            .status
            .success()
    );
}
