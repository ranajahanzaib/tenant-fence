use crate::config::Config;
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
/// A normalized declared OpenAPI parameter.
pub struct Parameter {
    pub name: String,
    pub location: String,
    pub required: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
/// Relevant operation metadata, without schema-driven request generation.
pub struct Operation {
    pub id: String,
    pub method: String,
    pub path: String,
    pub parameters: Vec<Parameter>,
    pub request_body: Option<Value>,
    pub security: Value,
}
#[derive(Debug)]
/// Deterministically ordered operations from a focused OpenAPI loader.
pub struct Spec {
    pub operations: BTreeMap<String, Operation>,
}
fn resolve(v: &Value, root: &Value, stack: &mut BTreeSet<String>, depth: usize) -> Result<Value> {
    ensure!(depth < 64, "OpenAPI reference/nesting limit (64)");
    if let Some(reference) = v.get("$ref").and_then(Value::as_str) {
        ensure!(
            reference.starts_with("#/"),
            "OpenAPI: external $ref unsupported: {reference}"
        );
        ensure!(
            stack.insert(reference.into()),
            "OpenAPI: cyclic $ref {reference}"
        );
        let target = root
            .pointer(&reference[1..])
            .with_context(|| format!("OpenAPI: missing $ref {reference}"))?;
        let result = resolve(target, root, stack, depth + 1)?;
        stack.remove(reference);
        return Ok(result);
    }
    match v {
        Value::Object(o) => o
            .iter()
            .map(|(k, v)| Ok((k.clone(), resolve(v, root, stack, depth + 1)?)))
            .collect::<Result<serde_json::Map<_, _>>>()
            .map(Value::Object),
        Value::Array(a) => a
            .iter()
            .map(|v| resolve(v, root, stack, depth + 1))
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
        _ => Ok(v.clone()),
    }
}
impl Spec {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).context("read OpenAPI")?;
        ensure!(raw.len() <= 4_194_304, "OpenAPI exceeds 4 MiB limit");
        let root: Value = serde_saphyr::from_str(&raw).context("parse OpenAPI YAML/JSON")?;
        Self::parse(root)
    }
    pub fn parse(root: Value) -> Result<Self> {
        let version = root["openapi"].as_str().unwrap_or("");
        ensure!(
            version.starts_with("3.0.") || version.starts_with("3.1."),
            "OpenAPI: supported versions are 3.0.x and 3.1.x"
        );
        let paths = root["paths"]
            .as_object()
            .context("OpenAPI.paths: expected object")?;
        let mut operations = BTreeMap::new();
        for (path, item) in paths {
            ensure!(
                path.starts_with('/')
                    && !path.starts_with("//")
                    && !path.contains(['?', '#', '\\']),
                "OpenAPI: unsafe path {path}"
            );
            let item = resolve(item, &root, &mut BTreeSet::new(), 0)?;
            for method in [
                "get", "patch", "put", "post", "delete", "head", "options", "trace",
            ] {
                let Some(op) = item.get(method) else { continue };
                let id = op["operationId"]
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("{method} {path}"));
                let mut parameters: BTreeMap<(String, String), Parameter> = BTreeMap::new();
                for source in [item.get("parameters"), op.get("parameters")]
                    .into_iter()
                    .flatten()
                {
                    for p in source
                        .as_array()
                        .context("OpenAPI.parameters: expected array")?
                    {
                        let name = p["name"]
                            .as_str()
                            .context("OpenAPI parameter.name missing")?
                            .to_owned();
                        let location = p["in"]
                            .as_str()
                            .context("OpenAPI parameter.in missing")?
                            .to_owned();
                        parameters.insert(
                            (name.clone(), location.clone()),
                            Parameter {
                                name,
                                location,
                                required: p["required"].as_bool().unwrap_or(false),
                            },
                        );
                    }
                }
                ensure!(
                    !operations.contains_key(&id),
                    "OpenAPI: duplicate operationId {id}"
                );
                operations.insert(
                    id.clone(),
                    Operation {
                        id,
                        method: method.to_uppercase(),
                        path: path.clone(),
                        parameters: parameters.into_values().collect(),
                        request_body: op.get("requestBody").cloned(),
                        security: op
                            .get("security")
                            .or(root.get("security"))
                            .cloned()
                            .unwrap_or(Value::Null),
                    },
                );
            }
        }
        ensure!(!operations.is_empty(), "OpenAPI.paths: no operations");
        Ok(Self { operations })
    }
    pub fn op(&self, id: &str) -> Result<&Operation> {
        self.operations
            .get(id)
            .with_context(|| format!("resources: operationId '{id}' not found in OpenAPI"))
    }
    pub fn validate(&self, c: &Config) -> Result<()> {
        for r in &c.resources {
            let mut ids = vec![(r.read.as_str(), "GET")];
            if let Some(id) = &r.discovery {
                ids.push((id, "GET"));
            }
            if let Some(id) = &r.collection {
                ids.push((id, "GET"));
            }
            if let Some(id) = &r.export {
                ids.push((id, "GET"));
            }
            if let Some(m) = &r.mutation {
                ids.push((&m.operation, "PATCH"));
            }
            for (id, method) in ids {
                let op = self.op(id)?;
                ensure!(op.method == method, "resources.{id}: requires {method}");
                for p in &op.parameters {
                    ensure!(
                        ["path", "query"].contains(&p.location.as_str()) || !p.required,
                        "operation {id}: required {} parameter unsupported",
                        p.location
                    );
                    if p.required || p.location == "path" {
                        ensure!(
                            p.name == r.id_parameter
                                || Some(&p.name) == r.tenant_parameter.as_ref()
                                || r.parameters.contains_key(&p.name),
                            "resources.{id}.parameters: missing {}",
                            p.name
                        );
                    }
                }
                let mut rest = op.path.as_str();
                while let Some(start) = rest.find('{') {
                    let end = rest[start..]
                        .find('}')
                        .context("OpenAPI: unclosed path parameter")?
                        + start;
                    let name = &rest[start + 1..end];
                    ensure!(
                        op.parameters
                            .iter()
                            .any(|p| p.location == "path" && p.name == name),
                        "operation {id}: undeclared path parameter {name}"
                    );
                    rest = &rest[end + 1..];
                }
                if method == "PATCH" {
                    ensure!(
                        op.request_body
                            .as_ref()
                            .and_then(|b| b.pointer("/content/application~1json"))
                            .is_some(),
                        "operation {id}: PATCH requires application/json requestBody"
                    );
                }
            }
            let read = self.op(&r.read)?;
            ensure!(
                read.parameters.iter().any(|p| p.name == r.id_parameter
                    && ["path", "query"].contains(&p.location.as_str())),
                "resources.id_parameter: must be declared on read operation"
            );
            if let Some(id) = &r.collection {
                ensure!(
                    self.op(id)?
                        .parameters
                        .iter()
                        .any(|p| Some(&p.name) == r.tenant_parameter.as_ref()
                            && ["path", "query"].contains(&p.location.as_str())),
                    "resources.tenant_parameter: undeclared on collection"
                );
            }
        }
        Ok(())
    }
    pub fn inspect(&self, c: &Config) -> String {
        let mut out = String::from("TenantFence · offline execution plan\n");
        for op in self.operations.values() {
            let mapped = c.resources.iter().any(|r| {
                r.read == op.id
                    || r.discovery.as_ref() == Some(&op.id)
                    || r.collection.as_ref() == Some(&op.id)
                    || r.export.as_ref() == Some(&op.id)
                    || r.mutation.as_ref().is_some_and(|m| m.operation == op.id)
            });
            out.push_str(&format!(
                "{} {} [{}] — {}\n",
                op.method,
                op.path,
                op.id,
                if mapped {
                    "explicitly mapped"
                } else {
                    "SKIPPED: no explicit mapping (advisory only)"
                }
            ));
        }
        for r in &c.resources {
            out.push_str(&format!(
                "Resource {}: read; collection={}; export={}; mutation={}\n",
                r.name,
                r.collection.is_some(),
                c.execution.exports && r.export.is_some(),
                c.execution.writes && r.mutation.is_some()
            ));
        }
        out.push_str(&format!("At most {} HTTP requests (including retries and reserved cleanup); {} resources per tenant; serial execution. Redirects disabled. Initial collection page only.\n",c.execution.max_requests,c.execution.max_resources_per_tenant));
        out
    }
}
/// Extract a stable string or numeric fixture identifier.
pub fn scalar_id(v: &Value) -> Result<String> {
    match v {
        Value::String(s) if !s.is_empty() => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        _ => bail!("resource ID: expected nonempty string or number"),
    }
}
