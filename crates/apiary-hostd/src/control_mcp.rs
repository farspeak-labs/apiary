//! Apiary's MCP control plane. This is deliberately an adapter over the REST
//! router, not a second management implementation: MCP authentication yields
//! a Nostr identity, then each forwarded operation passes through the same
//! per-agent governor or host-manager gate used by the cockpit and REST API.

use crate::{build_router, nip98, App};
use apiary_core::keystore::Keystore;
use axum::{
    body::{to_bytes, Body},
    extract::{OriginalUri, State},
    http::{HeaderMap, Method, Request, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use nostr::prelude::PublicKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom, Write};
use tower::ServiceExt;

const MAX_FORWARD_RESPONSE: usize = 8 * 1024 * 1024;

pub async fn handle(
    State(state): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    raw_body: axum::body::Bytes,
) -> Response {
    let path = uri
        .path_and_query()
        .map(|value| value.to_string())
        .unwrap_or_else(|| uri.path().to_string());
    let signer = match nip98::check_control(&state, &headers, "POST", &path, Some(&raw_body)) {
        Ok(signer) => signer,
        Err(error) => return error.into_response(),
    };
    let request: Value = match serde_json::from_slice(&raw_body) {
        Ok(request) => request,
        Err(error) => return rpc_http_error(Value::Null, -32700, &format!("parse error: {error}")),
    };
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let params = request.get("params").cloned().unwrap_or_else(|| json!({}));

    let result = match method {
        "server/discover" => Ok(json!({
            "supportedVersions": ["2026-07-28", "2025-06-18"],
            "capabilities": {"tools": {"listChanged": false}},
            "serverInfo": {"name": "apiary-control", "version": env!("CARGO_PKG_VERSION")}
        })),
        "initialize" => Ok(json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {"listChanged": false}},
            "serverInfo": {"name": "apiary-control", "version": env!("CARGO_PKG_VERSION")}
        })),
        "notifications/initialized" => return StatusCode::ACCEPTED.into_response(),
        "tools/list" => Ok(json!({"tools": tools()})),
        "tools/call" => {
            let result = call_tool(&state, signer, &params).await;
            audit_call(&state, signer, &params, &result);
            result
        }
        _ => Err((-32601, format!("method not found: {method}"))),
    };

    match result {
        Ok(result) => (
            StatusCode::OK,
            Json(json!({"jsonrpc": "2.0", "id": id, "result": result})),
        )
            .into_response(),
        Err((code, message)) => rpc_http_error(id, code, &message),
    }
}

fn tools() -> Vec<Value> {
    vec![
        json!({
            "name": "apiary_describe",
            "description": "Describe Apiary's management surface, authorization model, and MCP safety exclusions.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
            "annotations": {"readOnlyHint": true, "idempotentHint": true}
        }),
        json!({
            "name": "apiary_list_agents",
            "description": "List only the Apiary agents this authenticated Nostr identity governs. Host managers do not automatically govern every agent.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
            "annotations": {"readOnlyHint": true, "idempotentHint": true}
        }),
        json!({
            "name": "apiary_get_agent_environment",
            "description": "Read an assigned agent's manifest, skills, inference connections, spend, routines, lease, and listener state in one call.",
            "inputSchema": {
                "type": "object",
                "properties": {"agent": {"type": "string", "description": "Agent npub"}},
                "required": ["agent"],
                "additionalProperties": false
            },
            "annotations": {"readOnlyHint": true, "idempotentHint": true}
        }),
        json!({
            "name": "apiary_request",
            "description": "Call an Apiary management REST operation as the authenticated identity. Existing per-agent governor and host-manager checks are enforced. Configuration writes remain unratified amendments. Plaintext credential opening, unlock, export, UI event streams, and folder picking are intentionally unavailable.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"]},
                    "path": {"type": "string", "description": "Relative /api/... path, optionally with a query string"},
                    "body": {"description": "JSON request body; omit for bodyless operations"}
                },
                "required": ["method", "path"],
                "additionalProperties": false
            },
            "annotations": {"readOnlyHint": false, "destructiveHint": true, "openWorldHint": false}
        }),
    ]
}

async fn call_tool(
    state: &App,
    signer: Option<PublicKey>,
    params: &Value,
) -> Result<Value, (i64, String)> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| (-32602, "tools/call requires a name".into()))?;
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let output = match name {
        "apiary_describe" => describe(),
        "apiary_list_agents" => forward(state, signer, Method::GET, "/api/agents", None).await?,
        "apiary_get_agent_environment" => {
            let raw = arguments
                .get("agent")
                .and_then(Value::as_str)
                .ok_or_else(|| (-32602, "agent is required".into()))?;
            let key = apiary_core::identity::parse_npub(raw)
                .map_err(|error| (-32602, error.to_string()))?;
            let agent = apiary_core::identity::to_npub(&key)
                .map_err(|error| (-32602, error.to_string()))?;
            let base = format!("/api/agents/{agent}");
            let paths = [
                ("manifest", format!("{base}/manifest")),
                ("skills", format!("{base}/skills")),
                ("harnesses", format!("{base}/harnesses")),
                ("inference", format!("{base}/inference")),
                ("spend", format!("{base}/spend")),
                ("routines", format!("{base}/routines")),
                ("lease", format!("{base}/lease")),
                ("listener", format!("{base}/listener")),
            ];
            // These are independent read models. Execute them together so a
            // remote manager pays one slowest-route latency, not eight RTTs.
            let requests = paths.clone().map(|(_, path)| {
                let state = state.clone();
                async move { forward(&state, signer, Method::GET, &path, None).await }
            });
            let [manifest, skills, harnesses, inference, spend, routines, lease, listener] =
                futures_join_8(requests).await;
            let mut environment = serde_json::Map::new();
            for ((name, _), result) in paths.into_iter().zip([
                manifest, skills, harnesses, inference, spend, routines, lease, listener,
            ]) {
                environment.insert(name.into(), result?);
            }
            json!({"agent": agent, "environment": environment})
        }
        "apiary_request" => {
            let method = arguments
                .get("method")
                .and_then(Value::as_str)
                .ok_or_else(|| (-32602, "method is required".into()))?
                .parse::<Method>()
                .map_err(|_| (-32602, "method must be GET, POST, PUT, or DELETE".into()))?;
            let path = arguments
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| (-32602, "path is required".into()))?;
            validate_target(&method, path)?;
            let body = arguments
                .get("body")
                .filter(|value| !value.is_null())
                .cloned();
            forward(state, signer, method, path, body).await?
        }
        _ => return Err((-32601, format!("unknown tool: {name}"))),
    };
    let is_error = response_is_error(&output);
    let text = if name == "apiary_get_agent_environment" {
        "Apiary returned the governed environment snapshot in structuredContent.".to_string()
    } else {
        serde_json::to_string_pretty(&output).unwrap_or_else(|_| output.to_string())
    };
    Ok(json!({
        "resultType": "complete",
        "content": [{"type": "text", "text": text}],
        "structuredContent": output,
        "isError": is_error
    }))
}

async fn futures_join_8<F, T>(futures: [F; 8]) -> [T; 8]
where
    F: std::future::Future<Output = T>,
{
    let [a, b, c, d, e, f, g, h] = futures;
    let (a, b, c, d, e, f, g, h) = tokio::join!(a, b, c, d, e, f, g, h);
    [a, b, c, d, e, f, g, h]
}

fn response_is_error(output: &Value) -> bool {
    let direct = output
        .get("status")
        .and_then(Value::as_u64)
        .is_some_and(|status| !(200..300).contains(&status));
    direct
        || output
            .get("environment")
            .and_then(Value::as_object)
            .is_some_and(|environment| environment.values().any(response_is_error))
}

fn describe() -> Value {
    json!({
        "authentication": {
            "remote": "NIP-98 per request or Bearer apiary_<signed-control-token>",
            "desktop": "per-launch x-apiary-token or a signed control token",
            "authorization": "agent operations require the route's viewer/operator/editor/governor role; existing governance.suspend_keys are governors; host operations require host-manager membership"
        },
        "convenience_tools": ["apiary_list_agents", "apiary_get_agent_environment"],
        "request_tool": {
            "path": "Any relative /api/... route except the explicit safety exclusions",
            "routes": [
                "agents, manifests and ratification", "skills and constitutions",
                "inference and connector grants", "routines, presence and leases",
                "logs, spend and runs", "host managers and connector library"
            ]
        },
        "excluded": ["/api/host/pick-folder", "/api/events"],
        "human_door": {
            "routes": {
                "/api/unlock, /api/unlock/forget": "governance.autonomy.unlock",
                "/api/agents/{npub}/credential/open": "governance.autonomy.open_credentials",
                "/api/agents/{npub}/export": "governance.autonomy.export"
            },
            "rule": "Available only to a caller whose OWN RATIFIED manifest grants that capability. A person grants each one separately and must ratify the grant: autonomy can never grant autonomy, so no agent can widen itself or another. suspend_keys always stops an autonomous agent."
        },
        "governance": "Writes do not bypass Apiary: constitutional changes invalidate ratification until an authorized governor approves them. Ratifying is likewise gated — an agent may sign ratifications only where it is a listed governor and holds governance.autonomy.ratify, and never one that grants autonomy."
    })
}

/// Ok(None) = allowed outright; Ok(Some(need)) = allowed only for a caller
/// granted that autonomy capability; Err = never available through MCP.
fn validate_target(method: &Method, target: &str) -> Result<Option<AutonomyNeed>, (i64, String)> {
    if !matches!(
        *method,
        Method::GET | Method::POST | Method::PUT | Method::DELETE
    ) {
        return Err((-32602, "unsupported HTTP method".into()));
    }
    let lower = target.to_ascii_lowercase();
    let path = lower.split('?').next().unwrap_or_default();
    if !path.starts_with("/api/")
        || target.contains("..")
        || lower.contains("%2e")
        || lower.contains("%2f")
        || target.contains('#')
        || target.starts_with("//")
    {
        return Err((
            -32602,
            "path must be a non-traversing relative /api/... route".into(),
        ));
    }
    // Never reachable through MCP for anyone: a UI stream and a native
    // file dialog, neither of which means anything to a protocol client.
    if path == "/api/events" || path == "/api/host/pick-folder" {
        return Err((
            -32602,
            "that route is intentionally excluded from MCP control".into(),
        ));
    }
    // The human door. Reachable only for a caller whose ratified manifest
    // grants that specific autonomy capability (see `Autonomy`).
    let needs = if path == "/api/unlock" || path == "/api/unlock/forget" {
        Some(AutonomyNeed::Unlock)
    } else if path.ends_with("/credential/open") {
        Some(AutonomyNeed::OpenCredentials)
    } else if path.ends_with("/export") {
        Some(AutonomyNeed::Export)
    } else {
        None
    };
    Ok(needs)
}

/// Which autonomy capability a route demands of its caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutonomyNeed {
    Unlock,
    Export,
    OpenCredentials,
}

impl AutonomyNeed {
    fn label(self) -> &'static str {
        match self {
            Self::Unlock => "unlock",
            Self::Export => "export",
            Self::OpenCredentials => "open credentials",
        }
    }

    fn granted_by(self, autonomy: &apiary_core::manifest::Autonomy) -> bool {
        match self {
            Self::Unlock => autonomy.unlock,
            Self::Export => autonomy.export,
            Self::OpenCredentials => autonomy.open_credentials,
        }
    }
}

/// Does this caller hold the capability the route needs? The answer comes
/// from the caller's own RATIFIED manifest (`manifest.approved.yaml`), never
/// from the working copy — otherwise an agent able to write its manifest
/// could widen itself without a ratification.
fn autonomy_permits(
    state: &App,
    signer: Option<PublicKey>,
    need: AutonomyNeed,
) -> Result<(), (i64, String)> {
    let refuse = |detail: &str| {
        Err((
            -32602,
            format!(
                "'{}' is part of the human door: {detail}. A person grants it \
                 per capability under governance.autonomy, and must ratify that grant.",
                need.label()
            ),
        ))
    };
    let Some(signer) = signer else {
        return refuse("this call has no authenticated agent identity");
    };
    let Ok(npub) = apiary_core::identity::to_npub(&signer) else {
        return refuse("the caller identity could not be read");
    };
    let Ok(ks) = Keystore::open(&state.home) else {
        return refuse("the keystore is unavailable");
    };
    let dir = ks.agent_dir(&npub);
    if need.granted_by(&crate::approved_autonomy(&dir)) {
        return Ok(());
    }
    refuse("the calling agent has not been granted it")
}

async fn forward(
    state: &App,
    signer: Option<PublicKey>,
    method: Method,
    target: &str,
    body: Option<Value>,
) -> Result<Value, (i64, String)> {
    if let Some(need) = validate_target(&method, target)? {
        autonomy_permits(state, signer, need)?;
    }
    let bytes = match body {
        Some(body) => serde_json::to_vec(&body).map_err(|error| (-32602, error.to_string()))?,
        None => Vec::new(),
    };
    let mut builder = Request::builder()
        .method(method)
        .uri(target)
        .header("x-apiary-internal-token", &state.internal_token);
    if let Some(signer) = signer {
        let npub =
            apiary_core::identity::to_npub(&signer).map_err(|error| (-32603, error.to_string()))?;
        builder = builder.header("x-apiary-internal-signer", npub);
    }
    if !bytes.is_empty() {
        builder = builder.header("content-type", "application/json");
    }
    let request = builder
        .body(Body::from(bytes))
        .map_err(|error| (-32603, error.to_string()))?;
    let response = build_router(state.clone())
        .oneshot(request)
        .await
        .map_err(|never| match never {})?;
    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let body = to_bytes(response.into_body(), MAX_FORWARD_RESPONSE)
        .await
        .map_err(|error| (-32603, format!("could not read Apiary response: {error}")))?;
    let value = serde_json::from_slice::<Value>(&body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body).into_owned()));
    Ok(json!({
        "status": status.as_u16(),
        "content_type": content_type,
        "body": value
    }))
}

fn rpc_http_error(id: Value, code: i64, message: &str) -> Response {
    (
        StatusCode::OK,
        Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": code, "message": message}
        })),
    )
        .into_response()
}

fn audit_call(
    state: &App,
    signer: Option<PublicKey>,
    params: &Value,
    result: &Result<Value, (i64, String)>,
) {
    let Ok(_guard) = state.control_audit.lock() else {
        return;
    };
    let path = state.home.join("control-audit.jsonl");
    let previous = last_nonempty_line(&path)
        .and_then(|line| serde_json::from_str::<Value>(&line).ok())
        .and_then(|entry| entry["hash"].as_str().map(String::from));
    let caller = signer
        .and_then(|key| apiary_core::identity::to_npub(&key).ok())
        .unwrap_or_else(|| "local-open-mode".into());
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let summary = if name == "apiary_request" {
        json!({
            "method": arguments["method"],
            "path": arguments["path"],
            "body_sha256": arguments.get("body").map(|body| format!("{:x}", Sha256::digest(body.to_string().as_bytes())))
        })
    } else {
        json!({"agent": arguments.get("agent")})
    };
    let status = match result {
        Ok(value) if value["isError"] == true => "error",
        Ok(_) => "ok",
        Err(_) => "error",
    };
    let mut entry = json!({
        "at": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
        "caller": caller,
        "tool": name,
        "summary": summary,
        "status": status,
        "prev": previous,
    });
    let hash = format!("{:x}", Sha256::digest(entry.to_string().as_bytes()));
    entry["hash"] = json!(hash);
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    if let Ok(mut file) = options.open(&path) {
        let _ = writeln!(file, "{entry}");
    }
}

fn last_nonempty_line(path: &std::path::Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut cursor = file.seek(SeekFrom::End(0)).ok()?;
    let mut bytes = Vec::new();
    const CHUNK: u64 = 4096;
    while cursor > 0 {
        let take = cursor.min(CHUNK);
        cursor -= take;
        file.seek(SeekFrom::Start(cursor)).ok()?;
        let mut chunk = vec![0; take as usize];
        file.read_exact(&mut chunk).ok()?;
        chunk.extend(bytes);
        bytes = chunk;
        if bytes.iter().filter(|&&byte| byte == b'\n').count() > 1 {
            break;
        }
    }
    String::from_utf8(bytes)
        .ok()?
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{access::ManagerRegistry, AppState, AuthMode};
    use std::sync::Arc;

    fn test_state() -> App {
        let home = std::env::temp_dir().join(format!(
            "apiary-control-mcp-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        Arc::new(AppState {
            home,
            passphrase: std::sync::RwLock::new(None),
            remember_passphrase: None,
            forget_passphrase: None,
            automatic_unlock: std::sync::atomic::AtomicBool::new(false),
            auth: AuthMode::Open,
            origin: "http://127.0.0.1:7777".into(),
            managers: std::sync::RwLock::new(ManagerRegistry::in_memory(Vec::new())),
            token: None,
            browser_sessions: std::sync::Mutex::new(std::collections::HashMap::new()),
            pending_nip46: std::sync::Mutex::new(std::collections::HashMap::new()),
            remote_signers: std::sync::Mutex::new(std::collections::HashMap::new()),
            desktop_token: None,
            internal_token: "control-mcp-test-internal".into(),
            control_audit: std::sync::Mutex::new(()),
            control_tokens: std::sync::Mutex::new(()),
            listeners: std::sync::Mutex::new(std::collections::HashMap::new()),
            pending_oauth: std::sync::Mutex::new(std::collections::HashMap::new()),
            supervisor_notes: std::sync::Mutex::new(std::collections::HashMap::new()),
            admitted: std::sync::Mutex::new(std::collections::HashMap::new()),
            decisions: Default::default(),
        })
    }

    #[test]
    fn target_validation_blocks_escape_routes_and_gates_the_human_door() {
        // Ordinary management: no autonomy needed.
        assert_eq!(validate_target(&Method::GET, "/api/agents").unwrap(), None);
        assert_eq!(
            validate_target(&Method::POST, "/api/agents/npub1x/active").unwrap(),
            None
        );
        // The human door: allowed only against a granted capability.
        assert_eq!(
            validate_target(&Method::POST, "/api/agents/x/credential/open").unwrap(),
            Some(AutonomyNeed::OpenCredentials)
        );
        assert_eq!(
            validate_target(&Method::POST, "/api/agents/x/export").unwrap(),
            Some(AutonomyNeed::Export)
        );
        assert_eq!(
            validate_target(&Method::POST, "/api/unlock").unwrap(),
            Some(AutonomyNeed::Unlock)
        );
        // Never available to any caller, autonomous or not.
        assert!(validate_target(&Method::GET, "/api/events").is_err());
        assert!(validate_target(&Method::POST, "/api/host/pick-folder").is_err());
        assert!(validate_target(&Method::GET, "/api/../secret").is_err());
        assert!(validate_target(&Method::GET, "https://example.com/api/status").is_err());
    }

    /// The capability check reads the caller's RATIFIED manifest; with no
    /// grant (and no identity at all) every door route is refused.
    #[test]
    fn human_door_refuses_callers_without_a_grant() {
        let state = test_state();
        for need in [
            AutonomyNeed::Unlock,
            AutonomyNeed::Export,
            AutonomyNeed::OpenCredentials,
        ] {
            let denied = autonomy_permits(&state, None, need).unwrap_err();
            assert!(denied.1.contains("human door"), "explains itself: {denied:?}");
        }
    }

    #[test]
    fn catalog_marks_only_the_generic_request_as_mutating() {
        let catalog = tools();
        assert_eq!(catalog.len(), 4);
        assert!(catalog[..3]
            .iter()
            .all(|tool| tool["annotations"]["readOnlyHint"] == true));
        assert_eq!(catalog[3]["annotations"]["readOnlyHint"], false);
    }

    #[test]
    fn bundled_environment_denials_are_mcp_tool_errors() {
        assert!(!response_is_error(&json!({
            "environment": {"manifest": {"status": 200}, "skills": {"status": 200}}
        })));
        assert!(response_is_error(&json!({
            "environment": {"manifest": {"status": 403}, "skills": {"status": 403}}
        })));
    }

    #[tokio::test]
    async fn endpoint_lists_tools_and_forwards_to_the_rest_router() {
        let state = test_state();
        let list = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}});
        let response = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .body(Body::from(list.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["result"]["tools"].as_array().unwrap().len(), 4);

        let call = json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "apiary_list_agents", "arguments": {}}
        });
        let response = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .body(Body::from(call.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["result"]["structuredContent"]["status"], 200);
        assert_eq!(
            value["result"]["structuredContent"]["body"]["agents"],
            json!([])
        );
        let response = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/control/audit?tail=10")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let audit: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(audit["chain"]["valid"], true);
        assert_eq!(audit["chain"]["entries"], 1);
        let _ = std::fs::remove_dir_all(&state.home);
    }
}
