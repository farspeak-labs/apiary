//! MCP client — SPEC §6 meets the Model Context Protocol.
//!
//! Speaks the 2026-07-28 revision natively (stateless, per-request `_meta`,
//! no sessions) over both standard transports:
//!
//! - **stdio**: newline-delimited JSON-RPC to a client-launched subprocess,
//!   spawned with a scrubbed environment (env_clear + explicit allowlist —
//!   the same hygiene as the ACP adapter, and it matters more here: the
//!   spec says stdio servers inherit the host app's permissions).
//! - **Streamable HTTP**: one POST per message to a single MCP endpoint,
//!   `MCP-Protocol-Version` + `Mcp-Method`/`Mcp-Name` mirror headers,
//!   responses as plain JSON or a request-scoped SSE stream.
//!
//! Era detection per the spec's backward-compatibility rules: probe
//! `server/discover`; a result means modern, anything else falls back to
//! the legacy `initialize` handshake (2025-06-18) — which is what most of
//! today's server ecosystem still speaks.
//!
//! MRTR `input_required` results are refused, not proxied: Apiary runs are
//! autonomous and governed; a tool that demands interactive input mid-call
//! gets a clear error the model can relay.

use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

pub const MODERN_VERSION: &str = "2026-07-28";
pub const LEGACY_VERSION: &str = "2025-06-18";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const PROBE_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Debug, Clone, PartialEq)]
pub enum Era {
    Modern,
    Legacy,
}

#[derive(Debug, Clone)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    /// Server-declared MCP `annotations.readOnlyHint`. Missing is false,
    /// per the protocol. This is still server-supplied trust metadata.
    pub read_only: bool,
}

#[derive(Debug, Clone)]
pub struct CallOutcome {
    pub text: String,
    pub is_error: bool,
}

/// Where and how to reach the server.
#[derive(Clone)]
pub enum Binding {
    Stdio {
        command: String,
        args: Vec<String>,
        /// Environment variable NAMES passed through from the host env.
        /// Everything else is scrubbed.
        env_passthrough: Vec<String>,
    },
    Http {
        url: String,
        /// Bearer token (raw or OAuth access token), sent on every request.
        bearer: Option<String>,
    },
}

enum Wire {
    Stdio {
        child: Child,
        stdin: std::process::ChildStdin,
        lines: mpsc::Receiver<String>,
    },
    Http {
        client: reqwest::blocking::Client,
        url: String,
        bearer: Option<String>,
        /// Legacy streamable-HTTP session id, echoed once the server mints it.
        session: Option<String>,
    },
}

pub struct McpClient {
    wire: Wire,
    pub era: Era,
    next_id: u64,
}

/// A 401 carrying the server's WWW-Authenticate challenge — the caller may
/// hold a refresh token and retry.
#[derive(Debug)]
pub struct AuthRequired(pub String);

fn meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": MODERN_VERSION,
        "io.modelcontextprotocol/clientInfo": {
            "name": "apiary",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "io.modelcontextprotocol/clientCapabilities": {},
    })
}

impl Drop for McpClient {
    fn drop(&mut self) {
        if let Wire::Stdio { child, .. } = &mut self.wire {
            // Graceful: stdin already closes when the handle drops with us;
            // give the server a beat, then make sure it is gone.
            std::thread::sleep(Duration::from_millis(150));
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl McpClient {
    /// Connect and determine the server's era.
    pub fn connect(binding: Binding) -> Result<Self, crate::Error> {
        let wire = match binding {
            Binding::Stdio {
                command,
                args,
                env_passthrough,
            } => {
                let mut cmd = Command::new(&command);
                cmd.args(&args)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .env_clear();
                // Minimal viable environment plus the declared passthrough.
                for name in ["PATH", "HOME", "TMPDIR", "LANG"]
                    .iter()
                    .map(|s| s.to_string())
                    .chain(env_passthrough.iter().cloned())
                {
                    if let Ok(v) = std::env::var(&name) {
                        cmd.env(&name, v);
                    }
                }
                let mut child = cmd.spawn().map_err(|e| {
                    crate::Error::Provider(format!("mcp stdio spawn '{command}': {e}"))
                })?;
                let stdin = child.stdin.take().expect("piped stdin");
                let stdout = child.stdout.take().expect("piped stdout");
                let (tx, rx) = mpsc::channel::<String>();
                std::thread::spawn(move || {
                    let reader = BufReader::new(stdout);
                    for line in reader.lines() {
                        match line {
                            Ok(l) if !l.trim().is_empty() => {
                                if tx.send(l).is_err() {
                                    break;
                                }
                            }
                            Ok(_) => continue,
                            Err(_) => break,
                        }
                    }
                });
                Wire::Stdio {
                    child,
                    stdin,
                    lines: rx,
                }
            }
            Binding::Http { url, bearer } => Wire::Http {
                client: reqwest::blocking::Client::builder()
                    .timeout(REQUEST_TIMEOUT)
                    .build()
                    .map_err(|e| crate::Error::Provider(format!("mcp http client: {e}")))?,
                url,
                bearer,
                session: None,
            },
        };
        let mut me = Self {
            wire,
            era: Era::Modern,
            next_id: 0,
        };
        me.detect_era()?;
        Ok(me)
    }

    fn detect_era(&mut self) -> Result<(), crate::Error> {
        // Probe with server/discover per the spec: a result = modern; any
        // error or timeout = legacy `initialize` fallback (deliberately NOT
        // keyed to one error code).
        let probe = self.raw_request(
            "server/discover",
            json!({"_meta": meta()}),
            None,
            PROBE_TIMEOUT,
        );
        match probe {
            Ok(v) if v.get("result").is_some() => {
                self.era = Era::Modern;
                Ok(())
            }
            _ => {
                self.era = Era::Legacy;
                let init = self.raw_request(
                    "initialize",
                    json!({
                        "protocolVersion": LEGACY_VERSION,
                        "capabilities": {},
                        "clientInfo": {"name": "apiary", "version": env!("CARGO_PKG_VERSION")},
                    }),
                    None,
                    REQUEST_TIMEOUT,
                )?;
                if init.get("result").is_none() {
                    // Show the whole response when there is no `error` to
                    // quote: "initialize failed: null" tells nobody anything.
                    let detail = match init.get("error") {
                        Some(e) => e.to_string(),
                        None => format!("no result in response: {init}"),
                    };
                    return Err(crate::Error::Provider(format!(
                        "mcp initialize failed: {detail}"
                    )));
                }
                self.notify("notifications/initialized", json!({}))?;
                Ok(())
            }
        }
    }

    fn params_with_meta(&self, mut params: Value) -> Value {
        if self.era == Era::Modern {
            params["_meta"] = meta();
        }
        params
    }

    fn protocol_version(&self) -> &'static str {
        match self.era {
            Era::Modern => MODERN_VERSION,
            Era::Legacy => LEGACY_VERSION,
        }
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<(), crate::Error> {
        let msg = json!({"jsonrpc": "2.0", "method": method, "params": params});
        let proto = self.protocol_version();
        match &mut self.wire {
            Wire::Stdio { stdin, .. } => {
                let line = serde_json::to_string(&msg)?;
                writeln!(stdin, "{line}")
                    .map_err(|e| crate::Error::Provider(format!("mcp stdio write: {e}")))?;
                stdin
                    .flush()
                    .map_err(|e| crate::Error::Provider(format!("mcp stdio flush: {e}")))?;
                Ok(())
            }
            Wire::Http {
                client,
                url,
                bearer,
                session,
            } => {
                let mut req = client
                    .post(url.as_str())
                    .header("content-type", "application/json")
                    .header("accept", "application/json, text/event-stream")
                    .header("mcp-protocol-version", proto)
                    .json(&msg);
                if let Some(b) = bearer {
                    req = req.bearer_auth(b);
                }
                if let Some(s) = session {
                    req = req.header("mcp-session-id", s.clone());
                }
                let _ = req.send();
                Ok(())
            }
        }
    }

    /// One JSON-RPC round trip. `tool_name` feeds the Mcp-Name mirror and
    /// any Mcp-Param-* headers on HTTP.
    fn raw_request(
        &mut self,
        method: &str,
        params: Value,
        header_params: Option<&[(String, String)]>,
        timeout: Duration,
    ) -> Result<Value, crate::Error> {
        self.next_id += 1;
        let id = self.next_id;
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let proto = self.protocol_version();
        match &mut self.wire {
            Wire::Stdio { stdin, lines, .. } => {
                let line = serde_json::to_string(&msg)?;
                writeln!(stdin, "{line}")
                    .map_err(|e| crate::Error::Provider(format!("mcp stdio write: {e}")))?;
                stdin
                    .flush()
                    .map_err(|e| crate::Error::Provider(format!("mcp stdio flush: {e}")))?;
                let deadline = std::time::Instant::now() + timeout;
                loop {
                    let remaining = deadline
                        .checked_duration_since(std::time::Instant::now())
                        .ok_or_else(|| {
                            crate::Error::Provider(format!("mcp: timeout awaiting {method}"))
                        })?;
                    let raw = lines.recv_timeout(remaining).map_err(|_| {
                        crate::Error::Provider(format!(
                            "mcp: no response to {method} (timeout/EOF)"
                        ))
                    })?;
                    let v: Value = match serde_json::from_str(&raw) {
                        Ok(v) => v,
                        Err(_) => continue, // not our concern; spec: stdout is MCP-only, but be tolerant
                    };
                    // Responses correlate by id; notifications are skipped.
                    if v.get("id").and_then(Value::as_u64) == Some(id) {
                        return Ok(v);
                    }
                }
            }
            Wire::Http {
                client,
                url,
                bearer,
                session,
            } => {
                let mut req = client
                    .post(url.as_str())
                    .timeout(timeout)
                    .header("content-type", "application/json")
                    .header("accept", "application/json, text/event-stream")
                    .header("mcp-protocol-version", proto)
                    .header("mcp-method", method)
                    .json(&msg);
                if let Some(name) = msg
                    .get("params")
                    .and_then(|p| p.get("name").or_else(|| p.get("uri")))
                    .and_then(Value::as_str)
                {
                    req = req.header("mcp-name", header_safe(name));
                }
                if let Some(hp) = header_params {
                    for (hname, hval) in hp {
                        req = req.header(format!("mcp-param-{hname}"), header_safe(hval));
                    }
                }
                if let Some(b) = bearer {
                    req = req.bearer_auth(b);
                }
                if let Some(s) = session {
                    req = req.header("mcp-session-id", s.clone());
                }
                let resp = req
                    .send()
                    .map_err(|e| crate::Error::Provider(format!("mcp http: {e}")))?;
                if resp.status().as_u16() == 401 {
                    let challenge = resp
                        .headers()
                        .get("www-authenticate")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_string();
                    return Err(crate::Error::Provider(format!(
                        "mcp-auth-required: {challenge}"
                    )));
                }
                if let Some(sid) = resp
                    .headers()
                    .get("mcp-session-id")
                    .and_then(|v| v.to_str().ok())
                {
                    *session = Some(sid.to_string());
                }
                let status = resp.status();
                let ct = resp
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                let body = resp
                    .text()
                    .map_err(|e| crate::Error::Provider(format!("mcp http body: {e}")))?;
                // A gateway's own error (403, 502, …) is often valid JSON with
                // neither result nor error, which used to surface downstream as
                // "initialize failed: null". Say what actually came back.
                if !status.is_success() {
                    return Err(crate::Error::Provider(format!(
                        "mcp http {} on {method}: {}",
                        status.as_u16(),
                        body.chars().take(200).collect::<String>()
                    )));
                }
                if ct.starts_with("text/event-stream") {
                    // Request-scoped SSE: the final response terminates the
                    // stream; take the last data frame with our id.
                    for data in body.lines().filter_map(|l| l.strip_prefix("data:")) {
                        if let Ok(v) = serde_json::from_str::<Value>(data.trim()) {
                            if v.get("id").and_then(Value::as_u64) == Some(id) {
                                return Ok(v);
                            }
                        }
                    }
                    Err(crate::Error::Provider(
                        "mcp: SSE stream ended without a response".into(),
                    ))
                } else {
                    serde_json::from_str(&body).map_err(|e| {
                        crate::Error::Provider(format!(
                            "mcp: non-JSON response ({e}): {}",
                            body.chars().take(200).collect::<String>()
                        ))
                    })
                }
            }
        }
    }

    /// Swap the bearer token after an OAuth refresh (HTTP wire only).
    pub fn set_bearer(&mut self, token: String) {
        if let Wire::Http { bearer, .. } = &mut self.wire {
            *bearer = Some(token);
        }
    }

    pub fn tools_list(&mut self) -> Result<Vec<McpTool>, crate::Error> {
        let params = self.params_with_meta(json!({}));
        let v = self.raw_request("tools/list", params, None, REQUEST_TIMEOUT)?;
        if let Some(err) = v.get("error") {
            return Err(crate::Error::Provider(format!("mcp tools/list: {err}")));
        }
        let tools = v["result"]["tools"].as_array().cloned().unwrap_or_default();
        Ok(tools
            .iter()
            .filter_map(|t| {
                Some(McpTool {
                    name: t.get("name")?.as_str()?.to_string(),
                    description: t
                        .get("description")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    input_schema: t
                        .get("inputSchema")
                        .cloned()
                        .unwrap_or_else(|| json!({"type": "object"})),
                    read_only: t
                        .get("annotations")
                        .and_then(|a| a.get("readOnlyHint"))
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                })
            })
            .collect())
    }

    pub fn tools_call(
        &mut self,
        tool: &McpTool,
        arguments: &Value,
    ) -> Result<CallOutcome, crate::Error> {
        let header_params = extract_header_params(&tool.input_schema, arguments);
        let params = self.params_with_meta(json!({
            "name": tool.name,
            "arguments": arguments,
        }));
        let v = self.raw_request("tools/call", params, Some(&header_params), REQUEST_TIMEOUT)?;
        if let Some(err) = v.get("error") {
            return Err(crate::Error::Provider(format!("mcp tools/call: {err}")));
        }
        let result = &v["result"];
        if result.get("resultType").and_then(Value::as_str) == Some("input_required") {
            return Ok(CallOutcome {
                text: "This tool requires interactive input mid-call (MCP multi-round-trip), \
                       which is not available in an autonomous governed run. Choose a \
                       different approach or report this limitation."
                    .into(),
                is_error: true,
            });
        }
        let is_error = result
            .get("isError")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        // Prefer structuredContent, else concatenate text items.
        let text = if let Some(sc) = result.get("structuredContent") {
            sc.to_string()
        } else {
            let parts: Vec<String> = result["content"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|c| match c.get("type").and_then(Value::as_str) {
                            Some("text") => c.get("text").and_then(Value::as_str).map(String::from),
                            Some(other) => Some(format!("[{other} content omitted]")),
                            None => None,
                        })
                        .collect()
                })
                .unwrap_or_default();
            parts.join("\n")
        };
        Ok(CallOutcome { text, is_error })
    }
}

/// Header-value encoding per the Streamable HTTP spec: plain visible-ASCII
/// values pass through; anything else (or a value matching the sentinel)
/// is carried as `=?base64?...?=` of the UTF-8 bytes.
fn header_safe(value: &str) -> String {
    let plain = !value.is_empty()
        && value
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b) || b == 0x20)
        && value == value.trim()
        && !(value.starts_with("=?base64?") && value.ends_with("?="))
        || value.is_empty();
    if plain {
        value.to_string()
    } else {
        use base64::Engine;
        format!(
            "=?base64?{}?=",
            base64::engine::general_purpose::STANDARD.encode(value.as_bytes())
        )
    }
}

/// Walk `properties` chains for `x-mcp-header` annotations and extract the
/// matching argument values (statically reachable paths only, per spec).
fn extract_header_params(schema: &Value, arguments: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut seen = HashMap::new();
    walk(schema, arguments, &mut out, &mut seen);
    fn walk(
        schema: &Value,
        args: &Value,
        out: &mut Vec<(String, String)>,
        seen: &mut HashMap<String, ()>,
    ) {
        let Some(props) = schema.get("properties").and_then(Value::as_object) else {
            return;
        };
        for (key, prop) in props {
            let value = args.get(key);
            if let Some(hname) = prop.get("x-mcp-header").and_then(Value::as_str) {
                let valid = !hname.is_empty()
                    && hname
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
                    && seen.insert(hname.to_lowercase(), ()).is_none();
                if valid {
                    let rendered = match value {
                        Some(Value::String(s)) => Some(s.clone()),
                        Some(Value::Bool(b)) => Some(b.to_string()),
                        Some(Value::Number(n)) if n.is_i64() || n.is_u64() => Some(n.to_string()),
                        _ => None,
                    };
                    if let Some(r) = rendered {
                        out.push((hname.to_string(), r));
                    }
                }
            }
            // Nested objects: chains of `properties` keys only.
            if prop.get("properties").is_some() {
                walk(prop, value.unwrap_or(&Value::Null), out, seen);
            }
        }
    }
    out
}

/// Sanitize an MCP tool name into the model-facing tool namespace:
/// `[A-Za-z0-9_-]`, ≤ 64 chars, `mcp_` prefix.
pub fn model_tool_name(mcp_name: &str) -> String {
    let cleaned: String = mcp_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let mut name = format!("mcp_{cleaned}");
    name.truncate(64);
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_names_sanitize_for_the_model() {
        assert_eq!(model_tool_name("read_text_file"), "mcp_read_text_file");
        assert_eq!(model_tool_name("admin.tools.list"), "mcp_admin_tools_list");
        assert!(model_tool_name(&"x".repeat(200)).len() <= 64);
    }

    #[test]
    fn header_values_encode_safely() {
        assert_eq!(header_safe("us-west1"), "us-west1");
        assert!(header_safe("Hello, 世界").starts_with("=?base64?"));
        assert!(header_safe(" padded ").starts_with("=?base64?"));
    }

    #[test]
    fn x_mcp_headers_extracted_from_properties_chains() {
        let schema = json!({"type":"object","properties":{
            "region": {"type":"string","x-mcp-header":"Region"},
            "nested": {"type":"object","properties":{
                "tenant": {"type":"string","x-mcp-header":"Tenant"}}},
            "query": {"type":"string"}}});
        let args = json!({"region":"us-west1","nested":{"tenant":"acme"},"query":"q"});
        let hp = extract_header_params(&schema, &args);
        assert!(hp.contains(&("Region".to_string(), "us-west1".to_string())));
        assert!(hp.contains(&("Tenant".to_string(), "acme".to_string())));
        assert_eq!(hp.len(), 2);
    }
}
