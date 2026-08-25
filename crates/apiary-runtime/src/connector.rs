//! Connectors — SPEC §6. Everything capable is a connector; the core has
//! custody, connectors have capability. A connector absent from the manifest
//! is a capability that does not exist (default-deny by construction).
//!
//! Caps come from the manifest entry and are enforced HERE, host-side —
//! the model's arguments are requests, not commands.

use apiary_core::custody::{AgentHandle, Custody};
use apiary_core::manifest::Manifest;
use nostr::prelude::*;
use serde_json::{json, Value};

/// A connector's tool-facing definition (Anthropic tool schema shape).
#[derive(Debug, Clone)]
pub struct ToolDef {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

pub trait Connector {
    fn def(&self) -> ToolDef;
    /// Execute with host-checked caps. Custody is passed so signing/decrypt
    /// happens here, at call time — the model never holds material.
    fn execute(
        &self,
        custody: &Custody,
        agent: &AgentHandle,
        args: &Value,
    ) -> Result<String, crate::Error>;
    /// Does this tool only LOOK at the world? Reading, searching, listing:
    /// true. Sending, writing, publishing, proposing: false.
    ///
    /// The host uses this to answer "did anything actually happen?" without
    /// asking the model to tell it — which is how a proactive run earns the
    /// right to be recorded as quiet. Defaults to false so a connector
    /// added later is assumed to act until it says otherwise.
    fn observes_only(&self) -> bool {
        false
    }
}

/// The connector kinds this host can bind — the one list (README:
/// "one list per concept"); bind_connectors and the API both read it.
pub const BOUND_KINDS: &[&str] = &[
    "nostr-publish",
    "mock-echo",
    "mcp",
    "obsidian",
    "markdown-vault",
    "web-search",
    "web-fetch",
    "files",
    "git",
];

/// Build the agent's connector set from its manifest. Unknown kinds are an
/// error, not a skip — a manifest declaring a capability the host can't
/// bind should fail loudly at run start, not silently at dispatch.
pub fn bind_connectors(
    manifest: &Manifest,
    custody: &Custody,
    agent: &AgentHandle,
) -> Result<Vec<Box<dyn Connector>>, crate::Error> {
    bind_connectors_in(manifest, custody, agent, None)
}

/// With the agent dir known, the agent also gets the PROPOSE tools —
/// harmless by construction (a proposal is never enacted by the agent).
pub fn bind_connectors_in(
    manifest: &Manifest,
    custody: &Custody,
    agent: &AgentHandle,
    agent_dir: Option<&std::path::Path>,
) -> Result<Vec<Box<dyn Connector>>, crate::Error> {
    let mut out: Vec<Box<dyn Connector>> = Vec::new();
    let has_explicit_web_fetch = manifest
        .connectors
        .iter()
        .any(|connector| connector.kind == "web-fetch");
    if let Some(dir) = agent_dir {
        out.push(Box::new(crate::proposal::ProposeRoutine {
            agent_dir: dir.to_path_buf(),
            manifest: manifest.clone(),
        }));
        out.push(Box::new(crate::proposal::ProposeAmendment {
            agent_dir: dir.to_path_buf(),
            manifest: manifest.clone(),
        }));
        out.push(Box::new(crate::proposal::ProposeAgent {
            agent_dir: dir.to_path_buf(),
            npub: manifest.identity.npub.clone(),
        }));
    }
    for entry in &manifest.connectors {
        match entry.kind.as_str() {
            "mcp" => out.extend(bind_mcp(entry, custody, agent, agent_dir)?),
            "obsidian" => out.extend(bind_vault(entry, true, manifest.memory.knowledge_home.as_ref())?),
            "markdown-vault" => out.extend(bind_vault(entry, false, manifest.memory.knowledge_home.as_ref())?),
            "web-search" => {
                out.push(Box::new(bind_web_search(entry)?));
                // A full-research grant can deliberately include the public page
                // reader. Do not expose a duplicate web_fetch tool when the
                // manifest already carries a separately governed fetch grant.
                if !has_explicit_web_fetch
                    && entry
                        .caps
                        .get("fetch_public_pages")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                {
                    out.push(Box::new(bind_web_fetch_caps(
                        true,
                        Vec::new(),
                        false,
                        entry
                            .caps
                            .get("fetch_max_bytes")
                            .and_then(Value::as_u64)
                            .unwrap_or(262_144),
                    )?));
                }
            }
            "web-fetch" => out.push(Box::new(bind_web_fetch(entry)?)),
            "files" => out.extend(bind_files(entry)?),
            "git" => out.extend(bind_git(entry)?),
            "nostr-publish" => {
                let relays: Vec<String> = entry
                    .caps
                    .get("relays")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|r| r.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                if relays.is_empty() {
                    return Err(crate::Error::Provider(
                        "nostr-publish requires caps.relays (an allowlist — \
                         the agent may only publish where the manifest says)"
                            .into(),
                    ));
                }
                out.push(Box::new(NostrPublish { relays }));
            }
            "mock-echo" => out.push(Box::new(MockEcho)),
            other => {
                return Err(crate::Error::Provider(format!(
                    "unknown connector kind '{other}' (host binds: {})",
                    BOUND_KINDS.join(", ")
                )))
            }
        }
    }
    // Presence-derived tools: a channel the agent LIVES on is also a place
    // it may speak first. Same sealed token, same allowlist — declaring
    // presence was the ratified act, so no separate grant exists to forget.
    if let Some(tg) = manifest.presence.channel("telegram") {
        if let Some(cred) = &tg.credential {
            let speaker = crate::speak::speak_slot(manifest).and_then(|slot| {
                let credential = slot
                    .credential
                    .as_ref()
                    .and_then(|b| custody.open(agent, b).ok());
                crate::speak::bind_speaker(manifest, credential)
            });
            out.push(Box::new(crate::telegram::TelegramSend {
                credential: cred.clone(),
                allowed_chats: tg.list_config("allowed_chats"),
                speaker,
            }));
        }
    }
    Ok(out)
}

/// Publish a kind-1 note to the manifest-allowlisted relays, signed by the
/// agent's own key — the one connector whose credential IS the identity.
pub struct NostrPublish {
    relays: Vec<String>,
}

impl Connector for NostrPublish {
    fn def(&self) -> ToolDef {
        ToolDef {
            name: "nostr_publish".into(),
            description: format!(
                "Publish a public nostr note (kind 1), signed with your own identity key. \
                 It will be permanently attributable to you on: {}. \
                 Use it when the task asks you to post, announce, or say something publicly.",
                self.relays.join(", ")
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "The note text to publish."
                    }
                },
                "required": ["content"],
                "additionalProperties": false
            }),
        }
    }

    fn execute(
        &self,
        custody: &Custody,
        agent: &AgentHandle,
        args: &Value,
    ) -> Result<String, crate::Error> {
        let content = args
            .get("content")
            .and_then(|c| c.as_str())
            .ok_or_else(|| crate::Error::Provider("nostr_publish: missing content".into()))?;
        // Custody signs; the relay client only ever sees the finished event.
        let event = custody.sign(agent, EventBuilder::new(Kind::TextNote, content))?;
        let mut acks = Vec::new();
        let mut failures = Vec::new();
        for relay in &self.relays {
            match crate::relay::publish(relay, &event) {
                Ok(msg) => acks.push(format!("{relay}: {msg}")),
                Err(e) => failures.push(format!("{relay}: {e}")),
            }
        }
        if acks.is_empty() {
            return Err(crate::Error::Provider(format!(
                "nostr_publish: no relay accepted the note ({})",
                failures.join("; ")
            )));
        }
        Ok(json!({
            "event_id": event.id.to_hex(),
            "accepted": acks,
            "failed": failures,
        })
        .to_string())
    }
}

/// Test connector: echoes its arguments. Lets tests exercise the full
/// dispatch + logging path with no network.
pub struct MockEcho;

impl Connector for MockEcho {
    fn def(&self) -> ToolDef {
        ToolDef {
            name: "mock_echo".into(),
            description: "Echo the input back (test connector).".into(),
            input_schema: json!({
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
                "additionalProperties": false
            }),
        }
    }

    fn execute(
        &self,
        _custody: &Custody,
        _agent: &AgentHandle,
        args: &Value,
    ) -> Result<String, crate::Error> {
        Ok(format!(
            "echo: {}",
            args.get("text").and_then(|t| t.as_str()).unwrap_or("")
        ))
    }
}

// ---------------------------------------------------------------- mcp

/// Bind an `mcp` manifest entry: connect (era-detected), list the server's
/// tools, clamp to the human-owned `allowed_tools` allowlist, and expose
/// each surviving tool as its own Connector. Caps:
///
/// ```yaml
/// - type: mcp
///   caps:
///     transport: stdio           # or "http"
///     command: npx               # stdio only
///     args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
///     env: []                    # env var NAMES passed through (scrubbed otherwise)
///     url: https://…/mcp         # http only
///     allowed_tools: [read_text_file, list_directory]   # REQUIRED; ["*"] = all
///     access: read-only          # or "read-write"; absent preserves legacy behavior
///     tool_access:               # optional per-tool override; keys are the allowlist
///       read_text_file: read-only
///       update_file: read-write
///   credential: <nip44 blob>     # http only: bearer token or OAuth JSON
/// ```
///
/// The allowlist is required and enforced host-side: an MCP server offers
/// whatever it likes; the manifest decides what the agent may touch.
fn bind_mcp(
    entry: &apiary_core::manifest::Connector,
    custody: &Custody,
    agent: &AgentHandle,
    agent_dir: Option<&std::path::Path>,
) -> Result<Vec<Box<dyn Connector>>, crate::Error> {
    use std::sync::{Arc, Mutex};
    let cap_str = |k: &str| entry.caps.get(k).and_then(|v| v.as_str()).map(String::from);
    let cap_list = |k: &str| -> Vec<String> {
        entry
            .caps
            .get(k)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    let tool_access = entry
        .caps
        .get("tool_access")
        .and_then(|value| value.as_object())
        .map(|policies| {
            policies
                .iter()
                .map(|(name, mode)| {
                    let mode = mode.as_str().ok_or_else(|| {
                        crate::Error::Provider(format!(
                            "mcp caps.tool_access.{name} must be read-only or read-write"
                        ))
                    })?;
                    match mode {
                        "read-only" => Ok((name.clone(), true)),
                        "read-write" => Ok((name.clone(), false)),
                        other => Err(crate::Error::Provider(format!(
                            "mcp caps.tool_access.{name} '{other}' is invalid (read-only | read-write)"
                        ))),
                    }
                })
                .collect::<Result<std::collections::HashMap<_, _>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    let mut allowed = cap_list("allowed_tools");
    if !tool_access.is_empty() {
        allowed = tool_access.keys().cloned().collect();
    }
    if allowed.is_empty() {
        // Freshly granted, nothing ticked yet: inert, not broken. Binding
        // zero tools keeps the agent answering while the governor finishes
        // DISCOVER → APPLY; the host supervisor surfaces the gap loudly.
        return Ok(Vec::new());
    }
    let read_only = match cap_str("access").as_deref() {
        Some("read-only") => true,
        Some("read-write") | None => false,
        Some("mixed") if !tool_access.is_empty() => false,
        Some(other) => {
            return Err(crate::Error::Provider(format!(
                "mcp caps.access '{other}' is invalid (read-only | read-write)"
            )))
        }
    };
    let transport = cap_str("transport").unwrap_or_else(|| "stdio".into());
    // Sealed credential: either a raw bearer token or an OAuth JSON object
    // ({"type":"oauth","access_token":…}). Opened just-in-time, per use.
    let credential_plain = match &entry.credential {
        Some(blob) => Some(custody.open(agent, blob)?.as_str().to_string()),
        None => None,
    };
    let (binding, refresh) = match transport.as_str() {
        "stdio" => (
            crate::mcp::Binding::Stdio {
                command: cap_str("command").ok_or_else(|| {
                    crate::Error::Provider("mcp stdio requires caps.command".into())
                })?,
                args: cap_list("args"),
                env_passthrough: cap_list("env"),
            },
            None,
        ),
        "http" => {
            let raw_url = cap_str("url")
                .ok_or_else(|| crate::Error::Provider("mcp http requires caps.url".into()))?;
            let url = resolve_mcp_url(&raw_url, agent_dir)?;
            let (bearer, refresh) = match credential_plain.as_deref() {
                None => (None, None),
                Some(raw) => match serde_json::from_str::<Value>(raw) {
                    Ok(v) if v.get("type").and_then(Value::as_str) == Some("oauth") => (
                        v.get("access_token")
                            .and_then(Value::as_str)
                            .map(String::from),
                        Some(v),
                    ),
                    _ => (Some(raw.to_string()), None),
                },
            };
            (crate::mcp::Binding::Http { url, bearer }, refresh)
        }
        other => {
            return Err(crate::Error::Provider(format!(
                "mcp transport '{other}' not supported (stdio | http)"
            )))
        }
    };
    // Connect + list with one 401 recovery each: the sealed access token
    // routinely expires between runs — the refresh token is the durable
    // grant. Without this every bind (so every mention) dies on a token
    // that the tool-call path would have refreshed anyway.
    let auth_required = |e: &crate::Error| {
        matches!(e, crate::Error::Provider(m) if m.starts_with("mcp-auth-required"))
    };
    let refresh_or = |e: crate::Error| match &refresh {
        Some(r) => refresh_access_token(r).map_err(|re| {
            crate::Error::Provider(format!(
                "mcp server rejected the token (401) and the refresh failed ({re}) — \
                 re-grant the connector to re-authorize"
            ))
        }),
        None => Err(e),
    };
    let mut client = match crate::mcp::McpClient::connect(binding.clone()) {
        Ok(c) => c,
        Err(e) if auth_required(&e) => {
            let token = refresh_or(e)?;
            let binding = match binding {
                crate::mcp::Binding::Http { url, .. } => crate::mcp::Binding::Http {
                    url,
                    bearer: Some(token),
                },
                other => other,
            };
            crate::mcp::McpClient::connect(binding)?
        }
        Err(e) => return Err(e),
    };
    let tools = match client.tools_list() {
        Ok(t) => t,
        Err(e) if auth_required(&e) => {
            client.set_bearer(refresh_or(e)?);
            client.tools_list()?
        }
        Err(e) => return Err(e),
    };
    let wildcard = allowed.iter().any(|a| a == "*");
    let granted: Vec<crate::mcp::McpTool> = tools
        .into_iter()
        .filter(|t| mcp_tool_allowed(t, &allowed, wildcard, read_only, &tool_access))
        .collect();
    if granted.is_empty() {
        let message = if read_only {
            "mcp: no allowed tool is explicitly marked readOnlyHint=true; \
             unmarked tools fail closed in read-only mode"
        } else {
            "mcp: server offered no tool matching caps.allowed_tools — \
             check the allowlist against the server's actual tool names"
        };
        return Err(crate::Error::Provider(message.into()));
    }
    let shared = Arc::new(Mutex::new(client));
    let mut out: Vec<Box<dyn Connector>> = Vec::new();
    let mut used_names: Vec<String> = Vec::new();
    for tool in granted {
        let mut name = crate::mcp::model_tool_name(&tool.name);
        while used_names.contains(&name) {
            name.truncate(60);
            name.push('x');
        }
        used_names.push(name.clone());
        out.push(Box::new(McpToolConnector {
            model_name: name,
            tool,
            client: shared.clone(),
            refresh: refresh.clone(),
        }));
    }
    Ok(out)
}

fn resolve_mcp_url(
    configured: &str,
    agent_dir: Option<&std::path::Path>,
) -> Result<String, crate::Error> {
    if configured != "apiary://local/mcp" {
        return Ok(configured.to_string());
    }
    let agent_dir = agent_dir.ok_or_else(|| {
        crate::Error::Provider(
            "apiary://local/mcp requires an agent directory (run through an Apiary host)".into(),
        )
    })?;
    let home = agent_dir
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or_else(|| crate::Error::Provider("could not resolve the Apiary home".into()))?;
    let path = home.join("control.json");
    let raw = std::fs::read_to_string(&path).map_err(|error| {
        crate::Error::Provider(format!(
            "{} is unavailable; start Apiary or use an explicit MCP URL: {error}",
            path.display()
        ))
    })?;
    let value: Value = serde_json::from_str(&raw)?;
    value
        .get("url")
        .and_then(Value::as_str)
        .filter(|url| url.starts_with("http://") || url.starts_with("https://"))
        .map(String::from)
        .ok_or_else(|| crate::Error::Provider(format!("{} has no valid url", path.display())))
}

fn mcp_tool_allowed(
    tool: &crate::mcp::McpTool,
    allowed: &[String],
    wildcard: bool,
    read_only: bool,
    tool_access: &std::collections::HashMap<String, bool>,
) -> bool {
    if !tool_access.is_empty() {
        return tool_access
            .get(&tool.name)
            .is_some_and(|requires_read_only| !requires_read_only || tool.read_only);
    }
    (wildcard || allowed.contains(&tool.name)) && (!read_only || tool.read_only)
}

struct McpToolConnector {
    model_name: String,
    tool: crate::mcp::McpTool,
    client: std::sync::Arc<std::sync::Mutex<crate::mcp::McpClient>>,
    /// OAuth material for 401 recovery: {"token_endpoint","client_id","refresh_token",…}.
    refresh: Option<Value>,
}

impl Connector for McpToolConnector {
    /// The server's own readOnlyHint. Unmarked tools count as acting —
    /// same fail-closed reading the read-only cap already applies.
    fn observes_only(&self) -> bool {
        self.tool.read_only
    }

    fn def(&self) -> ToolDef {
        ToolDef {
            name: self.model_name.clone(),
            description: format!(
                "{} (via a granted MCP server; the manifest allowlists this tool)",
                self.tool.description
            ),
            input_schema: self.tool.input_schema.clone(),
        }
    }

    fn execute(
        &self,
        _custody: &Custody,
        _agent: &AgentHandle,
        args: &Value,
    ) -> Result<String, crate::Error> {
        let mut client = self
            .client
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let outcome =
            match client.tools_call(&self.tool, args) {
                Ok(o) => o,
                Err(crate::Error::Provider(msg)) if msg.starts_with("mcp-auth-required") => {
                    // One refresh attempt, then one retry — bounded, no loops.
                    let refreshed = self
                        .refresh
                        .as_ref()
                        .and_then(|r| refresh_access_token(r).ok());
                    match refreshed {
                        Some(token) => {
                            client.set_bearer(token);
                            client.tools_call(&self.tool, args)?
                        }
                        None => return Err(crate::Error::Provider(
                            "mcp server rejected the token (401) and no refresh was possible — \
                             re-grant the connector to re-authorize"
                                .into(),
                        )),
                    }
                }
                Err(e) => return Err(e),
            };
        if outcome.is_error {
            Ok(format!("TOOL ERROR (self-correctable): {}", outcome.text))
        } else {
            Ok(outcome.text)
        }
    }
}

/// OAuth refresh-token grant (public client shape). Returns the new access
/// token; the refreshed session lives for this run only — the durable seed
/// stays sealed in the manifest.
/// One refresh-token exchange; used by the 401-recovery in tool calls
/// and by tool DISCOVERY (which otherwise dies on a stale access token).
pub fn refresh_access_token(oauth: &Value) -> Result<String, crate::Error> {
    let get = |k: &str| {
        oauth
            .get(k)
            .and_then(Value::as_str)
            .ok_or_else(|| crate::Error::Provider(format!("oauth credential missing {k}")))
    };
    let refresh_token = get("refresh_token")?;
    let token_endpoint = get("token_endpoint")?;
    let client_id = get("client_id")?;
    let mut form = vec![
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", refresh_token.to_string()),
        ("client_id", client_id.to_string()),
    ];
    if let Some(resource) = oauth.get("resource").and_then(Value::as_str) {
        form.push(("resource", resource.to_string()));
    }
    let resp = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| crate::Error::Provider(format!("refresh client: {e}")))?
        .post(token_endpoint)
        .form(&form)
        .send()
        .map_err(|e| crate::Error::Provider(format!("oauth refresh: {e}")))?;
    let v: Value = resp
        .json()
        .map_err(|e| crate::Error::Provider(format!("oauth refresh body: {e}")))?;
    v.get("access_token")
        .and_then(Value::as_str)
        .map(String::from)
        .ok_or_else(|| crate::Error::Provider(format!("oauth refresh refused: {v}")))
}

// ---------------------------------------------------------------- web search + fetch

/// Search is discovery, not page access. The provider endpoint is hard-coded
/// so neither the model nor manifest caps can turn a search credential into a
/// generic authenticated HTTP client. The optional companion `web_fetch` tool
/// is separately visible in caps as `fetch_public_pages`.
fn bind_web_search(entry: &apiary_core::manifest::Connector) -> Result<WebSearch, crate::Error> {
    let credential = entry.credential.clone().ok_or_else(|| {
        crate::Error::Provider(
            "web-search requires a Brave Search API key sealed as its credential".into(),
        )
    })?;
    let provider = entry
        .caps
        .get("provider")
        .and_then(Value::as_str)
        .unwrap_or("brave");
    if provider != "brave" {
        return Err(crate::Error::Provider(format!(
            "web-search provider '{provider}' is unsupported (supported: brave)"
        )));
    }
    let country = entry
        .caps
        .get("country")
        .and_then(Value::as_str)
        .unwrap_or("US")
        .trim()
        .to_ascii_uppercase();
    if country.len() != 2 || !country.bytes().all(|c| c.is_ascii_uppercase()) {
        return Err(crate::Error::Provider(
            "web-search caps.country must be a two-letter country code".into(),
        ));
    }
    let search_lang = entry
        .caps
        .get("search_lang")
        .and_then(Value::as_str)
        .unwrap_or("en")
        .trim()
        .to_ascii_lowercase();
    if !(2..=5).contains(&search_lang.len())
        || !search_lang
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c == b'-')
    {
        return Err(crate::Error::Provider(
            "web-search caps.search_lang must be a short language code".into(),
        ));
    }
    let safesearch = entry
        .caps
        .get("safesearch")
        .and_then(Value::as_str)
        .unwrap_or("moderate")
        .to_ascii_lowercase();
    if !matches!(safesearch.as_str(), "off" | "moderate" | "strict") {
        return Err(crate::Error::Provider(
            "web-search caps.safesearch must be off, moderate, or strict".into(),
        ));
    }
    Ok(WebSearch {
        credential,
        country,
        search_lang,
        safesearch,
        max_results: entry
            .caps
            .get("max_results")
            .and_then(Value::as_u64)
            .unwrap_or(10)
            .clamp(1, 20) as usize,
    })
}

struct WebSearch {
    credential: apiary_core::manifest::EncryptedBlob,
    country: String,
    search_lang: String,
    safesearch: String,
    max_results: usize,
}

impl Connector for WebSearch {
    fn observes_only(&self) -> bool {
        true
    }

    fn def(&self) -> ToolDef {
        ToolDef {
            name: "web_search".into(),
            description: format!(
                "Search the public web using Brave's independent index and return structured source results. \
                 If web_fetch is granted, use it afterward to read promising sources. Up to {} results per query; \
                 country={}, language={}, SafeSearch={}.",
                self.max_results, self.country, self.search_lang, self.safesearch
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query (maximum 400 characters and 50 words)"
                    },
                    "count": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": self.max_results,
                        "description": "Number of web results to return"
                    },
                    "offset": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 9,
                        "description": "Result page offset for follow-up searches"
                    },
                    "freshness": {
                        "type": "string",
                        "enum": ["pd", "pw", "pm", "py"],
                        "description": "Optional age filter: past day, week, month, or year"
                    }
                },
                "required": ["query"],
                "additionalProperties": false
            }),
        }
    }

    fn execute(
        &self,
        custody: &Custody,
        agent: &AgentHandle,
        args: &Value,
    ) -> Result<String, crate::Error> {
        let query = args
            .get("query")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|q| !q.is_empty())
            .ok_or_else(|| crate::Error::Provider("web_search: query is required".into()))?;
        if query.chars().count() > 400 || query.split_whitespace().count() > 50 {
            return Err(crate::Error::Provider(
                "web_search: query exceeds 400 characters or 50 words".into(),
            ));
        }
        let count = args
            .get("count")
            .and_then(Value::as_u64)
            .unwrap_or(self.max_results as u64) as usize;
        if count == 0 || count > self.max_results {
            return Err(crate::Error::Provider(format!(
                "web_search: count must be between 1 and {}",
                self.max_results
            )));
        }
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        if offset > 9 {
            return Err(crate::Error::Provider(
                "web_search: offset must be between 0 and 9".into(),
            ));
        }
        let freshness = args.get("freshness").and_then(Value::as_str);
        if freshness.is_some_and(|v| !matches!(v, "pd" | "pw" | "pm" | "py")) {
            return Err(crate::Error::Provider(
                "web_search: freshness must be pd, pw, pm, or py".into(),
            ));
        }

        let mut url = reqwest::Url::parse("https://api.search.brave.com/res/v1/web/search")
            .expect("hard-coded Brave endpoint is a valid URL");
        {
            let mut pairs = url.query_pairs_mut();
            pairs
                .append_pair("q", query)
                .append_pair("count", &count.to_string())
                .append_pair("offset", &offset.to_string())
                .append_pair("country", &self.country)
                .append_pair("search_lang", &self.search_lang)
                .append_pair("safesearch", &self.safesearch)
                .append_pair("result_filter", "web")
                .append_pair("text_decorations", "false");
            if let Some(value) = freshness {
                pairs.append_pair("freshness", value);
            }
        }
        let (host, addr) =
            validate_web_url(&url, false, &["api.search.brave.com".to_string()], false)?;
        let token = custody.open(agent, &self.credential)?;
        if token.trim().is_empty() {
            return Err(crate::Error::Provider(
                "web_search: sealed API key is empty".into(),
            ));
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("Apiary/", env!("CARGO_PKG_VERSION")))
            .resolve(&host, addr)
            .build()
            .map_err(|e| crate::Error::Provider(format!("web search client: {e}")))?;
        let mut response = client
            .get(url)
            .header("accept", "application/json")
            .header("x-subscription-token", token.trim())
            .send()
            .map_err(|e| crate::Error::Provider(format!("web search failed: {e}")))?;
        let status = response.status();
        if !status.is_success() {
            let message = match status.as_u16() {
                401 | 403 => "credential was refused",
                429 => "provider rate limit reached",
                _ => "provider request failed",
            };
            return Err(crate::Error::Provider(format!(
                "web_search: {message} (HTTP {})",
                status.as_u16()
            )));
        }
        use std::io::Read;
        const MAX_SEARCH_RESPONSE: usize = 1_048_576;
        let mut bytes = Vec::new();
        response
            .by_ref()
            .take((MAX_SEARCH_RESPONSE + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| crate::Error::Provider(format!("web search response: {e}")))?;
        if bytes.len() > MAX_SEARCH_RESPONSE {
            return Err(crate::Error::Provider(
                "web_search: provider response exceeded 1 MiB".into(),
            ));
        }
        let payload: Value = serde_json::from_slice(&bytes).map_err(|e| {
            crate::Error::Provider(format!("web search returned invalid JSON: {e}"))
        })?;
        Ok(normalize_brave_results(query, offset, count, &payload).to_string())
    }
}

fn bounded_text(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

const MAX_WEB_FETCH_OUTPUT_CHARS: usize = 32_768;

fn compact_web_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len().min(MAX_WEB_FETCH_OUTPUT_CHARS));
    let mut previous_blank = false;
    for line in value.lines() {
        let line = line.trim_end();
        let blank = line.trim().is_empty();
        if blank && previous_blank {
            continue;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(line);
        previous_blank = blank;
    }
    out.trim().to_string()
}

fn readable_web_body(
    content_type: &str,
    bytes: &[u8],
    max_chars: usize,
) -> Result<(String, bool), crate::Error> {
    let raw = if matches!(content_type, "text/html" | "application/xhtml+xml") {
        html2text::from_read(bytes, 100)
            .map_err(|error| crate::Error::Provider(format!("render HTML: {error}")))?
    } else if content_type == "application/json" {
        serde_json::from_slice::<Value>(bytes)
            .map(|value| value.to_string())
            .unwrap_or_else(|_| String::from_utf8_lossy(bytes).into_owned())
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    };
    let compact = compact_web_text(&raw);
    let limit = max_chars.min(MAX_WEB_FETCH_OUTPUT_CHARS);
    let truncated = compact.chars().count() > limit;
    Ok((bounded_text(&compact, limit), truncated))
}

fn normalize_brave_results(query: &str, offset: u64, max_results: usize, payload: &Value) -> Value {
    let results = payload
        .pointer("/web/results")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let url = item.get("url")?.as_str()?;
                    let parsed = reqwest::Url::parse(url).ok()?;
                    if !matches!(parsed.scheme(), "http" | "https") {
                        return None;
                    }
                    let title = item.get("title").and_then(Value::as_str).unwrap_or(url);
                    Some(json!({
                        "title": bounded_text(title, 512),
                        "url": bounded_text(url, 4096),
                        "description": bounded_text(item.get("description").and_then(Value::as_str).unwrap_or(""), 1500),
                        "age": item.get("age").and_then(Value::as_str).map(|age| bounded_text(age, 100)),
                    }))
                })
                .take(max_results)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "provider": "brave",
        "query": query,
        "offset": offset,
        "more_results_available": payload.pointer("/query/more_results_available").and_then(Value::as_bool).unwrap_or(false),
        "results": results,
    })
}

/// A deliberately narrow web reader. The manifest names every permitted
/// domain; DNS is resolved and pinned only after private/special addresses
/// are rejected, and every redirect is checked again. There is no generic
/// request method, arbitrary header, or private-network escape hatch.
fn bind_web_fetch(entry: &apiary_core::manifest::Connector) -> Result<WebFetch, crate::Error> {
    let allow_all_public = entry
        .caps
        .get("allow_all_public")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let domains = entry
        .caps
        .get("allowed_domains")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(|domain| domain.trim().trim_end_matches('.').to_ascii_lowercase())
                .filter(|domain| {
                    !domain.is_empty()
                        && !domain.contains('/')
                        && !domain.contains(':')
                        && domain.len() <= 253
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if domains.is_empty() && !allow_all_public {
        return Err(crate::Error::Provider(
            "web-fetch requires caps.allow_all_public=true or explicit caps.allowed_domains".into(),
        ));
    }
    let max_bytes = entry
        .caps
        .get("max_bytes")
        .and_then(Value::as_u64)
        .unwrap_or(262_144);
    bind_web_fetch_caps(
        allow_all_public,
        domains,
        entry
            .caps
            .get("allow_subdomains")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        max_bytes,
    )
}

fn bind_web_fetch_caps(
    allow_all_public: bool,
    domains: Vec<String>,
    allow_subdomains: bool,
    max_bytes: u64,
) -> Result<WebFetch, crate::Error> {
    Ok(WebFetch {
        domains,
        allow_all_public,
        allow_subdomains,
        max_bytes: max_bytes.clamp(1_024, 2_097_152) as usize,
    })
}

struct WebFetch {
    domains: Vec<String>,
    allow_all_public: bool,
    allow_subdomains: bool,
    max_bytes: usize,
}

impl Connector for WebFetch {
    fn observes_only(&self) -> bool {
        true
    }

    fn def(&self) -> ToolDef {
        let access = if self.allow_all_public {
            "all public HTTPS websites".to_string()
        } else {
            format!("the human-approved domains: {}", self.domains.join(", "))
        };
        ToolDef {
            name: "web_fetch".into(),
            description: format!(
                "Read a text, HTML, JSON, or XML page over HTTPS from {access}. HTML is \
                 converted to compact readable text and model-visible output is bounded. \
                 Private networks, credentials in URLs, unapproved redirects, \
                 binary bodies, and responses above the configured limit are refused.",
            ),
            input_schema: json!({
                "type": "object",
                "properties": {"url": {"type": "string", "description": "full https:// URL"}},
                "required": ["url"],
            }),
        }
    }

    fn execute(
        &self,
        _custody: &Custody,
        _agent: &AgentHandle,
        args: &Value,
    ) -> Result<String, crate::Error> {
        let raw = args
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| crate::Error::Provider("url is required".into()))?;
        let mut url = reqwest::Url::parse(raw)
            .map_err(|e| crate::Error::Provider(format!("invalid URL: {e}")))?;
        for _ in 0..=5 {
            let (host, addr) = validate_web_url(
                &url,
                self.allow_all_public,
                &self.domains,
                self.allow_subdomains,
            )?;
            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(20))
                .redirect(reqwest::redirect::Policy::none())
                .user_agent(concat!("Apiary/", env!("CARGO_PKG_VERSION")))
                .resolve(&host, addr)
                .build()
                .map_err(|e| crate::Error::Provider(format!("web client: {e}")))?;
            let mut response = client
                .get(url.clone())
                .header(
                    "accept",
                    "text/html,text/plain,application/json,application/xml,application/xhtml+xml",
                )
                .send()
                .map_err(|e| crate::Error::Provider(format!("fetch failed: {e}")))?;
            if response.status().is_redirection() {
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| {
                        crate::Error::Provider("redirect had no valid Location".into())
                    })?;
                url = url
                    .join(location)
                    .map_err(|e| crate::Error::Provider(format!("bad redirect: {e}")))?;
                continue;
            }
            let status = response.status();
            if !status.is_success() {
                return Err(crate::Error::Provider(format!(
                    "fetch returned HTTP {}",
                    status.as_u16()
                )));
            }
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("text/plain")
                .split(';')
                .next()
                .unwrap_or("text/plain")
                .trim()
                .to_ascii_lowercase();
            if !is_text_content_type(&content_type) {
                return Err(crate::Error::Provider(format!(
                    "content type '{content_type}' is not readable text"
                )));
            }
            let mut bytes = Vec::new();
            use std::io::Read;
            response
                .by_ref()
                .take((self.max_bytes + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|e| crate::Error::Provider(format!("read response: {e}")))?;
            let truncated = bytes.len() > self.max_bytes;
            bytes.truncate(self.max_bytes);
            let (body, output_truncated) =
                readable_web_body(&content_type, &bytes, self.max_bytes)?;
            return Ok(json!({
                "url": url.as_str(),
                "status": status.as_u16(),
                "content_type": content_type,
                "truncated": truncated || output_truncated,
                "body": body,
            })
            .to_string());
        }
        Err(crate::Error::Provider("too many redirects (max 5)".into()))
    }
}

fn validate_web_url(
    url: &reqwest::Url,
    allow_all_public: bool,
    domains: &[String],
    allow_subdomains: bool,
) -> Result<(String, std::net::SocketAddr), crate::Error> {
    if url.scheme() != "https" {
        return Err(crate::Error::Provider("web-fetch allows HTTPS only".into()));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(crate::Error::Provider(
            "credentials in URLs are refused".into(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| crate::Error::Provider("URL has no hostname".into()))?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if !domain_allowed(&host, allow_all_public, domains, allow_subdomains) {
        return Err(crate::Error::Provider(format!(
            "domain '{host}' is not in the manifest allowlist"
        )));
    }
    let port = url.port_or_known_default().unwrap_or(443);
    use std::net::ToSocketAddrs;
    let addrs = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| crate::Error::Provider(format!("DNS lookup failed: {e}")))?;
    for addr in addrs {
        if public_ip(addr.ip()) {
            return Ok((host, addr));
        }
    }
    Err(crate::Error::Provider(
        "hostname resolves only to private or special-use addresses".into(),
    ))
}

fn domain_allowed(
    host: &str,
    allow_all_public: bool,
    domains: &[String],
    allow_subdomains: bool,
) -> bool {
    allow_all_public
        || domains.iter().any(|configured| {
            let wildcard = configured.strip_prefix("*.");
            let base = wildcard.unwrap_or(configured);
            host == base
                || ((allow_subdomains || wildcard.is_some())
                    && host.len() > base.len()
                    && host.ends_with(base)
                    && host.as_bytes()[host.len() - base.len() - 1] == b'.')
        })
}

fn public_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
                || o[0] == 0
                || o[0] >= 224
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || (o[0] == 192 && o[1] == 0 && (o[2] == 0 || o[2] == 2))
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19 || o[1] == 51))
                || (o[0] == 203 && o[1] == 0 && o[2] == 113))
        }
        std::net::IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4() {
                return public_ip(std::net::IpAddr::V4(v4));
            }
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0x0db8))
        }
    }
}

fn is_text_content_type(value: &str) -> bool {
    value.starts_with("text/")
        || matches!(
            value,
            "application/json"
                | "application/ld+json"
                | "application/xml"
                | "application/xhtml+xml"
                | "application/rss+xml"
                | "application/atom+xml"
        )
        || value.ends_with("+json")
        || value.ends_with("+xml")
}

// ---------------------------------------------------------------- named read-only roots (files + git)

#[derive(Clone)]
struct NamedRoot {
    name: String,
    path: std::path::PathBuf,
}

type NamedRoots = std::sync::Arc<Vec<NamedRoot>>;

fn bind_named_roots(
    entry: &apiary_core::manifest::Connector,
    key: &str,
    label: &str,
    require_git: bool,
) -> Result<NamedRoots, crate::Error> {
    let raw = entry
        .caps
        .get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut roots = Vec::new();
    let mut names = std::collections::HashSet::new();
    for value in raw {
        let name = value
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        let path = value
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        if name.is_empty() || path.is_empty() || !names.insert(name.clone()) {
            return Err(crate::Error::Provider(format!(
                "{label} entries need unique non-empty name and path"
            )));
        }
        let canonical = std::fs::canonicalize(path)
            .map_err(|e| crate::Error::Provider(format!("open {label} '{name}': {e}")))?;
        if !canonical.is_dir() {
            return Err(crate::Error::Provider(format!(
                "{label} '{name}' is not a directory"
            )));
        }
        if require_git && !canonical.join(".git").exists() {
            return Err(crate::Error::Provider(format!(
                "repository '{name}' has no .git directory"
            )));
        }
        roots.push(NamedRoot {
            name,
            path: canonical,
        });
    }
    if roots.is_empty() {
        return Err(crate::Error::Provider(format!(
            "{} connector requires caps.{key}: [{{name, path}}, …]",
            entry.kind
        )));
    }
    Ok(std::sync::Arc::new(roots))
}

fn pick_root<'a>(
    roots: &'a NamedRoots,
    requested: Option<&str>,
) -> Result<&'a NamedRoot, crate::Error> {
    match requested {
        None if roots.len() == 1 => Ok(&roots[0]),
        None => Err(crate::Error::Provider(format!(
            "name one root: {}",
            roots
                .iter()
                .map(|r| r.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
        Some(name) => roots
            .iter()
            .find(|r| r.name == name)
            .ok_or_else(|| crate::Error::Provider(format!("no granted root named '{name}'"))),
    }
}

fn lexical_relative(value: &str, allow_empty: bool) -> Result<std::path::PathBuf, crate::Error> {
    let trimmed = value.trim().trim_matches('/');
    if trimmed.is_empty() && allow_empty {
        return Ok(std::path::PathBuf::new());
    }
    let path = std::path::Path::new(trimmed);
    if path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        return Err(crate::Error::Provider(
            "path must be relative and contain no traversal".into(),
        ));
    }
    Ok(path.to_path_buf())
}

fn resolve_existing(
    root: &NamedRoot,
    relative: &str,
    allow_empty: bool,
) -> Result<std::path::PathBuf, crate::Error> {
    let rel = lexical_relative(relative, allow_empty)?;
    let path = root
        .path
        .join(rel)
        .canonicalize()
        .map_err(|e| crate::Error::Provider(format!("open '{relative}': {e}")))?;
    if !path.starts_with(&root.path) {
        return Err(crate::Error::Provider(format!(
            "'{relative}' escapes root '{}'",
            root.name
        )));
    }
    Ok(path)
}

// ---------------------------------------------------------------- files

fn bind_files(
    entry: &apiary_core::manifest::Connector,
) -> Result<Vec<Box<dyn Connector>>, crate::Error> {
    let roots = bind_named_roots(entry, "roots", "file root", false)?;
    let mut extensions = entry
        .caps
        .get("extensions")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(|v| v.trim().trim_start_matches('.').to_ascii_lowercase())
                .filter(|v| !v.is_empty() && v.chars().all(|c| c.is_ascii_alphanumeric()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if extensions.is_empty() {
        extensions = [
            "txt", "md", "json", "jsonl", "yaml", "yml", "csv", "tsv", "log", "xml", "html", "toml",
        ]
        .into_iter()
        .map(String::from)
        .collect();
    }
    let max_bytes = entry
        .caps
        .get("max_bytes")
        .and_then(Value::as_u64)
        .unwrap_or(262_144)
        .clamp(1_024, 1_048_576) as usize;
    let hidden = entry
        .caps
        .get("include_hidden")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let settings = FileSettings {
        roots,
        extensions: std::sync::Arc::new(extensions),
        max_bytes,
        include_hidden: hidden,
    };
    Ok(vec![
        Box::new(FilesList(settings.clone())),
        Box::new(FilesRead(settings.clone())),
        Box::new(FilesSearch(settings)),
    ])
}

#[derive(Clone)]
struct FileSettings {
    roots: NamedRoots,
    extensions: std::sync::Arc<Vec<String>>,
    max_bytes: usize,
    include_hidden: bool,
}

fn allowed_file(path: &std::path::Path, extensions: &[String]) -> bool {
    path.extension()
        .and_then(|v| v.to_str())
        .map(|v| extensions.iter().any(|e| e.eq_ignore_ascii_case(v)))
        .unwrap_or(false)
}

fn hidden_name(path: &std::path::Path) -> bool {
    path.file_name()
        .and_then(|v| v.to_str())
        .is_some_and(|v| v.starts_with('.'))
}

fn hidden_component(path: &str) -> bool {
    std::path::Path::new(path).components().any(|component| {
        matches!(component, std::path::Component::Normal(name) if name.to_string_lossy().starts_with('.'))
    })
}

struct FilesList(FileSettings);

impl Connector for FilesList {
    fn observes_only(&self) -> bool {
        true
    }

    fn def(&self) -> ToolDef {
        ToolDef {
            name: "files_list".into(),
            description: format!(
                "List files and folders inside the approved roots: {}. Only approved text extensions are shown.",
                self.0.roots.iter().map(|r| r.name.as_str()).collect::<Vec<_>>().join(", ")
            ),
            input_schema: json!({
                "type":"object",
                "properties":{
                    "root":{"type":"string"},
                    "path":{"type":"string","description":"relative folder; omit for root"},
                    "limit":{"type":"integer","minimum":1,"maximum":200}
                }
            }),
        }
    }

    fn execute(&self, _: &Custody, _: &AgentHandle, args: &Value) -> Result<String, crate::Error> {
        let root = pick_root(&self.0.roots, args.get("root").and_then(Value::as_str))?;
        let relative = args.get("path").and_then(Value::as_str).unwrap_or("");
        if !self.0.include_hidden && hidden_component(relative) {
            return Err(crate::Error::Provider(
                "hidden paths are not allowed".into(),
            ));
        }
        let dir = resolve_existing(root, relative, true)?;
        if !dir.is_dir() {
            return Err(crate::Error::Provider("path is not a folder".into()));
        }
        let limit = args
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(100)
            .clamp(1, 200) as usize;
        let mut rows = Vec::new();
        for item in std::fs::read_dir(&dir).map_err(|e| crate::Error::Provider(e.to_string()))? {
            let item = item.map_err(|e| crate::Error::Provider(e.to_string()))?;
            let path = item.path();
            if !self.0.include_hidden && hidden_name(&path) {
                continue;
            }
            let meta = item
                .file_type()
                .map_err(|e| crate::Error::Provider(e.to_string()))?;
            if meta.is_symlink() {
                continue;
            }
            if meta.is_dir() || (meta.is_file() && allowed_file(&path, &self.0.extensions)) {
                let rel = path
                    .strip_prefix(&root.path)
                    .unwrap_or(&path)
                    .to_string_lossy();
                rows.push(json!({"path": rel, "kind": if meta.is_dir() {"folder"} else {"file"}}));
            }
            if rows.len() >= limit {
                break;
            }
        }
        rows.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
        Ok(serde_json::to_string(&rows)?)
    }
}

struct FilesRead(FileSettings);

impl Connector for FilesRead {
    fn observes_only(&self) -> bool {
        true
    }

    fn def(&self) -> ToolDef {
        ToolDef {
            name: "files_read".into(),
            description: "Read one approved text file by root-relative path. Binary files, oversized files, symlink escapes, and unapproved extensions are refused.".into(),
            input_schema: json!({
                "type":"object",
                "properties":{"root":{"type":"string"},"path":{"type":"string"}},
                "required":["path"]
            }),
        }
    }

    fn execute(&self, _: &Custody, _: &AgentHandle, args: &Value) -> Result<String, crate::Error> {
        let root = pick_root(&self.0.roots, args.get("root").and_then(Value::as_str))?;
        let relative = args
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| crate::Error::Provider("path is required".into()))?;
        if !self.0.include_hidden && hidden_component(relative) {
            return Err(crate::Error::Provider(
                "hidden paths are not allowed".into(),
            ));
        }
        let path = resolve_existing(root, relative, false)?;
        if !path.is_file() || !allowed_file(&path, &self.0.extensions) {
            return Err(crate::Error::Provider("file type is not allowed".into()));
        }
        let size = std::fs::metadata(&path)
            .map_err(|e| crate::Error::Provider(e.to_string()))?
            .len() as usize;
        if size > self.0.max_bytes {
            return Err(crate::Error::Provider(format!(
                "file is {size} bytes; limit is {}",
                self.0.max_bytes
            )));
        }
        let mut file =
            std::fs::File::open(&path).map_err(|e| crate::Error::Provider(e.to_string()))?;
        let mut bytes = Vec::with_capacity(size);
        use std::io::Read;
        file.read_to_end(&mut bytes)
            .map_err(|e| crate::Error::Provider(e.to_string()))?;
        let content = String::from_utf8(bytes)
            .map_err(|_| crate::Error::Provider("file is not valid UTF-8 text".into()))?;
        Ok(json!({"root":root.name,"path":relative,"body":content}).to_string())
    }
}

struct FilesSearch(FileSettings);

impl Connector for FilesSearch {
    fn observes_only(&self) -> bool {
        true
    }

    fn def(&self) -> ToolDef {
        ToolDef {
            name: "files_search".into(),
            description: "Search file names and bounded UTF-8 text inside approved roots. Returns at most 50 matches and scans at most 2,000 approved files.".into(),
            input_schema: json!({
                "type":"object",
                "properties":{"root":{"type":"string"},"query":{"type":"string"},"path":{"type":"string"}},
                "required":["query"]
            }),
        }
    }

    fn execute(&self, _: &Custody, _: &AgentHandle, args: &Value) -> Result<String, crate::Error> {
        let root = pick_root(&self.0.roots, args.get("root").and_then(Value::as_str))?;
        let query = args
            .get("query")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|q| !q.is_empty())
            .ok_or_else(|| crate::Error::Provider("query is required".into()))?;
        let relative = args.get("path").and_then(Value::as_str).unwrap_or("");
        if !self.0.include_hidden && hidden_component(relative) {
            return Err(crate::Error::Provider(
                "hidden paths are not allowed".into(),
            ));
        }
        let start = resolve_existing(root, relative, true)?;
        if !start.is_dir() {
            return Err(crate::Error::Provider("search path is not a folder".into()));
        }
        let mut files = Vec::new();
        collect_text_files(&start, &self.0, &mut files, 2_000)?;
        let needle = query.to_lowercase();
        let mut hits = Vec::new();
        for path in files {
            let rel = path
                .strip_prefix(&root.path)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            if rel.to_lowercase().contains(&needle) {
                hits.push(json!({"path":rel,"matched":"name"}));
            } else if std::fs::metadata(&path)
                .map(|m| m.len() as usize <= self.0.max_bytes)
                .unwrap_or(false)
            {
                if let Ok(body) = std::fs::read_to_string(&path) {
                    if let Some(line) = body
                        .lines()
                        .find(|line| line.to_lowercase().contains(&needle))
                    {
                        hits.push(json!({"path":rel,"matched":"content","snippet":line.chars().take(240).collect::<String>()}));
                    }
                }
            }
            if hits.len() >= 50 {
                break;
            }
        }
        Ok(serde_json::to_string(&hits)?)
    }
}

fn collect_text_files(
    dir: &std::path::Path,
    settings: &FileSettings,
    out: &mut Vec<std::path::PathBuf>,
    max: usize,
) -> Result<(), crate::Error> {
    if out.len() >= max {
        return Ok(());
    }
    for item in std::fs::read_dir(dir).map_err(|e| crate::Error::Provider(e.to_string()))? {
        let item = item.map_err(|e| crate::Error::Provider(e.to_string()))?;
        let path = item.path();
        if !settings.include_hidden && hidden_name(&path) {
            continue;
        }
        let kind = item
            .file_type()
            .map_err(|e| crate::Error::Provider(e.to_string()))?;
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            collect_text_files(&path, settings, out, max)?;
        } else if kind.is_file() && allowed_file(&path, &settings.extensions) {
            out.push(path);
        }
        if out.len() >= max {
            break;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- git (read-only)

fn bind_git(
    entry: &apiary_core::manifest::Connector,
) -> Result<Vec<Box<dyn Connector>>, crate::Error> {
    let roots = bind_named_roots(entry, "repos", "repository", true)?;
    Ok([
        GitAction::Status,
        GitAction::Log,
        GitAction::Diff,
        GitAction::Show,
        GitAction::Search,
    ]
    .into_iter()
    .map(|action| {
        Box::new(GitRead {
            roots: roots.clone(),
            action,
        }) as Box<dyn Connector>
    })
    .collect())
}

#[derive(Clone, Copy)]
enum GitAction {
    Status,
    Log,
    Diff,
    Show,
    Search,
}

struct GitRead {
    roots: NamedRoots,
    action: GitAction,
}

impl Connector for GitRead {
    fn observes_only(&self) -> bool {
        true
    }

    fn def(&self) -> ToolDef {
        let repos = self
            .roots
            .iter()
            .map(|r| r.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        match self.action {
            GitAction::Status => ToolDef { name:"git_status".into(), description:format!("Show branch and working-tree status for an approved repository ({repos}). Read-only; hooks and external diff programs are never run."), input_schema:git_schema(false, false) },
            GitAction::Log => ToolDef { name:"git_log".into(), description:format!("Show bounded commit history for an approved repository ({repos})."), input_schema:json!({"type":"object","properties":{"repo":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":100}}}) },
            GitAction::Diff => ToolDef { name:"git_diff".into(), description:format!("Show a bounded, no-external-program diff in an approved repository ({repos})."), input_schema:json!({"type":"object","properties":{"repo":{"type":"string"},"revision":{"type":"string","description":"optional revision or range"},"path":{"type":"string","description":"optional repository-relative path"}}}) },
            GitAction::Show => ToolDef { name:"git_show".into(), description:format!("Show a commit or one file at a revision in an approved repository ({repos})."), input_schema:json!({"type":"object","properties":{"repo":{"type":"string"},"revision":{"type":"string","default":"HEAD"},"path":{"type":"string"}}}) },
            GitAction::Search => ToolDef { name:"git_search".into(), description:format!("Search tracked text in an approved repository ({repos})."), input_schema:json!({"type":"object","properties":{"repo":{"type":"string"},"query":{"type":"string"},"path":{"type":"string"}},"required":["query"]}) },
        }
    }

    fn execute(&self, _: &Custody, _: &AgentHandle, args: &Value) -> Result<String, crate::Error> {
        let repo = pick_root(&self.roots, args.get("repo").and_then(Value::as_str))?;
        let mut command = Vec::<String>::new();
        match self.action {
            GitAction::Status => command.extend(
                ["status", "--short", "--branch", "--untracked-files=normal"].map(String::from),
            ),
            GitAction::Log => {
                let limit = args
                    .get("limit")
                    .and_then(Value::as_u64)
                    .unwrap_or(30)
                    .clamp(1, 100);
                command.extend(
                    [
                        "log",
                        &format!("--max-count={limit}"),
                        "--date=iso-strict",
                        "--pretty=format:%h%x09%ad%x09%an%x09%s",
                    ]
                    .map(String::from),
                );
            }
            GitAction::Diff => {
                command.extend(
                    ["diff", "--no-ext-diff", "--no-textconv", "--unified=3"].map(String::from),
                );
                if let Some(rev) = args.get("revision").and_then(Value::as_str) {
                    command.push(safe_revision(rev)?);
                }
                if let Some(path) = args.get("path").and_then(Value::as_str) {
                    command.push("--".into());
                    command.push(safe_git_path(path)?);
                }
            }
            GitAction::Show => {
                let rev = safe_revision(
                    args.get("revision")
                        .and_then(Value::as_str)
                        .unwrap_or("HEAD"),
                )?;
                command.extend(
                    ["show", "--no-ext-diff", "--no-textconv", "--format=fuller"].map(String::from),
                );
                if let Some(path) = args.get("path").and_then(Value::as_str) {
                    command.push(format!("{rev}:{}", safe_git_path(path)?));
                } else {
                    command.push(rev);
                }
            }
            GitAction::Search => {
                let query = args
                    .get("query")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| crate::Error::Provider("query is required".into()))?;
                if query.len() > 500 {
                    return Err(crate::Error::Provider("query is too long".into()));
                }
                command.extend(["grep", "-n", "-I", "-e", query, "--"].map(String::from));
                if let Some(path) = args.get("path").and_then(Value::as_str) {
                    command.push(safe_git_path(path)?);
                }
            }
        }
        run_git_bounded(repo, &command)
    }
}

fn git_schema(path: bool, revision: bool) -> Value {
    let mut properties = serde_json::Map::new();
    properties.insert("repo".into(), json!({"type":"string"}));
    if path {
        properties.insert("path".into(), json!({"type":"string"}));
    }
    if revision {
        properties.insert("revision".into(), json!({"type":"string"}));
    }
    Value::Object(serde_json::Map::from_iter([
        ("type".into(), json!("object")),
        ("properties".into(), Value::Object(properties)),
    ]))
}

fn safe_revision(value: &str) -> Result<String, crate::Error> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 200
        || value.starts_with('-')
        || value.chars().any(char::is_whitespace)
    {
        return Err(crate::Error::Provider("revision is invalid".into()));
    }
    Ok(value.to_string())
}

fn safe_git_path(value: &str) -> Result<String, crate::Error> {
    Ok(lexical_relative(value, false)?
        .to_string_lossy()
        .to_string())
}

fn run_git_bounded(root: &NamedRoot, args: &[String]) -> Result<String, crate::Error> {
    use std::io::Read;
    let mut child = std::process::Command::new("git");
    child
        .arg("--no-pager")
        .arg("-c")
        .arg("core.pager=cat")
        .arg("-c")
        .arg("diff.external=")
        .arg("-c")
        .arg("core.attributesFile=/dev/null")
        .arg("-C")
        .arg(&root.path)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = child
        .spawn()
        .map_err(|e| crate::Error::Provider(format!("start git: {e}")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| crate::Error::Provider("git stdout unavailable".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| crate::Error::Provider("git stderr unavailable".into()))?;
    let read = |mut pipe: Box<dyn std::io::Read + Send>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = pipe.by_ref().take(524_289).read_to_end(&mut bytes);
            let truncated = bytes.len() > 524_288;
            bytes.truncate(524_288);
            (bytes, truncated)
        })
    };
    let out_thread = read(Box::new(stdout));
    let err_thread = read(Box::new(stderr));
    let status = child
        .wait()
        .map_err(|e| crate::Error::Provider(format!("wait for git: {e}")))?;
    let (stdout, truncated) = out_thread.join().unwrap_or_default();
    let (stderr, _) = err_thread.join().unwrap_or_default();
    if !status.success() && !truncated {
        return Err(crate::Error::Provider(format!(
            "git refused: {}",
            String::from_utf8_lossy(&stderr).trim()
        )));
    }
    let mut text = String::from_utf8_lossy(&stdout).to_string();
    if truncated {
        text.push_str("\n… output truncated at 512 KiB");
    }
    Ok(text)
}

// ---------------------------------------------------------------- vaults

/// Bind an `obsidian` / `markdown-vault` connector: named markdown
/// folders (Obsidian vaults, checked-out KB repos, plain note dirs) as
/// tools. Caps:
///
/// ```yaml
/// - type: markdown-vault          # or obsidian (adds tags/frontmatter/wikilinks)
///   caps:
///     vaults:
///       - {name: kb, path: /Users/me/repos/winery-kb/kb}
///       - {name: notes, path: ~/notes}
///     write: false                # write/append tools exist ONLY when true
/// ```
///
/// Reads are path-jailed to each vault root (traversal and symlink
/// escapes refused). Note content returned to the model is DATA under the
/// provenance rule, like every tool result.
fn bind_vault(
    entry: &apiary_core::manifest::Connector,
    obsidian: bool,
    home: Option<&apiary_core::manifest::KnowledgeHome>,
) -> Result<Vec<Box<dyn Connector>>, crate::Error> {
    let vaults: Vec<(String, std::path::PathBuf)> = entry
        .caps
        .get("vaults")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| {
                    Some((
                        v.get("name")?.as_str()?.to_string(),
                        v.get("path")?.as_str()?.to_string(),
                    ))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
        .into_iter()
        .map(|(name, path)| crate::vault::open_root(&path).map(|root| (name, root)))
        .collect::<Result<_, _>>()?;
    if vaults.is_empty() {
        return Err(crate::Error::Provider(
            "vault connector requires caps.vaults: [{name, path}, …]".into(),
        ));
    }
    let write = entry
        .caps
        .get("write")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let kind = if obsidian { "obsidian" } else { "vault" };
    let vault_names: Vec<String> = vaults.iter().map(|(n, _)| n.clone()).collect();
    let shared = std::sync::Arc::new(vaults);
    let mut out: Vec<Box<dyn Connector>> = vec![
        Box::new(VaultSearch {
            kind,
            obsidian,
            vaults: shared.clone(),
            names: vault_names.clone(),
        }),
        Box::new(VaultRead {
            kind,
            obsidian,
            vaults: shared.clone(),
            names: vault_names.clone(),
        }),
        Box::new(VaultList {
            kind,
            vaults: shared.clone(),
            names: vault_names.clone(),
        }),
    ];
    if write {
        // `remember` only exists when the governor declared a destination
        // AND that destination is one of the vaults this connector can
        // write. No declaration, no durable memory — the agent is not left
        // guessing where its knowledge should go.
        if let Some(home) = home.filter(|h| vault_names.iter().any(|n| *n == h.vault)) {
            out.push(Box::new(RememberNote {
                kind,
                vaults: shared.clone(),
                home: home.clone(),
            }));
        }
        out.push(Box::new(VaultWrite {
            kind,
            vaults: shared,
            names: vault_names,
        }));
    }
    Ok(out)
}

/// `remember` — write something learned into the agent's declared knowledge
/// home.
///
/// Separate from `vault_write` on purpose. Writing a file is a mechanical
/// act; remembering is a claim that will be read later by people and by
/// other agents, so the host decides where it lands and stamps who said it.
/// **Attribution is not optional and the agent cannot suppress it**: without
/// it, nobody reading the knowledge base six months from now can tell a
/// human decision from an agent's inference.
struct RememberNote {
    kind: &'static str,
    vaults: Vaults,
    home: apiary_core::manifest::KnowledgeHome,
}

impl Connector for RememberNote {
    fn def(&self) -> ToolDef {
        ToolDef {
            name: "remember".into(),
            description: format!(
                "Write something you have learned into your knowledge home ({} in the {} \
                 vault), where it survives this run and other people and agents can read \
                 it. Use it for durable, reusable facts and decisions — not for chatter, \
                 and not for what you merely did (that is already in your log). Your name \
                 and the date are recorded automatically. Appends by default, so an \
                 existing note grows rather than being overwritten.",
                self.home
                    .folder
                    .as_deref()
                    .filter(|f| !f.is_empty())
                    .unwrap_or("the root"),
                self.home.vault,
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "short title; the file is named from it"},
                    "note": {"type": "string", "description": "what you learned, in markdown"},
                    "replace": {"type": "boolean", "description": "rewrite the note instead of appending (default false)"},
                },
                "required": ["title", "note"],
            }),
        }
    }

    fn execute(
        &self,
        _custody: &Custody,
        agent: &AgentHandle,
        args: &Value,
    ) -> Result<String, crate::Error> {
        let title = args
            .get("title")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| crate::Error::Provider("title is required".into()))?;
        let note = args
            .get("note")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .ok_or_else(|| crate::Error::Provider("note is required".into()))?;
        let replace = args
            .get("replace")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let root = self
            .vaults
            .iter()
            .find(|(name, _)| *name == self.home.vault)
            .map(|(_, root)| root.clone())
            .ok_or_else(|| {
                crate::Error::Provider(format!(
                    "knowledge home vault '{}' is not available on this host",
                    self.home.vault
                ))
            })?;
        // The HOST picks the path from the title — the agent never chooses
        // where its memory lands.
        let rel = self.home.note_path(title);
        let stamp = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC");
        // Attribution the agent cannot suppress: its own key, not a name
        // it chose for itself.
        let who = agent.pubkey().to_bech32().unwrap_or_else(|_| agent.pubkey().to_hex());
        let entry = format!(
            "\n---\n_Recorded by {who} · {stamp}_\n\n### {title}\n\n{note}\n"
        );
        write_into_vault(&root, &rel, &entry, !replace)?;
        Ok(format!(
            "Remembered in {} ({}). It is attributed to you and dated; anyone with the \
             vault can read, correct, or build on it.",
            rel, self.kind
        ))
    }
}

type Vaults = std::sync::Arc<Vec<(String, std::path::PathBuf)>>;

/// Browse: the shape of a vault (folders with counts, recent notes) or the
/// notes under one folder — so "what's in here?" is answerable without
/// guessing search terms. Bounded output; paths are jailed as always.
struct VaultList {
    kind: &'static str,
    vaults: Vaults,
    names: Vec<String>,
}

impl Connector for VaultList {
    fn observes_only(&self) -> bool {
        true
    }

    fn def(&self) -> ToolDef {
        ToolDef {
            name: format!("{}_list", self.kind),
            description: format!(
                "Browse a granted vault ({}). With no folder: an overview — every folder with its \
                 note count, plus the most recently modified notes. With a folder: the notes in it \
                 (title, path, size, modified). Use this to orient before searching or reading.",
                self.names.join(", ")
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "vault": {"type": "string", "description": "vault name (needed only when several are granted)"},
                    "folder": {"type": "string", "description": "folder path relative to the vault root; omit for the overview"},
                    "limit": {"type": "integer", "description": "max notes to list (default 60, max 200)"}
                }
            }),
        }
    }

    fn execute(
        &self,
        _custody: &Custody,
        _agent: &AgentHandle,
        args: &Value,
    ) -> Result<String, crate::Error> {
        let (vname, root) = vault_root(&self.vaults, args["vault"].as_str())?;
        let limit = args["limit"].as_u64().unwrap_or(60).clamp(1, 200) as usize;
        let notes = crate::vault::walk(root)?;
        let folder = args["folder"]
            .as_str()
            .map(|f| f.trim().trim_matches('/').to_string())
            .filter(|f| !f.is_empty());
        let mut out = String::new();
        match folder {
            None => {
                // Overview: folders with counts, then recent notes.
                let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
                for n in &notes {
                    let dir = match n.rel.rfind('/') {
                        Some(i) => n.rel[..i].to_string(),
                        None => "(root)".to_string(),
                    };
                    *counts.entry(dir).or_default() += 1;
                }
                out.push_str(&format!(
                    "vault '{vname}': {} notes in {} folders\n\nfolders:\n",
                    notes.len(),
                    counts.len()
                ));
                for (dir, c) in counts.iter().take(120) {
                    out.push_str(&format!("  {dir}/  ({c})\n"));
                }
                if counts.len() > 120 {
                    out.push_str(&format!("  … and {} more folders\n", counts.len() - 120));
                }
                let mut recent: Vec<(std::time::SystemTime, &crate::vault::NoteRef)> = notes
                    .iter()
                    .filter_map(|n| {
                        std::fs::metadata(root.join(&n.rel))
                            .and_then(|m| m.modified())
                            .ok()
                            .map(|t| (t, n))
                    })
                    .collect();
                recent.sort_by_key(|(t, _)| std::cmp::Reverse(*t));
                out.push_str("\nrecently modified:\n");
                for (t, n) in recent.iter().take(15) {
                    let secs = t
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    out.push_str(&format!(
                        "  {}  ({}, {})\n",
                        n.rel,
                        n.title,
                        human_age(secs)
                    ));
                }
                out.push_str("\nCall again with a folder to list its notes; use _search for content; _read for a note.");
            }
            Some(f) => {
                let prefix = format!("{f}/");
                let mut listed = 0;
                let mut total = 0;
                for n in &notes {
                    if !(n.rel.starts_with(&prefix) || (f == "(root)" && !n.rel.contains('/'))) {
                        continue;
                    }
                    total += 1;
                    if listed >= limit {
                        continue;
                    }
                    let meta = std::fs::metadata(root.join(&n.rel)).ok();
                    let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                    let age = meta
                        .and_then(|m| m.modified().ok())
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| human_age(d.as_secs()))
                        .unwrap_or_default();
                    out.push_str(&format!("  {}  ({} bytes, {age})\n", n.rel, size));
                    listed += 1;
                }
                if total == 0 {
                    return Ok(format!("no notes under '{f}/' in vault '{vname}' (folders are listed by the overview call)"));
                }
                out = format!(
                    "vault '{vname}', folder '{f}/': {total} notes{}\n",
                    if total > listed {
                        format!(" (showing {listed})")
                    } else {
                        String::new()
                    }
                ) + &out;
            }
        }
        Ok(out)
    }
}

fn human_age(modified_unix: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let d = now.saturating_sub(modified_unix);
    if d < 3600 {
        format!("{}m ago", d / 60)
    } else if d < 86_400 {
        format!("{}h ago", d / 3600)
    } else {
        format!("{}d ago", d / 86_400)
    }
}

fn vault_root<'a>(
    vaults: &'a Vaults,
    name: Option<&str>,
) -> Result<&'a (String, std::path::PathBuf), crate::Error> {
    match name {
        None if vaults.len() == 1 => Ok(&vaults[0]),
        None => Err(crate::Error::Provider(format!(
            "several vaults are granted — name one: {}",
            vaults
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
        Some(n) => vaults.iter().find(|(name, _)| name == n).ok_or_else(|| {
            crate::Error::Provider(format!(
                "no vault named '{n}' (granted: {})",
                vaults
                    .iter()
                    .map(|(n, _)| n.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        }),
    }
}

struct VaultSearch {
    kind: &'static str,
    obsidian: bool,
    vaults: Vaults,
    names: Vec<String>,
}

impl Connector for VaultSearch {
    fn observes_only(&self) -> bool {
        true
    }

    fn def(&self) -> ToolDef {
        ToolDef {
            name: format!("{}_search", self.kind),
            description: format!(
                "Search the granted markdown knowledge vaults ({}) by title{}, and content. \
                 Returns matching notes with paths for {}_read.",
                self.names.join(", "),
                if self.obsidian { ", tags" } else { "" },
                self.kind
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "vault": {"type": "string", "description": "vault name (optional when only one is granted)"},
                },
                "required": ["query"],
            }),
        }
    }

    fn execute(
        &self,
        _custody: &Custody,
        _agent: &AgentHandle,
        args: &Value,
    ) -> Result<String, crate::Error> {
        let query = args
            .get("query")
            .and_then(|v| v.as_str())
            .ok_or_else(|| crate::Error::Provider("query is required".into()))?;
        let named = args.get("vault").and_then(|v| v.as_str());
        let targets: Vec<&(String, std::path::PathBuf)> = match named {
            Some(_) => vec![vault_root(&self.vaults, named)?],
            None => self.vaults.iter().collect(),
        };
        let mut out = Vec::new();
        for (name, root) in targets {
            for hit in crate::vault::search(root, query, self.obsidian, 12)? {
                out.push(json!({
                    "vault": name,
                    "path": hit.rel,
                    "title": hit.title,
                    "matched": hit.matched,
                    "snippet": hit.snippet,
                }));
            }
        }
        if out.is_empty() {
            return Ok(format!("no notes match '{query}'"));
        }
        Ok(serde_json::to_string(&out)?)
    }
}

struct VaultRead {
    kind: &'static str,
    obsidian: bool,
    vaults: Vaults,
    names: Vec<String>,
}

impl Connector for VaultRead {
    fn observes_only(&self) -> bool {
        true
    }

    fn def(&self) -> ToolDef {
        ToolDef {
            name: format!("{}_read", self.kind),
            description: format!(
                "Read one note (by vault-relative path) from the granted vaults ({}).{}",
                self.names.join(", "),
                if self.obsidian {
                    " Returns frontmatter tags and outgoing [[wikilinks]] alongside the body."
                } else {
                    ""
                }
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "vault": {"type": "string", "description": "vault name (optional when only one is granted)"},
                },
                "required": ["path"],
            }),
        }
    }

    fn execute(
        &self,
        _custody: &Custody,
        _agent: &AgentHandle,
        args: &Value,
    ) -> Result<String, crate::Error> {
        let rel = args
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| crate::Error::Provider("path is required".into()))?;
        let (name, root) = vault_root(&self.vaults, args.get("vault").and_then(|v| v.as_str()))?;
        let content = crate::vault::read_note(root, rel)?;
        if self.obsidian {
            let t = crate::vault::tags(&content);
            let links = crate::vault::wikilinks(&content);
            let (_, body) = crate::vault::split_frontmatter(&content);
            Ok(json!({
                "vault": name,
                "path": rel,
                "tags": t,
                "wikilinks": links,
                "body": body,
            })
            .to_string())
        } else {
            Ok(json!({"vault": name, "path": rel, "body": content}).to_string())
        }
    }
}

/// Write into a vault with the full set of ordered defenses. Extracted so
/// every path that writes into a vault gets the same ones — a second copy is
/// a second chance to omit the symlink check.
///
/// Reject absolute paths and traversal LEXICALLY first, verify the deepest
/// EXISTING ancestor canonicalizes into the jail BEFORE creating anything,
/// re-verify the parent after creation, and refuse to write through a
/// symlink.
fn write_into_vault(
    root: &std::path::Path,
    rel: &str,
    content: &str,
    append: bool,
) -> Result<bool, crate::Error> {
    let rel_path = std::path::Path::new(rel);
    if rel_path.is_absolute()
        || !rel.ends_with(".md")
        || rel_path
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        return Err(crate::Error::Provider(
            "path must be a plain vault-relative .md file (no traversal, no absolute paths)"
                .into(),
        ));
    }
    let target = root.join(rel_path);
    let parent = target
        .parent()
        .ok_or_else(|| crate::Error::Provider("bad path".into()))?;
    let mut probe = parent.to_path_buf();
    while !probe.exists() {
        probe = match probe.parent() {
            Some(p) => p.to_path_buf(),
            None => return Err(crate::Error::Provider("bad path".into())),
        };
    }
    let canon_probe = probe
        .canonicalize()
        .map_err(|e| crate::Error::Provider(e.to_string()))?;
    if !canon_probe.starts_with(root) {
        return Err(crate::Error::Provider(format!(
            "'{rel}' escapes the vault — refused"
        )));
    }
    std::fs::create_dir_all(parent).map_err(|e| crate::Error::Provider(e.to_string()))?;
    let canon_parent = parent
        .canonicalize()
        .map_err(|e| crate::Error::Provider(e.to_string()))?;
    if !canon_parent.starts_with(root) {
        return Err(crate::Error::Provider(format!(
            "'{rel}' escapes the vault — refused"
        )));
    }
    let existed = match std::fs::symlink_metadata(&target) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(crate::Error::Provider(format!(
                "'{rel}' is a symlink — refused"
            )))
        }
        Ok(_) => true,
        Err(_) => false,
    };
    use std::io::Write;
    if append && existed {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&target)
            .map_err(|e| crate::Error::Provider(e.to_string()))?;
        writeln!(f, "\n{content}").map_err(|e| crate::Error::Provider(e.to_string()))?;
    } else {
        std::fs::write(&target, content).map_err(|e| crate::Error::Provider(e.to_string()))?;
    }
    Ok(append && existed)
}

struct VaultWrite {
    kind: &'static str,
    vaults: Vaults,
    names: Vec<String>,
}

impl Connector for VaultWrite {
    fn def(&self) -> ToolDef {
        ToolDef {
            name: format!("{}_write", self.kind),
            description: format!(
                "Write or append a markdown note in the granted vaults ({}). \
                 The manifest's write cap authorized this — use it sparingly \
                 and keep humans' notes intact (prefer append).",
                self.names.join(", ")
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "vault-relative path ending in .md"},
                    "content": {"type": "string"},
                    "append": {"type": "boolean", "description": "append instead of overwrite (default true)"},
                    "vault": {"type": "string"},
                },
                "required": ["path", "content"],
            }),
        }
    }

    fn execute(
        &self,
        _custody: &Custody,
        _agent: &AgentHandle,
        args: &Value,
    ) -> Result<String, crate::Error> {
        let rel = args
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| crate::Error::Provider("path is required".into()))?;
        let content = args
            .get("content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| crate::Error::Provider("content is required".into()))?;
        let append = args.get("append").and_then(|v| v.as_bool()).unwrap_or(true);
        let (name, root) = vault_root(&self.vaults, args.get("vault").and_then(|v| v.as_str()))?;
        let appended = write_into_vault(&root, rel, content, append)?;
        let _ = self.kind;
        Ok(json!({"vault": name, "path": rel, "written": true, "appended": appended}).to_string())
    }
}

#[cfg(test)]
mod connector_security_tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "apiary-connector-{name}-{}-{stamp}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn web_domains_are_exact_unless_subdomains_are_explicit() {
        let domains = vec!["example.com".to_string()];
        assert!(domain_allowed("example.com", false, &domains, false));
        assert!(!domain_allowed("www.example.com", false, &domains, false));
        assert!(domain_allowed("www.example.com", false, &domains, true));
        assert!(!domain_allowed("evilexample.com", false, &domains, true));
        assert!(!domain_allowed(
            "example.com.evil.test",
            false,
            &domains,
            true
        ));
        assert!(domain_allowed(
            "docs.example.com",
            false,
            &["*.example.com".to_string()],
            false
        ));
        assert!(domain_allowed("anywhere.example", true, &[], false));
    }

    #[test]
    fn web_fetch_refuses_private_and_special_addresses() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        for ip in [
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(10, 2, 3, 4),
            Ipv4Addr::new(169, 254, 169, 254),
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(192, 0, 2, 5),
        ] {
            assert!(!public_ip(IpAddr::V4(ip)), "{ip} must be refused");
        }
        assert!(public_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!public_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!public_ip(IpAddr::V6("fd00::1".parse().unwrap())));
        assert!(!public_ip(IpAddr::V6("::ffff:127.0.0.1".parse().unwrap())));
        assert!(public_ip(IpAddr::V6(
            "2606:4700:4700::1111".parse().unwrap()
        )));
    }

    #[test]
    fn web_fetch_html_is_readable_and_model_bounded() {
        let html = format!(
            "<html><head><title>Apiary docs</title><script>{}</script></head>\
             <body><main><h1>Codex CLI</h1><p>{}</p></main></body></html>",
            "ignored-script".repeat(10_000),
            "useful documentation ".repeat(10_000)
        );
        let (body, truncated) = readable_web_body("text/html", html.as_bytes(), 4_096).unwrap();
        assert!(body.contains("Codex CLI"));
        assert!(body.contains("useful documentation"));
        assert!(!body.contains("ignored-script"));
        assert!(!body.contains("<main>"));
        assert!(truncated);
        assert!(body.chars().count() <= 4_096);
    }

    #[test]
    fn web_fetch_json_is_minified_and_bounded() {
        let (body, truncated) = readable_web_body(
            "application/json",
            br#"{ "answer": 42, "items": [1, 2, 3] }"#,
            1_024,
        )
        .unwrap();
        assert_eq!(body, r#"{"answer":42,"items":[1,2,3]}"#);
        assert!(!truncated);
    }

    #[test]
    fn local_apiary_mcp_url_follows_host_discovery() {
        let home =
            std::env::temp_dir().join(format!("apiary-mcp-discovery-{}", std::process::id()));
        let agent_dir = home.join("agents/npub1test");
        std::fs::create_dir_all(&agent_dir).unwrap();
        std::fs::write(
            home.join("control.json"),
            r#"{"url":"http://127.0.0.1:43210/mcp","host_id":"test"}"#,
        )
        .unwrap();
        assert_eq!(
            resolve_mcp_url("apiary://local/mcp", Some(&agent_dir)).unwrap(),
            "http://127.0.0.1:43210/mcp"
        );
        assert_eq!(
            resolve_mcp_url("https://example.com/mcp", Some(&agent_dir)).unwrap(),
            "https://example.com/mcp"
        );
        std::fs::remove_dir_all(home).ok();
    }

    #[test]
    fn brave_results_are_reduced_to_grounding_sources() {
        let raw = json!({
            "query": {"more_results_available": true},
            "web": {"results": [
                {"title": "Primary source", "url": "https://example.com/report", "description": "The report", "age": "2 hours ago", "irrelevant": {"large": true}},
                {"title": "Missing URL"},
                {"url": "https://example.org/second"},
                {"title": "Unsafe scheme", "url": "javascript:alert(1)"}
            ]}
        });
        let normalized = normalize_brave_results("test query", 2, 10, &raw);
        assert_eq!(normalized["provider"], "brave");
        assert_eq!(normalized["query"], "test query");
        assert_eq!(normalized["offset"], 2);
        assert_eq!(normalized["more_results_available"], true);
        let results = normalized["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["title"], "Primary source");
        assert_eq!(results[0]["url"], "https://example.com/report");
        assert_eq!(results[1]["title"], "https://example.org/second");
        assert!(results[0].get("irrelevant").is_none());
    }

    #[test]
    fn file_roots_refuse_traversal_and_symlink_escape() {
        let base = scratch("files");
        let root_path = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(&root_path).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(root_path.join("safe.txt"), "safe").unwrap();
        std::fs::write(outside.join("secret.txt"), "secret").unwrap();
        let root = NamedRoot {
            name: "docs".into(),
            path: root_path.canonicalize().unwrap(),
        };
        assert!(resolve_existing(&root, "safe.txt", false).is_ok());
        assert!(resolve_existing(&root, "../outside/secret.txt", false).is_err());
        assert!(hidden_component("private/.config/settings.json"));
        assert!(!hidden_component("public/config/settings.json"));
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, root_path.join("escape")).unwrap();
            assert!(resolve_existing(&root, "escape/secret.txt", false).is_err());
        }
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn git_arguments_are_data_and_output_is_bounded() {
        assert!(safe_revision("--exec=evil").is_err());
        assert!(safe_revision("HEAD main").is_err());
        assert!(safe_git_path("../outside").is_err());

        let base = scratch("git");
        let status = std::process::Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(&base)
            .status()
            .unwrap();
        assert!(status.success());
        std::fs::write(base.join("note.txt"), "hello").unwrap();
        let root = NamedRoot {
            name: "repo".into(),
            path: base.canonicalize().unwrap(),
        };
        let out = run_git_bounded(
            &root,
            &[
                "status".into(),
                "--short".into(),
                "--untracked-files=normal".into(),
            ],
        )
        .unwrap();
        assert!(out.contains("note.txt"));
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn mcp_read_only_fails_closed_on_unmarked_tools() {
        let read = crate::mcp::McpTool {
            name: "read".into(),
            description: String::new(),
            input_schema: json!({"type":"object"}),
            read_only: true,
        };
        let write = crate::mcp::McpTool {
            name: "write".into(),
            description: String::new(),
            input_schema: json!({"type":"object"}),
            read_only: false,
        };
        let no_overrides = std::collections::HashMap::new();
        assert!(mcp_tool_allowed(&read, &[], true, true, &no_overrides));
        assert!(!mcp_tool_allowed(&write, &[], true, true, &no_overrides));
        assert!(mcp_tool_allowed(
            &write,
            &["write".into()],
            false,
            false,
            &no_overrides
        ));

        let granular = std::collections::HashMap::from([
            ("read".to_string(), true),
            ("write".to_string(), false),
        ]);
        assert!(mcp_tool_allowed(&read, &[], false, false, &granular));
        assert!(mcp_tool_allowed(&write, &[], false, false, &granular));
        let unsafe_read = std::collections::HashMap::from([("write".to_string(), true)]);
        assert!(!mcp_tool_allowed(&write, &[], false, false, &unsafe_read));
    }

    /// "Did anything happen?" must fail closed: a connector that has not
    /// declared itself an observer counts as acting, so a proactive run
    /// can never be recorded as quiet because someone forgot to answer.
    #[test]
    fn observes_only_defaults_to_acting() {
        struct Undeclared;
        impl Connector for Undeclared {
            fn def(&self) -> ToolDef {
                ToolDef {
                    name: "undeclared".into(),
                    description: String::new(),
                    input_schema: serde_json::json!({"type": "object"}),
                }
            }
            fn execute(
                &self,
                _c: &Custody,
                _a: &AgentHandle,
                _args: &Value,
            ) -> Result<String, crate::Error> {
                Ok(String::new())
            }
        }
        assert!(!Undeclared.observes_only());
        assert!(!MockEcho.observes_only());
    }
}
