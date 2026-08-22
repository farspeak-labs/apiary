//! The rest of the host surface: status/unlock, key tool, spend meter,
//! log publication, credential custody, Buzz membership operations, and
//! managed mention listeners. Everything the CLI can do, the GUI can do —
//! same governance gates, same log entries (SPEC §2: the GUI is a client).

use crate::{agent_ctx, err, load_manifest, nip98, suspend_pks, App, AppState};
use apiary_core::{ceremony, custody::Custody, keystore::Keystore, log::EpisodicLog};
use axum::{
    extract::{OriginalUri, Path as AxPath, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use nostr::prelude::*;
use serde_json::json;
use sha2::Digest;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

type Resp = (StatusCode, Json<serde_json::Value>);

fn persist_manifest(dir: &std::path::Path, expected_raw: &str, yaml: &str) -> Result<String, Resp> {
    // Never write a manifest the host cannot load back: a bad amendment
    // must fail HERE, in the amender's face, not at the next mention (or
    // worse, silently stop the agent when from_yaml rejects it later).
    if let Err(e) = apiary_core::manifest::Manifest::from_yaml(yaml) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            format!("this amendment would make the manifest invalid: {e}"),
        ));
    }
    crate::agent_store::replace_manifest(dir, expected_raw, yaml).map_err(|error| match error {
        crate::agent_store::StoreError::Conflict { current_revision } => (
            StatusCode::CONFLICT,
            Json(json!({
                "ok": false,
                "error": "the agent changed while this amendment was being prepared; reload and try again",
                "code": "manifest_revision_conflict",
                "current_revision": current_revision,
            })),
        ),
        crate::agent_store::StoreError::Io(error) => {
            err(StatusCode::INTERNAL_SERVER_ERROR, error)
        }
    })
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn push_line(lines: &Mutex<VecDeque<String>>, line: String) {
    if let Ok(mut q) = lines.lock() {
        if q.len() >= 300 {
            q.pop_front();
        }
        q.push_back(format!("[{}] {line}", now_secs()));
    }
}

#[derive(serde::Deserialize)]
pub struct AuditQuery {
    #[serde(default = "default_audit_tail")]
    tail: usize,
}

fn default_audit_tail() -> usize {
    100
}

/// Host-manager view of the local, hash-chained MCP management audit. Bodies
/// and credentials are never recorded; mutating calls carry only a body hash.
pub async fn control_audit_get(
    State(state): State<App>,
    OriginalUri(uri): OriginalUri,
    Query(query): Query<AuditQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(error) = check_admin(&state, &headers, "GET", &uri, None) {
        return error.into_response();
    }
    let path = state.home.join("control-audit.jsonl");
    let lines = std::fs::read_to_string(path).unwrap_or_default();
    let mut parsed = Vec::new();
    let mut chain_error = None;
    for (index, line) in lines.lines().enumerate() {
        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(entry) => parsed.push(entry),
            Err(error) => {
                chain_error = Some(format!("entry {index} is invalid JSON: {error}"));
                break;
            }
        }
    }
    let mut previous: Option<String> = None;
    for (index, entry) in parsed.iter().enumerate() {
        if chain_error.is_some() {
            break;
        }
        let stored_previous = entry.get("prev").and_then(|value| value.as_str());
        if stored_previous != previous.as_deref() {
            chain_error = Some(format!("entry {index} has a broken previous-hash link"));
            break;
        }
        let stored_hash = entry.get("hash").and_then(|value| value.as_str());
        let mut unsigned = entry.clone();
        if let Some(object) = unsigned.as_object_mut() {
            object.remove("hash");
        }
        let computed = format!(
            "{:x}",
            sha2::Sha256::digest(unsigned.to_string().as_bytes())
        );
        if stored_hash != Some(computed.as_str()) {
            chain_error = Some(format!("entry {index} has an invalid hash"));
            break;
        }
        previous = Some(computed);
    }
    let total = parsed.len();
    let entries = parsed
        .into_iter()
        .rev()
        .take(query.tail.clamp(1, 1000))
        .collect::<Vec<_>>();
    Json(json!({
        "ok": true,
        "chain": {"valid": chain_error.is_none(), "entries": total, "error": chain_error},
        "entries": entries,
    }))
    .into_response()
}

pub async fn control_tokens_all_get(
    State(state): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(error) = check_admin(&state, &headers, "GET", &uri, None) {
        return error.into_response();
    }
    match nip98::list_all_control_tokens(&state) {
        Ok(tokens) => {
            let now = now_secs();
            let tokens = tokens
                .into_iter()
                .map(|token| {
                    json!({
                        "id": token.id,
                        "agent": token.agent,
                        "label": token.label,
                        "created_at": token.created_at,
                        "expires_at": token.expires_at,
                        "revoked_at": token.revoked_at,
                        "active": token.revoked_at.is_none() && token.expires_at > now,
                    })
                })
                .collect::<Vec<_>>();
            Json(json!({"ok": true, "tokens": tokens})).into_response()
        }
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, error).into_response(),
    }
}

/// The common request gate: token/NIP-98 check, agent resolution, manifest
/// load, role authorization. Every per-agent endpoint goes through this.
#[allow(clippy::type_complexity)]
fn gate(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    method: &str,
    uri: &axum::http::Uri,
    body: Option<&[u8]>,
    npub: &str,
) -> Result<
    (
        Keystore,
        String,
        std::path::PathBuf,
        String,
        apiary_core::manifest::Manifest,
    ),
    Resp,
> {
    let pq = uri
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| uri.path().to_string());
    let signer = nip98::check(state, headers, method, &pq, body)?;
    let (ks, npub, dir) = agent_ctx(state, npub)?;
    let (raw, manifest) = load_manifest(&dir)?;
    nip98::authorize_agent_request(state, signer, &manifest, method, &pq)?;
    let path = uri.path();
    let deleting_agent = method == "DELETE"
        && path
            .strip_prefix("/api/agents/")
            .is_some_and(|tail| !tail.contains('/'));
    if is_archived(&dir) && method != "GET" && !path.ends_with("/archive") && !deleting_agent {
        return Err(err(
            StatusCode::CONFLICT,
            "agent is archived — restore it before changing or running it",
        ));
    }
    Ok((ks, npub, dir, raw, manifest))
}

/// Crate-visible gate for sibling modules (routines).
pub(crate) fn gate_pub(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    method: &str,
    uri: &axum::http::Uri,
    body: Option<&[u8]>,
    npub: &str,
) -> Result<
    (
        Keystore,
        String,
        std::path::PathBuf,
        String,
        apiary_core::manifest::Manifest,
    ),
    Resp,
> {
    gate(state, headers, method, uri, body, npub)
}

fn require_pass(state: &AppState) -> Result<String, Resp> {
    state.passphrase_clone().ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "keystore is locked — unlock with the passphrase first",
        )
    })
}

fn check_admin(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    method: &str,
    uri: &axum::http::Uri,
    body: Option<&[u8]>,
) -> Result<(), Resp> {
    let pq = uri
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| uri.path().to_string());
    let signer = nip98::check(state, headers, method, &pq, body)?;
    nip98::authorize_admin(state, signer)
}

fn write_private(path: &std::path::Path, content: &str) -> Result<(), std::io::Error> {
    std::fs::write(path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn admit(
    ks: &Keystore,
    npub: &str,
    pass: &str,
) -> Result<(Custody, apiary_core::custody::AgentHandle), Resp> {
    let keys = ks
        .load(npub, pass)
        .map_err(|e| err(StatusCode::UNAUTHORIZED, e))?;
    let mut custody = Custody::new();
    let handle = custody.admit(keys);
    Ok((custody, handle))
}

// ---------------------------------------------------------------- status

/// Exchange one fresh NIP-98 signature for an in-memory browser session.
/// The cookie is HttpOnly and the returned request token is required in a
/// custom header, so same-site form posts cannot exercise the session.
pub async fn browser_session_create(
    State(state): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    let signed = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("Nostr "));
    if state.auth != crate::AuthMode::Nip98 || !signed {
        return err(
            StatusCode::UNAUTHORIZED,
            "a fresh NIP-98 signature is required to open a browser session",
        )
        .into_response();
    }
    let pq = uri
        .path_and_query()
        .map(|path| path.to_string())
        .unwrap_or_else(|| uri.path().to_string());
    let signer = match nip98::check(&state, &headers, "POST", &pq, None) {
        Ok(Some(signer)) => signer,
        Ok(None) => {
            return err(StatusCode::UNAUTHORIZED, "NIP-98 signer is missing").into_response()
        }
        Err(error) => return error.into_response(),
    };
    // Do not issue a reusable browser session to an arbitrary valid Nostr
    // identity. Host managers and people assigned to at least one agent may
    // enter; individual routes still enforce their narrower role.
    if let Err(error) = nip98::authorize_cockpit(&state, Some(signer)) {
        return error.into_response();
    }
    let secure = state.origin.starts_with("https://");
    browser_session_response(&state, signer, secure)
}

#[derive(Default, serde::Deserialize)]
pub struct DesktopSessionRequest {
    manager: Option<String>,
}

/// Exchange the daemon's per-process desktop credential for the same
/// manager-bound session created by NIP-98. The credential is only published
/// in a 0600 file and is retrieved after SSH has authenticated the desktop.
/// It is never a general API bearer token.
pub async fn desktop_session_create(
    State(state): State<App>,
    headers: axum::http::HeaderMap,
    Json(body): Json<DesktopSessionRequest>,
) -> axum::response::Response {
    if state.auth != crate::AuthMode::Nip98 {
        return err(
            StatusCode::BAD_REQUEST,
            "desktop session exchange is only used in NIP-98 mode",
        )
        .into_response();
    }
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default();
    let expected = state.desktop_token.as_deref().unwrap_or_default();
    if expected.is_empty() || !nip98::constant_time_eq(presented, expected) {
        return err(StatusCode::UNAUTHORIZED, "desktop credential was refused").into_response();
    }

    let managers = match state.managers.read() {
        Ok(managers) => managers,
        Err(_) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "manager registry unavailable",
            )
            .into_response()
        }
    };
    let views = managers.views();
    let selected = match body.manager.as_deref() {
        Some(npub) => views.iter().find(|manager| manager.npub == npub),
        None if views.len() == 1 => views.first(),
        None => {
            return (
                StatusCode::CONFLICT,
                Json(json!({
                    "ok": false,
                    "error": "choose the approved manager identity for this desktop session",
                    "managers": views,
                })),
            )
                .into_response()
        }
    };
    let Some(selected) = selected else {
        return err(StatusCode::FORBIDDEN, "that identity is not a host manager").into_response();
    };
    let signer = match apiary_core::identity::parse_npub(&selected.npub) {
        Ok(signer) => signer,
        Err(error) => return err(StatusCode::INTERNAL_SERVER_ERROR, error).into_response(),
    };
    drop(managers);

    // This cookie is deliberately not Secure: this endpoint is consumed over
    // the SSH-forwarded loopback origin (http://127.0.0.1). The unpredictable
    // bearer above is still required, and the resulting cookie remains
    // HttpOnly, SameSite=Strict, manager-bound, and CSRF-bound.
    browser_session_response(&state, signer, false)
}

pub(crate) fn browser_session_response(
    state: &AppState,
    signer: PublicKey,
    secure_cookie: bool,
) -> axum::response::Response {
    let session = match nip98::issue_browser_session(state, signer) {
        Ok(session) => session,
        Err(error) => return err(StatusCode::INTERNAL_SERVER_ERROR, error).into_response(),
    };
    let npub = match apiary_core::identity::to_npub(&signer) {
        Ok(npub) => npub,
        Err(error) => return err(StatusCode::INTERNAL_SERVER_ERROR, error).into_response(),
    };
    let secure = if secure_cookie { "; Secure" } else { "" };
    let cookie = format!(
        "apiary_session={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
        session.token,
        session.expires_at.saturating_sub(now_secs()),
        secure,
    );
    let mut response = Json(json!({
        "ok": true,
        "npub": npub,
        "csrf": session.csrf,
        "expires_at": session.expires_at,
    }))
    .into_response();
    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        cookie.parse().expect("session cookie is valid"),
    );
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

/// Explicitly revoke the current browser session and expire its cookie.
pub async fn browser_session_delete(
    State(state): State<App>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    if state.auth != crate::AuthMode::Nip98 {
        return err(
            StatusCode::BAD_REQUEST,
            "browser sessions are only used in NIP-98 mode",
        )
        .into_response();
    }
    let signer = match nip98::revoke_browser_session(&state, &headers) {
        Ok(signer) => signer,
        Err(error) => return error.into_response(),
    };
    // NIP-46 client keys are disposable session material. Logging out drops
    // the connection rather than silently retaining signing authority.
    if let Ok(mut signers) = state.remote_signers.lock() {
        signers.remove(&signer.to_hex());
    }
    let secure = if state.origin.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "apiary_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{}",
        secure,
    );
    let mut response = Json(json!({ "ok": true })).into_response();
    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        cookie.parse().expect("expired session cookie is valid"),
    );
    response
}

pub async fn status(
    State(state): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let pq = uri
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| uri.path().to_string());
    let signer = match nip98::check(&state, &headers, "GET", &pq, None) {
        Ok(signer) => signer,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = nip98::authorize_cockpit(&state, signer) {
        return error.into_response();
    }
    let unlocked = state
        .passphrase
        .read()
        .map(|g| g.is_some())
        .unwrap_or(false);
    let (agents, owners) = Keystore::open(&state.home)
        .and_then(|ks| {
            let slots = ks.list()?;
            let agents = slots
                .iter()
                .filter(|npub| ks.agent_dir(npub).join("manifest.yaml").exists())
                .count();
            let owners = slots
                .iter()
                .filter(|npub| {
                    std::fs::read_to_string(ks.agent_dir(npub).join("principal.kind"))
                        .is_ok_and(|kind| kind.trim() == "owner")
                })
                .count();
            Ok((agents, owners))
        })
        .unwrap_or((0, 0));
    let listeners: Vec<serde_json::Value> = state
        .listeners
        .lock()
        .map(|m| {
            m.iter()
                .map(|(npub, p)| {
                    let running: Vec<&String> = p
                        .channels
                        .iter()
                        .filter(|(_, c)| !c.done.load(Ordering::Relaxed))
                        .map(|(k, _)| k)
                        .collect();
                    json!({
                        "npub": npub,
                        "channels": running,
                        "running": !running.is_empty(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Json(json!({
        "ok": true,
        "version": env!("CARGO_PKG_VERSION"),
        "home": state.home.display().to_string(),
        "origin": state.origin,
        "auth": match state.auth { crate::AuthMode::Open => "open", crate::AuthMode::Nip98 => "nip98" },
        "token_gated": state.token.is_some(),
        "unlocked": unlocked,
        "automatic_unlock": state.automatic_unlock.load(Ordering::Relaxed),
        "can_remember_unlock": state.remember_passphrase.is_some(),
        "can_forget_unlock": state.forget_passphrase.is_some(),
        "agents": agents,
        "owners": owners,
        "managers": state.managers.read().map(|registry| registry.len()).unwrap_or(0),
        "listeners": listeners,
        "anthropic_key_present": nonempty_env("ANTHROPIC_API_KEY")
            || nonempty_env("ANTHROPIC_AUTH_TOKEN"),
        "relay_pool": apiary_runtime::relay::stats(),
    }))
    .into_response()
}

// ---------------------------------------------------------- host managers

#[derive(serde::Deserialize)]
pub struct ManagerBody {
    name: String,
    npub: String,
}

/// List public Nostr identities with full host-scoped authority. Private keys
/// are never accepted here; each person signs through their own Nostr signer.
pub async fn managers_get(
    State(state): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = check_admin(&state, &headers, "GET", &uri, None) {
        return e.into_response();
    }
    match state.managers.read() {
        Ok(registry) => Json(json!({"ok": true, "managers": registry.views()})).into_response(),
        Err(_) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "host manager registry is unavailable",
        )
        .into_response(),
    }
}

/// Add a manager or update their local display name. Every manager has equal,
/// independent host authority; this is deliberately not a role hierarchy.
pub async fn managers_upsert(
    State(state): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    if let Err(e) = check_admin(&state, &headers, "POST", &uri, Some(&raw_body)) {
        return e.into_response();
    }
    let body: ManagerBody = match serde_json::from_slice(&raw_body) {
        Ok(body) => body,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    if let Err(error) = crate::access::validate_name(&body.name) {
        return err(StatusCode::BAD_REQUEST, error).into_response();
    }
    let key = match apiary_core::identity::parse_npub(body.npub.trim()) {
        Ok(key) => key,
        Err(error) => return err(StatusCode::BAD_REQUEST, error).into_response(),
    };
    let canonical = match apiary_core::identity::to_npub(&key) {
        Ok(npub) => npub,
        Err(error) => return err(StatusCode::BAD_REQUEST, error).into_response(),
    };
    let mut registry = match state.managers.write() {
        Ok(registry) => registry,
        Err(_) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "host manager registry is unavailable",
            )
            .into_response()
        }
    };
    if let Err(error) = registry.upsert(key, body.name.trim().to_string()) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, error).into_response();
    }
    Json(json!({"ok": true, "npub": canonical, "managers": registry.views()})).into_response()
}

pub async fn managers_remove(
    State(state): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    AxPath(npub): AxPath<String>,
) -> impl IntoResponse {
    if let Err(e) = check_admin(&state, &headers, "DELETE", &uri, None) {
        return e.into_response();
    }
    let key = match apiary_core::identity::parse_npub(&npub) {
        Ok(key) => key,
        Err(error) => return err(StatusCode::BAD_REQUEST, error).into_response(),
    };
    let mut registry = match state.managers.write() {
        Ok(registry) => registry,
        Err(_) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "host manager registry is unavailable",
            )
            .into_response()
        }
    };
    match registry.remove(&key) {
        Ok(crate::access::RemoveOutcome::Removed) => {
            Json(json!({"ok": true, "managers": registry.views()})).into_response()
        }
        Ok(crate::access::RemoveOutcome::NotFound) => {
            err(StatusCode::NOT_FOUND, "host manager was not found").into_response()
        }
        Ok(crate::access::RemoveOutcome::StartupManager) => err(
            StatusCode::CONFLICT,
            "this manager came from --admin; restart without that flag before removing them",
        )
        .into_response(),
        Ok(crate::access::RemoveOutcome::LastManager) => err(
            StatusCode::CONFLICT,
            "the last host manager cannot be removed; add a replacement first",
        )
        .into_response(),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, error).into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct GovernorsBody {
    #[serde(default)]
    npubs: Vec<String>,
    #[serde(default)]
    managers: Vec<apiary_core::manifest::ManagerGrant>,
}

/// Replace an agent's manager roles. The legacy `npubs` shape remains accepted
/// and treats every listed identity as a governor. Authorization is checked
/// against the current manifest before the inert amendment is written.
pub async fn governors_set(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (_ks, npub, dir, raw, mut manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(value) => value,
            Err(error) => return error.into_response(),
        };
    let body: GovernorsBody = match serde_json::from_slice(&raw_body) {
        Ok(body) => body,
        Err(error) => return err(StatusCode::BAD_REQUEST, error).into_response(),
    };
    if !body.npubs.is_empty() && !body.managers.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "send either legacy npubs or role-bearing managers, not both",
        )
        .into_response();
    }
    let requested = if body.managers.is_empty() {
        body.npubs
            .into_iter()
            .map(|npub| apiary_core::manifest::ManagerGrant {
                npub,
                role: apiary_core::manifest::ManagerRole::Governor,
            })
            .collect::<Vec<_>>()
    } else {
        body.managers
    };
    if requested.is_empty()
        || !requested
            .iter()
            .any(|manager| manager.role == apiary_core::manifest::ManagerRole::Governor)
    {
        return err(
            StatusCode::BAD_REQUEST,
            "at least one agent governor is required",
        )
        .into_response();
    }
    let mut seen = std::collections::HashSet::new();
    let mut normalized = Vec::new();
    for manager in requested {
        let key = match apiary_core::identity::parse_npub(manager.npub.trim()) {
            Ok(key) => key,
            Err(error) => return err(StatusCode::BAD_REQUEST, error).into_response(),
        };
        if !seen.insert(key) {
            return err(StatusCode::BAD_REQUEST, "duplicate agent manager identity")
                .into_response();
        }
        let npub = match apiary_core::identity::to_npub(&key) {
            Ok(npub) => npub,
            Err(error) => return err(StatusCode::BAD_REQUEST, error).into_response(),
        };
        normalized.push(apiary_core::manifest::ManagerGrant {
            npub,
            role: manager.role,
        });
    }
    manifest.governance.suspend_keys = normalized
        .iter()
        .filter(|manager| manager.role == apiary_core::manifest::ManagerRole::Governor)
        .map(|manager| manager.npub.clone())
        .collect();
    manifest.governance.managers = normalized
        .iter()
        .filter(|manager| manager.role != apiary_core::manifest::ManagerRole::Governor)
        .cloned()
        .collect();
    if let Err(error) = manifest.validate() {
        return err(StatusCode::BAD_REQUEST, error).into_response();
    }
    let yaml = match manifest.to_yaml() {
        Ok(yaml) => yaml,
        Err(error) => return err(StatusCode::INTERNAL_SERVER_ERROR, error).into_response(),
    };
    if let Err(error) = persist_manifest(&dir, &raw, &yaml) {
        return error.into_response();
    }
    Json(json!({
        "ok": true,
        "npub": npub,
        "managers": normalized,
        "manifest_sha256": ceremony::manifest_hash(&yaml),
        "ratified": false,
        "note": "agent managers changed — the agent is paused until one of the newly listed governors ratifies",
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
pub struct ConstitutionBody {
    #[serde(default)]
    purpose: String,
    #[serde(default)]
    role: String,
    #[serde(default)]
    voice: String,
    #[serde(default)]
    principles: Vec<String>,
    #[serde(default)]
    boundaries: Vec<String>,
}

/// Replace the agent's ratified operating character. This changes only how
/// the agent should behave; it cannot add tools or loosen connector caps.
pub async fn constitution_set(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (_ks, npub, dir, raw, mut manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(value) => value,
            Err(error) => return error.into_response(),
        };
    let body: ConstitutionBody = match serde_json::from_slice(&raw_body) {
        Ok(body) => body,
        Err(error) => return err(StatusCode::BAD_REQUEST, error).into_response(),
    };
    let clean_list = |items: Vec<String>| {
        items
            .into_iter()
            .map(|item| item.trim().to_string())
            .filter(|item| !item.is_empty())
            .collect()
    };
    manifest.constitution = apiary_core::manifest::Constitution {
        purpose: body.purpose.trim().to_string(),
        role: body.role.trim().to_string(),
        voice: body.voice.trim().to_string(),
        principles: clean_list(body.principles),
        boundaries: clean_list(body.boundaries),
    };
    let yaml = match manifest.to_yaml() {
        Ok(yaml) => yaml,
        Err(error) => return err(StatusCode::INTERNAL_SERVER_ERROR, error).into_response(),
    };
    if let Err(error) = persist_manifest(&dir, &raw, &yaml) {
        return error.into_response();
    }
    Json(json!({
        "ok": true,
        "npub": npub,
        "constitution": manifest.constitution,
        "manifest_sha256": ceremony::manifest_hash(&yaml),
        "ratified": false,
        "note": "role and personality changed — review and approve before the agent runs",
    }))
    .into_response()
}

/// Return the SKILL.md interchange form plus requirement status. Skill bodies
/// are safe to return to governors; credentials remain in separate sealed
/// connector fields and never appear here.
pub async fn skills_get(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (_ks, _npub, _dir, _raw, manifest) = match gate(&state, &headers, "GET", &uri, None, &npub)
    {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let skills = manifest
        .skills
        .iter()
        .map(|skill| {
            let missing: Vec<&String> = skill
                .requires_connectors
                .iter()
                .filter(|required| {
                    !manifest
                        .connectors
                        .iter()
                        .any(|connector| connector.kind.as_str() == required.as_str())
                })
                .collect();
            json!({
                "name": skill.name,
                "description": skill.description,
                "markdown": skill.to_markdown().unwrap_or_default(),
                "requires_connectors": skill.requires_connectors,
                "available": missing.is_empty(),
                "missing_connectors": missing,
            })
        })
        .collect::<Vec<_>>();
    Json(json!({"ok": true, "skills": skills})).into_response()
}

#[derive(serde::Deserialize)]
pub struct SkillBody {
    markdown: String,
    #[serde(default)]
    requires_connectors: Vec<String>,
    #[serde(default)]
    original_name: Option<String>,
}

/// Import or update one SKILL.md. The parsed body is embedded in the
/// manifest, so approval covers the exact instructions and exports remain
/// self-contained. Connector requirements are checks, never grants.
pub async fn skill_upsert(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (_ks, npub, dir, raw, mut manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(value) => value,
            Err(error) => return error.into_response(),
        };
    let body: SkillBody = match serde_json::from_slice(&raw_body) {
        Ok(body) => body,
        Err(error) => return err(StatusCode::BAD_REQUEST, error).into_response(),
    };
    let skill =
        match apiary_core::manifest::Skill::from_markdown(&body.markdown, body.requires_connectors)
        {
            Ok(skill) => skill,
            Err(error) => return err(StatusCode::BAD_REQUEST, error).into_response(),
        };
    let original = body.original_name.as_deref().unwrap_or(&skill.name);
    if original != skill.name
        && manifest
            .skills
            .iter()
            .any(|existing| existing.name == skill.name)
    {
        return err(
            StatusCode::CONFLICT,
            format!("a skill named '{}' already exists", skill.name),
        )
        .into_response();
    }
    manifest.skills.retain(|existing| existing.name != original);
    manifest.skills.push(skill.clone());
    manifest
        .skills
        .sort_by(|left, right| left.name.cmp(&right.name));
    if let Err(error) = manifest.validate() {
        return err(StatusCode::BAD_REQUEST, error).into_response();
    }
    let yaml = match manifest.to_yaml() {
        Ok(yaml) => yaml,
        Err(error) => return err(StatusCode::INTERNAL_SERVER_ERROR, error).into_response(),
    };
    if let Err(error) = persist_manifest(&dir, &raw, &yaml) {
        return error.into_response();
    }
    Json(json!({
        "ok": true,
        "npub": npub,
        "skill": skill.name,
        "manifest_sha256": ceremony::manifest_hash(&yaml),
        "ratified": false,
        "note": "skill saved — review its instructions and approve the amendment before the agent runs",
    }))
    .into_response()
}

pub async fn skill_delete(
    State(state): State<App>,
    AxPath((npub, name)): AxPath<(String, String)>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (_ks, npub, dir, raw, mut manifest) =
        match gate(&state, &headers, "DELETE", &uri, None, &npub) {
            Ok(value) => value,
            Err(error) => return error.into_response(),
        };
    let before = manifest.skills.len();
    manifest.skills.retain(|skill| skill.name != name);
    if manifest.skills.len() == before {
        return err(StatusCode::NOT_FOUND, format!("no skill named '{name}'")).into_response();
    }
    let yaml = match manifest.to_yaml() {
        Ok(yaml) => yaml,
        Err(error) => return err(StatusCode::INTERNAL_SERVER_ERROR, error).into_response(),
    };
    if let Err(error) = persist_manifest(&dir, &raw, &yaml) {
        return error.into_response();
    }
    Json(json!({
        "ok": true,
        "npub": npub,
        "removed": name,
        "manifest_sha256": ceremony::manifest_hash(&yaml),
        "ratified": false,
        "note": "skill removed — review and approve the amendment before the agent runs",
    }))
    .into_response()
}

// ----------------------------------------------------------- harness policy

pub async fn harnesses_get(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (_ks, _npub, _dir, _raw, manifest) = match gate(&state, &headers, "GET", &uri, None, &npub)
    {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    Json(json!({"ok": true, "harnesses": manifest.harnesses})).into_response()
}

#[derive(serde::Serialize)]
struct DiscoveredHarness {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    command: String,
    args: Vec<&'static str>,
    source: &'static str,
}

fn executable(path: &std::path::Path) -> bool {
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.metadata()
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    true
}

fn discover_acp_harnesses_from(
    berd_paths: &[std::path::PathBuf],
    search_path: Option<&std::ffi::OsStr>,
) -> Vec<DiscoveredHarness> {
    let mut found = Vec::new();
    let mut seen = std::collections::BTreeSet::new();

    for path in berd_paths {
        if executable(path) && seen.insert(path.clone()) {
            found.push(DiscoveredHarness {
                id: "berd-goose",
                name: "Berd's Goose harness",
                description: "Berd's bundled Goose ACP loop; Apiary still governs its profile, tools, sandbox, and accounting.",
                command: path.to_string_lossy().into_owned(),
                args: vec!["acp"],
                source: "Berd application",
            });
        }
    }

    if let Some(path) = search_path {
        for directory in std::env::split_paths(&path) {
            for (binary, id, name) in [
                ("goose", "goose", "Goose harness"),
                ("goosed", "goose-daemon", "Goose harness"),
            ] {
                let candidate = directory.join(binary);
                if executable(&candidate) && seen.insert(candidate.clone()) {
                    found.push(DiscoveredHarness {
                        id,
                        name,
                        description: "Installed Goose ACP loop; Apiary still governs its profile, tools, sandbox, and accounting.",
                        command: candidate.to_string_lossy().into_owned(),
                        args: vec!["acp"],
                        source: "PATH",
                    });
                }
            }
        }
    }
    found
}

fn discover_acp_harnesses() -> Vec<DiscoveredHarness> {
    let mut berd_paths = vec![std::path::PathBuf::from(
        "/Applications/Berd.app/Contents/MacOS/goosed",
    )];
    if let Some(home) = std::env::var_os("HOME") {
        berd_paths.push(
            std::path::PathBuf::from(home).join("Applications/Berd.app/Contents/MacOS/goosed"),
        );
    }
    let search_path = std::env::var_os("PATH");
    discover_acp_harnesses_from(&berd_paths, search_path.as_deref())
}

#[cfg(test)]
mod harness_discovery_tests {
    use super::discover_acp_harnesses_from;

    #[cfg(unix)]
    #[test]
    fn berd_and_path_goose_are_prefilled_as_stdio_acp_without_launching() {
        use std::os::unix::fs::PermissionsExt;

        let root =
            std::env::temp_dir().join(format!("apiary-harness-discovery-{}", std::process::id()));
        let berd = root.join("Berd.app/Contents/MacOS/goosed");
        let path_bin = root.join("bin");
        std::fs::create_dir_all(berd.parent().unwrap()).unwrap();
        std::fs::create_dir_all(&path_bin).unwrap();
        std::fs::write(&berd, b"test").unwrap();
        std::fs::write(path_bin.join("goose"), b"test").unwrap();
        std::fs::set_permissions(&berd, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(
            path_bin.join("goose"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();

        let found =
            discover_acp_harnesses_from(std::slice::from_ref(&berd), Some(path_bin.as_os_str()));
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].id, "berd-goose");
        assert_eq!(found[0].command, berd.to_string_lossy());
        assert_eq!(found[0].args, vec!["acp"]);
        assert_eq!(found[1].id, "goose");
        assert_eq!(found[1].args, vec!["acp"]);
        std::fs::remove_dir_all(root).unwrap();
    }
}

/// Discover known ACP harness executables without launching them. Discovery
/// is agent-scoped so the same viewer/editor/governor policy as the harness
/// page applies; it never imports the foreign harness's profile or secrets.
pub async fn harnesses_discover(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(error) = gate(&state, &headers, "GET", &uri, None, &npub) {
        return error.into_response();
    }
    Json(json!({"ok": true, "harnesses": discover_acp_harnesses()})).into_response()
}

#[derive(serde::Deserialize)]
pub struct HarnessBody {
    harness: apiary_core::manifest::HarnessGrant,
    #[serde(default)]
    original_name: Option<String>,
}

pub async fn harness_upsert(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (_ks, npub, dir, raw, mut manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(value) => value,
            Err(error) => return error.into_response(),
        };
    let body: HarnessBody = match serde_json::from_slice(&raw_body) {
        Ok(body) => body,
        Err(error) => return err(StatusCode::BAD_REQUEST, error).into_response(),
    };
    if let Err(error) = body.harness.validate() {
        return err(StatusCode::BAD_REQUEST, error).into_response();
    }
    let original = body.original_name.as_deref().unwrap_or(&body.harness.name);
    if original != body.harness.name
        && manifest
            .harnesses
            .iter()
            .any(|existing| existing.name == body.harness.name)
    {
        return err(
            StatusCode::CONFLICT,
            format!("a harness named '{}' already exists", body.harness.name),
        )
        .into_response();
    }
    manifest
        .harnesses
        .retain(|existing| existing.name != original);
    manifest.harnesses.push(body.harness.clone());
    manifest
        .harnesses
        .sort_by(|left, right| left.name.cmp(&right.name));
    if let Err(error) = manifest.validate() {
        return err(StatusCode::BAD_REQUEST, error).into_response();
    }
    let yaml = match manifest.to_yaml() {
        Ok(yaml) => yaml,
        Err(error) => return err(StatusCode::INTERNAL_SERVER_ERROR, error).into_response(),
    };
    if let Err(error) = persist_manifest(&dir, &raw, &yaml) {
        return error.into_response();
    }
    Json(json!({
        "ok": true,
        "npub": npub,
        "harness": body.harness.name,
        "manifest_sha256": ceremony::manifest_hash(&yaml),
        "ratified": false,
        "note": "harness policy saved — review its authority and approve the amendment before the agent runs",
    }))
    .into_response()
}

pub async fn harness_delete(
    State(state): State<App>,
    AxPath((npub, name)): AxPath<(String, String)>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (_ks, npub, dir, raw, mut manifest) =
        match gate(&state, &headers, "DELETE", &uri, None, &npub) {
            Ok(value) => value,
            Err(error) => return error.into_response(),
        };
    let before = manifest.harnesses.len();
    manifest.harnesses.retain(|harness| harness.name != name);
    if manifest.harnesses.len() == before {
        return err(StatusCode::NOT_FOUND, format!("no harness named '{name}'")).into_response();
    }
    let yaml = match manifest.to_yaml() {
        Ok(yaml) => yaml,
        Err(error) => return err(StatusCode::INTERNAL_SERVER_ERROR, error).into_response(),
    };
    if let Err(error) = persist_manifest(&dir, &raw, &yaml) {
        return error.into_response();
    }
    Json(json!({
        "ok": true,
        "npub": npub,
        "removed": name,
        "manifest_sha256": ceremony::manifest_hash(&yaml),
        "ratified": false,
        "note": "harness removed — review and approve the amendment before the agent runs",
    }))
    .into_response()
}

// ---------------------------------------------------------------- owners

#[derive(serde::Deserialize)]
pub struct CreateOwnerBody {
    name: String,
}

/// List locally held human approval identities. They occupy an encrypted
/// keystore slot but deliberately have no agent manifest, so they never run,
/// appear in the roster, or acquire capabilities.
pub async fn owners_get(
    State(state): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = check_admin(&state, &headers, "GET", &uri, None) {
        return e.into_response();
    }
    let ks = match Keystore::open(&state.home) {
        Ok(ks) => ks,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    let mut owners = Vec::new();
    for npub in ks.list().unwrap_or_default() {
        let dir = ks.agent_dir(&npub);
        let is_owner = std::fs::read_to_string(dir.join("principal.kind"))
            .is_ok_and(|kind| kind.trim() == "owner");
        if !is_owner {
            continue;
        }
        let name = std::fs::read_to_string(dir.join("name"))
            .unwrap_or_else(|_| "Owner".into())
            .trim()
            .to_string();
        owners.push(json!({"npub": npub, "name": name}));
    }
    Json(json!({"ok": true, "owners": owners})).into_response()
}

/// Create a separate human approval identity for desktop-first onboarding.
/// It is NIP-49-encrypted under the already-unlocked keystore passphrase and
/// can ratify agents, but it is not itself an agent.
pub async fn owners_create(
    State(state): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    if let Err(e) = check_admin(&state, &headers, "POST", &uri, Some(&raw_body)) {
        return e.into_response();
    }
    let body: CreateOwnerBody = match serde_json::from_slice(&raw_body) {
        Ok(body) => body,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let name = body.name.trim().to_string();
    if name.is_empty() || name.chars().count() > 60 {
        return err(
            StatusCode::BAD_REQUEST,
            "owner name must be 1–60 characters",
        )
        .into_response();
    }
    let pass = match require_pass(&state) {
        Ok(pass) => pass,
        Err(e) => return e.into_response(),
    };
    let home = state.home.clone();
    let out = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, Resp> {
        let ks = Keystore::open(&home).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        let keys = apiary_core::identity::generate();
        let npub = apiary_core::identity::to_npub(&keys.public_key())
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        ks.store(&keys, &pass)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        let dir = ks.agent_dir(&npub);
        write_private(&dir.join("principal.kind"), "owner\n")
            .and_then(|_| write_private(&dir.join("name"), &name))
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        Ok(json!({
            "ok": true,
            "npub": npub,
            "name": name,
            "note": "owner identity created and encrypted in this keystore",
        }))
    })
    .await
    .unwrap_or_else(|e| Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)));
    match out {
        Ok(value) => Json(value).into_response(),
        Err(e) => e.into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct UnlockBody {
    passphrase: String,
    #[serde(default)]
    remember: bool,
}

/// Unlock the keystore for this daemon's lifetime. Verified against a real
/// key when one exists — a wrong passphrase is rejected here rather than
/// surfacing later as a confusing decrypt failure mid-operation.
pub async fn unlock(
    State(state): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let pq = uri
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| uri.path().to_string());
    let signer = match nip98::check(&state, &headers, "POST", &pq, Some(&raw_body)) {
        Ok(sig) => sig,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = nip98::authorize_admin(&state, signer) {
        return e.into_response();
    }
    let body: UnlockBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    if body.passphrase.is_empty() {
        return err(StatusCode::BAD_REQUEST, "empty passphrase").into_response();
    }
    let state2 = state.clone();
    let pass = body.passphrase.clone();
    // NIP-49 scrypt is deliberately slow — off the async runtime.
    let verified = tokio::task::spawn_blocking(move || {
        let ks = Keystore::open(&state2.home).map_err(|e| e.to_string())?;
        ks.verify_or_initialize_workspace(&pass)
            .map_err(|_| "This workspace passphrase does not match.".to_string())
    })
    .await
    .unwrap_or_else(|e| Err(e.to_string()));
    match verified {
        Ok(checked) => {
            let mut remember_warning = None;
            if body.remember {
                match state.remember_passphrase.as_ref() {
                    Some(remember) => match remember(&body.passphrase) {
                        Ok(()) => state.automatic_unlock.store(true, Ordering::Relaxed),
                        Err(error) => remember_warning = Some(error),
                    },
                    None => {
                        remember_warning =
                            Some("automatic unlock is not available in this host build".to_string())
                    }
                }
            }
            if let Ok(mut g) = state.passphrase.write() {
                *g = Some(body.passphrase);
            }
            Json(json!({
                "ok": true,
                "unlocked": true,
                "verified_against_key": checked,
                "automatic_unlock": state.automatic_unlock.load(Ordering::Relaxed),
                "remember_warning": remember_warning,
            }))
            .into_response()
        }
        Err(e) => err(StatusCode::UNAUTHORIZED, e).into_response(),
    }
}

pub async fn lock(
    State(state): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let pq = uri
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| uri.path().to_string());
    let signer = match nip98::check(&state, &headers, "POST", &pq, None) {
        Ok(sig) => sig,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = nip98::authorize_admin(&state, signer) {
        return e.into_response();
    }
    if let Ok(mut m) = state.admitted.lock() {
        m.clear(); // decrypted material goes with the passphrase
    }
    if let Ok(mut g) = state.passphrase.write() {
        *g = None;
    }
    Json(json!({"ok": true, "unlocked": false})).into_response()
}

pub async fn forget_automatic_unlock(
    State(state): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let pq = uri
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| uri.path().to_string());
    let signer = match nip98::check(&state, &headers, "POST", &pq, None) {
        Ok(sig) => sig,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = nip98::authorize_admin(&state, signer) {
        return e.into_response();
    }
    let Some(forget) = state.forget_passphrase.as_ref() else {
        return err(
            StatusCode::NOT_IMPLEMENTED,
            "automatic unlock is not available in this host build",
        )
        .into_response();
    };
    if let Err(error) = forget() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, error).into_response();
    }
    state.automatic_unlock.store(false, Ordering::Relaxed);
    Json(json!({"ok": true, "automatic_unlock": false})).into_response()
}

// ---------------------------------------------------------------- key tool

#[derive(serde::Deserialize)]
pub struct KeyQuery {
    key: String,
}

pub async fn key_normalize(
    State(state): State<App>,
    Query(q): Query<KeyQuery>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let pq = uri
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| uri.path().to_string());
    if let Err(e) = nip98::check(&state, &headers, "GET", &pq, None) {
        return e.into_response();
    }
    match apiary_core::identity::parse_npub(&q.key) {
        Ok(pk) => Json(json!({
            "ok": true,
            "npub": apiary_core::identity::to_npub(&pk).unwrap_or_default(),
            "hex": pk.to_hex(),
        }))
        .into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, e).into_response(),
    }
}

// ---------------------------------------------------------------- spend

pub async fn spend_status(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (_ks, npub, dir, _raw, manifest) = match gate(&state, &headers, "GET", &uri, None, &npub) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let budget = apiary_runtime::spend::tokens_per_day(&manifest.governance.budgets)
        .ok()
        .flatten();
    let proactive_budget =
        apiary_runtime::spend::proactive_tokens_per_day(&manifest.governance.budgets)
            .ok()
            .flatten();
    let day = apiary_runtime::spend::SpendLedger::open(&dir).today();
    match day {
        Ok(d) => {
            let used = d.input_tokens + d.output_tokens;
            let reserved: u64 = d.reservations.iter().map(|r| r.amount).sum();
            let proactive_reserved: u64 = d
                .reservations
                .iter()
                .filter(|r| r.proactive)
                .map(|r| r.amount)
                .sum();
            Json(json!({
                "ok": true,
                "npub": npub,
                "date": d.date,
                "input_tokens": d.input_tokens,
                "output_tokens": d.output_tokens,
                "used": used,
                "reserved": reserved,
                "budget_tokens_per_day": budget,
                "remaining": budget.map(|b| b.saturating_sub(used + reserved)),
                // The proactive sub-lane: part of `used`, not additional to it.
                "proactive_used": d.proactive_tokens,
                "proactive_reserved": proactive_reserved,
                "budget_proactive_tokens_per_day": proactive_budget,
                "proactive_remaining": proactive_budget
                    .map(|b| b.saturating_sub(d.proactive_tokens + proactive_reserved)),
            }))
            .into_response()
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

// ----------------------------------------------------------- inference setup

fn inference_role(name: &str) -> &'static str {
    match name {
        "embed" => "embedding",
        "transcribe" => "transcription",
        "speak" => "speech",
        _ => "language",
    }
}

fn valid_inference_provider(role: &str, provider: &str) -> bool {
    match role {
        "embedding" => matches!(provider, "ollama" | "hash" | "mock"),
        "transcription" => matches!(provider, "apple-speech" | "whisper-cpp" | "openai" | "mock"),
        "speech" => matches!(provider, "apple-speech" | "macos-say" | "openai" | "mock"),
        _ => matches!(
            provider,
            "claude-code"
                | "codex"
                | "anthropic"
                | "openai"
                | "xai"
                | "ollama"
                | "mock"
                | "mock-tool"
        ),
    }
}

fn loopback_url(raw: &str) -> Option<reqwest::Url> {
    let url = reqwest::Url::parse(raw).ok()?;
    match url.host_str()? {
        "127.0.0.1" | "localhost" | "::1" | "[::1]" => Some(url),
        _ => None,
    }
}

fn nonempty_env(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| !value.is_empty())
}

fn credential_source(slot: &apiary_core::manifest::InferenceSlot) -> String {
    if slot.provider == "claude-code" {
        return "local Claude Code sign-in".into();
    }
    if slot.provider == "codex" {
        return "local ChatGPT sign-in".into();
    }
    if slot.credential.is_some() {
        return "sealed API key".into();
    }
    let env = match slot.provider.as_str() {
        "anthropic" => nonempty_env("ANTHROPIC_API_KEY") || nonempty_env("ANTHROPIC_AUTH_TOKEN"),
        "openai" => nonempty_env("OPENAI_API_KEY"),
        "xai" => nonempty_env("XAI_API_KEY"),
        _ => false,
    };
    if env {
        "host environment".into()
    } else {
        "none".into()
    }
}

fn probe_inference_slot(slot: &apiary_core::manifest::InferenceSlot) -> serde_json::Value {
    let role = inference_role(&slot.name);
    let provider = slot.provider.as_str();
    let credential = credential_source(slot);
    let base_url = slot.requires.get("base_url").and_then(|v| v.as_str());
    let configured = credential != "none";
    let result = |state: &str, detail: String| json!({"state": state, "detail": detail});

    match provider {
        "ollama" => {
            let client = match reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(2))
                .build()
            {
                Ok(c) => c,
                Err(e) => return result("unavailable", e.to_string()),
            };
            let response = client.get("http://127.0.0.1:11434/api/tags").send();
            let Ok(response) = response else {
                return result(
                    "unavailable",
                    "Ollama is not reachable on localhost:11434".into(),
                );
            };
            let payload: serde_json::Value = response.json().unwrap_or_default();
            let requested = slot.model.as_deref().unwrap_or("");
            let present = requested.is_empty()
                || payload["models"].as_array().is_some_and(|models| {
                    models.iter().any(|m| {
                        let found = m["name"].as_str().unwrap_or("");
                        found == requested
                            || found.strip_suffix(":latest") == Some(requested)
                            || requested.strip_suffix(":latest") == Some(found)
                    })
                });
            if present {
                result(
                    "ready",
                    format!("Local Ollama model {requested} is installed"),
                )
            } else {
                result(
                    "unavailable",
                    format!("Ollama is running, but {requested} is not installed"),
                )
            }
        }
        "apple-speech" => {
            let command = slot
                .requires
                .get("command")
                .and_then(|v| v.as_str())
                .map(String::from);
            let engine = apiary_runtime::transcribe::AppleSpeech::new(command, None);
            match engine.probe() {
                Ok(probe) => result(
                    "ready",
                    format!(
                        "On-device Apple Speech: {}{}",
                        if probe["transcribe"].as_bool() == Some(true) {
                            "transcription"
                        } else {
                            "speech"
                        },
                        if probe["speak"].as_bool() == Some(true) {
                            " + synthesis"
                        } else {
                            ""
                        }
                    ),
                ),
                Err(e) => result("unavailable", e.to_string()),
            }
        }
        "macos-say" => {
            if std::path::Path::new("/usr/bin/say").is_file() {
                result("ready", "macOS speech synthesis is available".into())
            } else {
                result(
                    "unavailable",
                    "The macOS say command is not installed".into(),
                )
            }
        }
        "hash" | "mock" | "mock-tool" => {
            result("ready", "Built into Apiary; no external connection".into())
        }
        "whisper-cpp" => result(
            "configured",
            "Local whisper.cpp is checked when audio is received".into(),
        ),
        "claude-code" => {
            if !apiary_runtime::inference::claude_code_is_installed() {
                result("unavailable", "Claude Code is not installed".into())
            } else {
                match apiary_runtime::inference::claude_code_auth_status() {
                    Ok(account) => result(
                        "ready",
                        format!("Claude Code is signed in on this Mac ({account})"),
                    ),
                    Err(error) => result("unavailable", error.to_string()),
                }
            }
        }
        "codex" => {
            if !apiary_runtime::inference::codex_is_installed() {
                result("unavailable", "Codex CLI is not installed".into())
            } else {
                match apiary_runtime::inference::codex_auth_status() {
                    Ok(account) => result(
                        "ready",
                        format!("Codex is signed in on this Mac ({account})"),
                    ),
                    Err(apiary_runtime::Error::Provider(detail)) => {
                        result("unavailable", detail)
                    }
                    Err(error) => result("unavailable", error.to_string()),
                }
            }
        }
        "anthropic"
            if slot.requires.get("auth").and_then(|value| value.as_str()) == Some("oauth") =>
        {
            result(
                "unavailable",
                "Legacy Claude OAuth source: open Edit connection and save it to migrate to Claude Code"
                    .into(),
            )
        }
        "anthropic" | "xai" => {
            if configured {
                result(
                    "configured",
                    "Credential is available; no billable test request was sent".into(),
                )
            } else {
                result(
                    "unavailable",
                    "Add an API credential for this connection".into(),
                )
            }
        }
        "openai" => {
            if let Some(raw) = base_url {
                if let Some(url) = loopback_url(raw) {
                    let root = url.as_str().trim_end_matches('/').trim_end_matches("/v1");
                    let target = if role == "speech" {
                        format!("{root}/health")
                    } else {
                        format!("{root}/v1/models")
                    };
                    let response = reqwest::blocking::Client::builder()
                        .timeout(std::time::Duration::from_secs(2))
                        .redirect(reqwest::redirect::Policy::none())
                        .build()
                        .and_then(|c| c.get(target).send());
                    return match response {
                        Ok(r) if r.status().is_success() => {
                            result("ready", format!("Local compatible endpoint at {raw}"))
                        }
                        _ => result("unavailable", format!("Nothing answered at {raw}")),
                    };
                }
            }
            if configured {
                result(
                    "configured",
                    "Credential is available; no billable test request was sent".into(),
                )
            } else {
                result(
                    "unavailable",
                    "Add an API credential or a local base URL".into(),
                )
            }
        }
        _ => result(
            "unavailable",
            format!("Provider '{provider}' is not supported for {role}"),
        ),
    }
}

fn inference_probe_key(slot: &apiary_core::manifest::InferenceSlot) -> String {
    if slot.provider == "claude-code" {
        // All Claude Code routes share one local account and executable.
        return "claude-code-account".into();
    }
    if slot.provider == "codex" {
        // All Codex routes share one local ChatGPT account and executable.
        return "codex-chatgpt-account".into();
    }
    serde_json::to_string(&json!({
        "provider": slot.provider,
        "role": inference_role(&slot.name),
        "model": slot.model,
        "requires": slot.requires,
    }))
    .unwrap_or_else(|_| format!("{}:{}", slot.provider, slot.name))
}

fn probe_inference_slots(slots: &[apiary_core::manifest::InferenceSlot]) -> Vec<serde_json::Value> {
    let mut representatives = std::collections::BTreeMap::new();
    for slot in slots {
        representatives
            .entry(inference_probe_key(slot))
            .or_insert_with(|| slot.clone());
    }
    let statuses = std::thread::scope(|scope| {
        let handles = representatives
            .into_iter()
            .map(|(key, slot)| scope.spawn(move || (key, probe_inference_slot(&slot))))
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .filter_map(|handle| handle.join().ok())
            .collect::<std::collections::HashMap<_, _>>()
    });
    slots
        .iter()
        .map(|slot| {
            json!({
                "name": slot.name,
                "role": inference_role(&slot.name),
                "provider": slot.provider,
                "model": slot.model,
                "requires": slot.requires,
                "credential_source": credential_source(slot),
                "status": statuses.get(&inference_probe_key(slot)).cloned().unwrap_or_else(|| json!({
                    "state": "unavailable",
                    "detail": "provider health check did not complete"
                })),
            })
        })
        .collect()
}

pub async fn inference_status(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (_ks, npub, dir, raw, manifest) = match gate(&state, &headers, "GET", &uri, None, &npub) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let ratified = crate::agent_decision(&state, &dir, &npub, &raw, &manifest).ratified;
    let slots = manifest.inference.clone();
    let default = manifest.routing.default.clone();
    let rules = manifest.routing.rules.clone();
    let floors = manifest.routing.floors.clone();
    let fallbacks = manifest.routing.fallbacks.clone();
    let configuration = ceremony::manifest_hash(&raw);
    let state_for_probe = state.clone();
    let npub_for_probe = npub.clone();
    let probed = tokio::task::spawn_blocking(move || {
        state_for_probe
            .decisions
            .inference_probes(&npub_for_probe, &configuration, || {
                probe_inference_slots(&slots)
            })
    })
    .await
    .unwrap_or_default();
    Json(json!({
        "ok": true,
        "npub": npub,
        "ratified": ratified,
        "slots": probed,
        "routing": {"default": default, "rules": rules, "floors": floors, "fallbacks": fallbacks},
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
pub struct InferenceFallbackBody {
    primary: String,
    #[serde(default)]
    fallback: Option<String>,
}

/// Set one explicit failover route. This is routing authority, so it amends
/// the manifest and pauses the agent until a governor ratifies it.
pub async fn inference_set_fallback(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (_ks, npub, dir, raw, mut manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(value) => value,
            Err(error) => return error.into_response(),
        };
    let body: InferenceFallbackBody = match serde_json::from_slice(&raw_body) {
        Ok(body) => body,
        Err(error) => return err(StatusCode::BAD_REQUEST, error).into_response(),
    };
    let is_language = |name: &str| {
        manifest
            .inference
            .iter()
            .any(|slot| slot.name == name && inference_role(&slot.name) == "language")
    };
    if !is_language(&body.primary) {
        return err(
            StatusCode::BAD_REQUEST,
            format!("'{}' is not a task-model route", body.primary),
        )
        .into_response();
    }
    match body.fallback.as_deref().filter(|name| !name.is_empty()) {
        Some(fallback) if fallback == body.primary => {
            return err(
                StatusCode::BAD_REQUEST,
                "a route cannot fall back to itself",
            )
            .into_response()
        }
        Some(fallback) if !is_language(fallback) => {
            return err(
                StatusCode::BAD_REQUEST,
                format!("'{fallback}' is not a task-model route"),
            )
            .into_response()
        }
        Some(fallback) => {
            manifest
                .routing
                .fallbacks
                .insert(body.primary.clone(), vec![fallback.to_string()]);
        }
        None => {
            manifest.routing.fallbacks.remove(&body.primary);
        }
    }
    let yaml = match manifest.to_yaml() {
        Ok(yaml) => yaml,
        Err(error) => return err(StatusCode::BAD_REQUEST, error).into_response(),
    };
    if let Err(error) = persist_manifest(&dir, &raw, &yaml) {
        return error.into_response();
    }
    state.decisions.invalidate(&npub);
    Json(json!({
        "ok": true,
        "npub": npub,
        "primary": body.primary,
        "fallback": body.fallback,
        "note": "fallback saved — review and approve before the agent runs",
    }))
    .into_response()
}

/// Make one tiny, governed call through an exact approved route. The test
/// consumes the agent's token budget and lands as a signed run checkpoint;
/// it skips memory and connectors and never masks failure with fallback.
pub async fn inference_test(
    State(state): State<App>,
    AxPath((npub, name)): AxPath<(String, String)>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (ks, npub, dir, raw, manifest) = match gate(&state, &headers, "POST", &uri, None, &npub) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    if !crate::agent_decision(&state, &dir, &npub, &raw, &manifest).ratified {
        return err(
            StatusCode::CONFLICT,
            "approve the current configuration before testing inference",
        )
        .into_response();
    }
    if !manifest
        .inference
        .iter()
        .any(|slot| slot.name == name && inference_role(&slot.name) == "language")
    {
        return err(
            StatusCode::NOT_FOUND,
            format!("no task-model route '{name}'"),
        )
        .into_response();
    }
    let passphrase = match require_pass(&state) {
        Ok(passphrase) => passphrase,
        Err(error) => return error.into_response(),
    };
    let result = tokio::task::spawn_blocking(move || {
        let (custody, handle) = admit(&ks, &npub, &passphrase)?;
        let context = apiary_runtime::routing::TaskContext {
            tokens_per_run: Some(4_096),
            disable_tools: true,
            route_override: Some(name),
            lightweight: true,
            disable_fallback: true,
            ..Default::default()
        };
        apiary_runtime::runner::run_task(
            &manifest,
            &dir,
            &custody,
            &handle,
            "Connection check. Reply exactly OK.",
            &context,
        )
        .map_err(|error| err(StatusCode::BAD_GATEWAY, error))
    })
    .await
    .unwrap_or_else(|error| Err(err(StatusCode::INTERNAL_SERVER_ERROR, error)));
    match result {
        Ok(outcome) => Json(json!({
            "ok": true,
            "slot": outcome.slot,
            "model": outcome.completion.model,
            "response": outcome.completion.text,
            "input_tokens": outcome.completion.input_tokens,
            "output_tokens": outcome.completion.output_tokens,
            "elapsed_ms": outcome.timings.total_ms,
            "log_event": outcome.log_event_id,
        }))
        .into_response(),
        Err(error) => error.into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct InferenceUpsertBody {
    #[serde(default)]
    original_name: Option<String>,
    name: String,
    provider: String,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    credential: Option<String>,
    #[serde(default)]
    clear_credential: bool,
    #[serde(default)]
    requires: std::collections::BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    set_default: bool,
}

fn validate_inference_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 40
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

pub async fn inference_upsert(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (ks, npub, dir, raw, mut manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let body: InferenceUpsertBody = match serde_json::from_slice(&raw_body) {
        Ok(v) => v,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let name = body.name.trim().to_string();
    let provider = body.provider.trim().to_lowercase();
    if !validate_inference_name(&name) {
        return err(
            StatusCode::BAD_REQUEST,
            "connection name must be 1–40 letters, numbers, dashes, or underscores",
        )
        .into_response();
    }
    let role = inference_role(&name);
    if !valid_inference_provider(role, &provider) {
        return err(
            StatusCode::BAD_REQUEST,
            format!("provider '{provider}' cannot serve the {role} role"),
        )
        .into_response();
    }
    let model = body
        .model
        .filter(|m| !m.trim().is_empty())
        .map(|m| m.trim().to_string());
    let auth = body.requires.get("auth").and_then(|value| value.as_str());
    if provider == "anthropic" && !matches!(auth, None | Some("api-key")) {
        return err(
            StatusCode::BAD_REQUEST,
            "Anthropic API authentication must use an API key",
        )
        .into_response();
    }
    if provider != "anthropic" && auth.is_some() {
        return err(
            StatusCode::BAD_REQUEST,
            "requires.auth is only supported for Anthropic connections",
        )
        .into_response();
    }
    if matches!(provider.as_str(), "claude-code" | "codex")
        && body
            .credential
            .as_deref()
            .is_some_and(|secret| !secret.trim().is_empty())
    {
        return err(
            StatusCode::BAD_REQUEST,
            format!(
                "{} uses the account signed in on this Mac; it does not accept a per-route credential",
                if provider == "codex" { "Codex" } else { "Claude Code" }
            ),
        )
        .into_response();
    }
    if role == "language" && model.is_none() {
        return err(
            StatusCode::BAD_REQUEST,
            "task model connections require an explicit model identifier",
        )
        .into_response();
    }
    let original = body.original_name.as_deref().unwrap_or(&name);
    let existing = manifest
        .inference
        .iter()
        .find(|s| s.name == original)
        .cloned();
    if original != name && manifest.inference.iter().any(|s| s.name == name) {
        return err(
            StatusCode::CONFLICT,
            format!("connection '{name}' already exists"),
        )
        .into_response();
    }
    let supplied_secret = body
        .credential
        .filter(|secret| !secret.trim().is_empty())
        .map(|secret| Zeroizing::new(secret.trim().to_string()));
    let credential =
        if matches!(provider.as_str(), "claude-code" | "codex") || body.clear_credential {
            None
        } else if let Some(secret) = supplied_secret {
            let pass = match require_pass(&state) {
                Ok(p) => p,
                Err(e) => return e.into_response(),
            };
            let npub2 = npub.clone();
            match tokio::task::spawn_blocking(move || {
                let (custody, handle) = admit(&ks, &npub2, &pass)?;
                custody
                    .seal(&handle, secret.as_str())
                    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))
            })
            .await
            .unwrap_or_else(|e| Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)))
            {
                Ok(blob) => Some(blob),
                Err(e) => return e.into_response(),
            }
        } else {
            let auth_unchanged = existing.as_ref().is_none_or(|slot| {
                slot.requires.get("auth").and_then(|value| value.as_str()) == auth
            });
            existing
                .as_ref()
                .filter(|slot| slot.provider == provider && auth_unchanged)
                .and_then(|s| s.credential.clone())
        };
    let slot = apiary_core::manifest::InferenceSlot {
        name: name.clone(),
        provider,
        model,
        credential,
        requires: body.requires,
    };
    if let Some(index) = manifest.inference.iter().position(|s| s.name == original) {
        manifest.inference[index] = slot;
        if original != name {
            if manifest.routing.default.as_deref() == Some(original) {
                manifest.routing.default = Some(name.clone());
            }
            for rule in manifest
                .routing
                .rules
                .iter_mut()
                .chain(manifest.routing.floors.iter_mut())
            {
                if rule.to == original {
                    rule.to = name.clone();
                }
            }
        }
    } else {
        manifest.inference.push(slot);
    }
    if body.set_default {
        if inference_role(&name) != "language" {
            return err(
                StatusCode::BAD_REQUEST,
                "only a language model can be the default route",
            )
            .into_response();
        }
        manifest.routing.default = Some(name.clone());
    }
    if let Err(e) = manifest.validate() {
        return err(StatusCode::BAD_REQUEST, e).into_response();
    }
    let yaml = match serde_yaml::to_string(&manifest) {
        Ok(y) => y,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    if let Err(error) = persist_manifest(&dir, &raw, &yaml) {
        return error.into_response();
    }
    Json(json!({
        "ok": true,
        "name": name,
        "ratified": false,
        "note": "inference connection saved — review and approve before the agent runs",
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
pub struct InferenceDefaultBody {
    name: String,
}

pub async fn inference_set_default(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (_ks, _npub, dir, raw, mut manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let body: InferenceDefaultBody = match serde_json::from_slice(&raw_body) {
        Ok(v) => v,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    if !manifest
        .inference
        .iter()
        .any(|s| s.name == body.name && inference_role(&s.name) == "language")
    {
        return err(
            StatusCode::BAD_REQUEST,
            "default must name a language model connection",
        )
        .into_response();
    }
    manifest.routing.default = Some(body.name.clone());
    let yaml = match serde_yaml::to_string(&manifest) {
        Ok(y) => y,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    if let Err(error) = persist_manifest(&dir, &raw, &yaml) {
        return error.into_response();
    }
    Json(json!({"ok": true, "default": body.name, "ratified": false})).into_response()
}

pub async fn inference_delete(
    State(state): State<App>,
    AxPath((npub, name)): AxPath<(String, String)>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (_ks, _npub, dir, raw, mut manifest) =
        match gate(&state, &headers, "DELETE", &uri, None, &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    if manifest.routing.default.as_deref() == Some(&name)
        || manifest
            .routing
            .rules
            .iter()
            .chain(manifest.routing.floors.iter())
            .any(|r| r.to == name)
    {
        return err(
            StatusCode::CONFLICT,
            "this connection is still used by routing; choose another default or edit its rules first",
        )
        .into_response();
    }
    let before = manifest.inference.len();
    manifest.inference.retain(|s| s.name != name);
    if manifest.inference.len() == before {
        return err(
            StatusCode::NOT_FOUND,
            format!("no inference connection '{name}'"),
        )
        .into_response();
    }
    let yaml = match serde_yaml::to_string(&manifest) {
        Ok(y) => y,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    if let Err(error) = persist_manifest(&dir, &raw, &yaml) {
        return error.into_response();
    }
    Json(json!({"ok": true, "removed": name, "ratified": false})).into_response()
}

#[cfg(test)]
mod inference_setup_tests {
    use super::*;

    #[test]
    fn reserved_names_select_supporting_roles() {
        assert_eq!(inference_role("workhorse"), "language");
        assert_eq!(inference_role("embed"), "embedding");
        assert_eq!(inference_role("transcribe"), "transcription");
        assert_eq!(inference_role("speak"), "speech");
    }

    #[test]
    fn provider_matrix_rejects_cross_role_bindings() {
        assert!(valid_inference_provider("language", "claude-code"));
        assert!(valid_inference_provider("language", "codex"));
        assert!(valid_inference_provider("language", "anthropic"));
        assert!(valid_inference_provider("embedding", "ollama"));
        assert!(valid_inference_provider("transcription", "apple-speech"));
        assert!(valid_inference_provider("speech", "macos-say"));
        assert!(!valid_inference_provider("embedding", "anthropic"));
        assert!(!valid_inference_provider("language", "apple-speech"));
    }

    #[test]
    fn diagnostics_only_probe_exact_loopback_hosts() {
        assert!(loopback_url("http://127.0.0.1:8880/v1").is_some());
        assert!(loopback_url("http://localhost:11434").is_some());
        assert!(loopback_url("http://[::1]:8080/v1").is_some());
        assert!(loopback_url("https://localhost.example.com/v1").is_none());
        assert!(loopback_url("https://api.openai.com/v1").is_none());
    }

    #[test]
    fn catalog_distinguishes_search_from_known_url_fetching() {
        let entries = connector_catalog().as_array().unwrap().clone();
        let search = entries
            .iter()
            .find(|entry| entry["kind"] == "web-search")
            .unwrap();
        assert_eq!(search["setup"], "credential");
        assert_eq!(search["caps"]["fetch_public_pages"], true);
        assert!(entries.iter().any(|entry| entry["kind"] == "web-fetch"));
    }
}

// ---------------------------------------------------------------- log pub

pub async fn log_publish(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (ks, npub, dir, _raw, manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&[]), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let pass = match require_pass(&state) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let relays = manifest.memory.log_relays.clone();
    if relays.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "manifest has no memory.log_relays — add relay URLs to the manifest first",
        )
        .into_response();
    }
    let out = tokio::task::spawn_blocking(move || {
        let (custody, handle) = admit(&ks, &npub, &pass)?;
        apiary_runtime::publish::publish_log(&dir, &custody, &handle, &relays)
            .map(|report| (npub, report))
            .map_err(|e| err(StatusCode::BAD_GATEWAY, e))
    })
    .await
    .unwrap_or_else(|e| Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)));
    match out {
        Ok((npub, r)) => Json(json!({
            "ok": true,
            "npub": npub,
            "published_public": r.published_public,
            "published_wrapped": r.published_wrapped,
            "skipped_local": r.skipped_local,
            "already_published": r.already_published,
            "relays": r.relay_results,
        }))
        .into_response(),
        Err(e) => e.into_response(),
    }
}

pub async fn log_remote(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (ks, npub, _dir, _raw, manifest) = match gate(&state, &headers, "GET", &uri, None, &npub) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let pass = match require_pass(&state) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let relays = manifest.memory.log_relays.clone();
    let out = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, Resp> {
        let pk = apiary_core::identity::parse_npub(&npub)
            .map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
        let (custody, handle) = admit(&ks, &npub, &pass)?;
        let mut summary = Vec::new();
        for relay in &relays {
            let own = json!({
                "authors": [pk.to_hex()],
                "kinds": [apiary_core::log::LOG_ENTRY_KIND, apiary_runtime::publish::WRAPPED_KIND],
            });
            let about = json!({
                "kinds": [apiary_core::log::LOG_ENTRY_KIND],
                "#p": [pk.to_hex()],
            });
            let fetched = apiary_runtime::relay::fetch(relay, own).and_then(|mut a| {
                let b = apiary_runtime::relay::fetch(relay, about)?;
                for e in b {
                    if !a.iter().any(|x| x.id == e.id) {
                        a.push(e);
                    }
                }
                Ok(a)
            });
            match fetched {
                Ok(events) => {
                    let mut items = Vec::new();
                    for e in &events {
                        if e.verify().is_err() {
                            continue;
                        }
                        let wrapped = e.kind.as_u16() == apiary_runtime::publish::WRAPPED_KIND;
                        // unwrap_self_entry yields the INNER signed log
                        // event; its content is the entry body.
                        let body: Option<serde_json::Value> = if wrapped {
                            apiary_runtime::publish::unwrap_self_entry(&custody, &handle, e)
                                .ok()
                                .and_then(|inner| serde_json::from_str(&inner.content).ok())
                        } else {
                            serde_json::from_str(&e.content).ok()
                        };
                        items.push(json!({
                            "id": e.id.to_hex(),
                            "at": e.created_at.as_secs(),
                            "signer": e.pubkey.to_hex(),
                            "kind": e.kind.as_u16(),
                            "wrapped": wrapped,
                            "body": body,
                        }));
                    }
                    summary.push(json!({"relay": relay, "ok": true, "events": items}));
                }
                Err(e) => {
                    summary.push(json!({"relay": relay, "ok": false, "error": e.to_string()}))
                }
            }
        }
        Ok(json!({"ok": true, "npub": npub, "relays": summary}))
    })
    .await
    .unwrap_or_else(|e| Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)));
    match out {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

// ---------------------------------------------------------------- ratify io

#[derive(serde::Deserialize)]
pub struct RatifyExportBody {
    /// The external human's key (npub or hex) that will sign elsewhere.
    r#as: String,
}

/// Emit the UNSIGNED ratification event so a human can sign with their own
/// nostr tooling — their master key never enters Apiary.
pub async fn ratify_export(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (_ks, npub, _dir, raw, manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let body: RatifyExportBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let ratifier = match apiary_core::identity::parse_npub(&body.r#as) {
        Ok(pk) => pk,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    if !suspend_pks(&manifest).contains(&ratifier) {
        return err(
            StatusCode::FORBIDDEN,
            "that key is not in this agent's governance.suspend_keys — only a named human can ratify",
        )
        .into_response();
    }
    match ceremony::ratification_unsigned(ratifier, &npub, &raw) {
        Ok(unsigned) => Json(json!({
            "ok": true,
            "npub": npub,
            "sign_as": body.r#as,
            "unsigned_event": serde_json::from_str::<serde_json::Value>(&unsigned.as_json())
                .unwrap_or_default(),
            "note": "sign this with your own nostr tooling, then import the signed event",
        }))
        .into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct RatifyImportBody {
    event: serde_json::Value,
}

pub async fn ratify_import(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (ks, npub, dir, raw, manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let body: RatifyImportBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let event = match Event::from_json(body.event.to_string()) {
        Ok(e) => e,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                format!("could not parse event: {e}"),
            )
            .into_response()
        }
    };
    // Same rail as the local path: an imported ratification event signed by
    // an agent cannot be the thing that grants autonomy.
    if let Err(e) = crate::check_autonomy_grant(&ks, &dir, &manifest, &event.pubkey) {
        return err(StatusCode::FORBIDDEN, e).into_response();
    }
    let pass = match require_pass(&state) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let listed = suspend_pks(&manifest);
    let state_for_decision = state.clone();
    let npub_for_decision = npub.clone();
    let out = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, Resp> {
        let (custody, handle) = admit(&ks, &npub, &pass)?;
        let log = EpisodicLog::open(&dir);
        // A complete founding needs BOTH signatures: the agent signs its
        // manifest here, then the external human event is verified in.
        let signed = ceremony::sign_manifest(&custody, &handle, &log, &raw)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        ceremony::import_ratification(&log, &event, &raw, &listed)
            .map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
        // Importing the signed event is authoritative. Keep a missing review
        // snapshot as a warning instead of claiming ratification failed.
        let snapshot_warning = write_private(&dir.join("manifest.approved.yaml"), &raw)
            .err()
            .map(|e| e.to_string());
        state_for_decision.decisions.invalidate(&npub_for_decision);
        Ok(json!({
            "ok": true,
            "npub": npub,
            "agent_signed": signed.id.to_hex(),
            "imported": event.id.to_hex(),
            "ratified_by": event.pubkey.to_hex(),
            "manifest_sha256": ceremony::manifest_hash(&raw),
            "snapshot_warning": snapshot_warning,
        }))
    })
    .await
    .unwrap_or_else(|e| Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)));
    match out {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

// ---------------------------------------------------------------- creds

#[derive(serde::Deserialize)]
pub struct ControlTokenBody {
    /// Short-lived by default; bounded to 90 days by the token verifier.
    #[serde(default = "default_control_token_ttl")]
    expires_in_seconds: u64,
    #[serde(default)]
    label: String,
}

fn default_control_token_ttl() -> u64 {
    24 * 60 * 60
}

/// Issue a bearer credential signed by this agent's own Nostr identity.
/// A governor authorizes issuance, but the resulting protocol client acts as
/// the agent—not as that human. It may run that same agent through AG-UI and
/// manage only agents which list this agent's npub (or the host, if explicitly
/// made a host manager).
pub async fn control_token_issue(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (ks, npub, _dir, _raw, _manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(value) => value,
            Err(error) => return error.into_response(),
        };
    let body: ControlTokenBody = if raw_body.is_empty() {
        ControlTokenBody {
            expires_in_seconds: default_control_token_ttl(),
            label: String::new(),
        }
    } else {
        match serde_json::from_slice(&raw_body) {
            Ok(body) => body,
            Err(error) => return err(StatusCode::BAD_REQUEST, error).into_response(),
        }
    };
    let label = body.label.trim();
    if label.len() > 80 || label.chars().any(char::is_control) {
        return err(
            StatusCode::BAD_REQUEST,
            "control-token label must be at most 80 printable characters",
        )
        .into_response();
    }
    let (custody, handle) = match crate::admit_agent(&state, &ks, &npub) {
        Ok(value) => value,
        Err(error) => return err(StatusCode::SERVICE_UNAVAILABLE, error).into_response(),
    };
    let host_id = apiary_runtime::lease::host_id(&state.home);
    match nip98::issue_control_token(&custody, &handle, &host_id, body.expires_in_seconds) {
        Ok((token, mut record)) => {
            record.label = label.to_string();
            if let Err(error) = nip98::register_control_token(&state, record.clone()) {
                return err(StatusCode::INTERNAL_SERVER_ERROR, error).into_response();
            }
            Json(json!({
                "ok": true,
                "agent": npub,
                "id": record.id,
                "label": record.label,
                "token": token,
                "expires_at": record.expires_at,
                "mcp_url": format!("{}/mcp", state.origin.trim_end_matches('/')),
                "local_mcp_url": "apiary://local/mcp",
                "host_id": host_id,
                "authorization": "Bearer <token>",
                "note": "This bearer acts as the agent identity. Store it as a sealed credential and never log it."
            }))
            .into_response()
        }
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, error).into_response(),
    }
}

pub async fn control_tokens_get(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (_ks, npub, _dir, _raw, _manifest) = match gate(&state, &headers, "GET", &uri, None, &npub)
    {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    match nip98::list_control_tokens(&state, &npub) {
        Ok(tokens) => {
            let now = now_secs();
            let tokens = tokens
                .into_iter()
                .map(|token| {
                    json!({
                        "id": token.id,
                        "agent": token.agent,
                        "label": token.label,
                        "created_at": token.created_at,
                        "expires_at": token.expires_at,
                        "revoked_at": token.revoked_at,
                        "active": token.revoked_at.is_none() && token.expires_at > now,
                    })
                })
                .collect::<Vec<_>>();
            Json(json!({"ok": true, "tokens": tokens})).into_response()
        }
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, error).into_response(),
    }
}

pub async fn control_token_revoke(
    State(state): State<App>,
    AxPath((npub, id)): AxPath<(String, String)>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (_ks, npub, _dir, _raw, _manifest) =
        match gate(&state, &headers, "DELETE", &uri, None, &npub) {
            Ok(value) => value,
            Err(error) => return error.into_response(),
        };
    if id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return err(StatusCode::BAD_REQUEST, "invalid control-token ID").into_response();
    }
    match nip98::revoke_control_token(&state, &npub, &id) {
        Ok(token) => Json(json!({
            "ok": true,
            "id": token.id,
            "agent": token.agent,
            "revoked_at": token.revoked_at,
        }))
        .into_response(),
        Err(error) if error.contains("not found") => {
            err(StatusCode::NOT_FOUND, error).into_response()
        }
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, error).into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct SealBody {
    plaintext: String,
}

pub async fn credential_seal(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (ks, npub, _dir, _raw, _manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let body: SealBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let pass = match require_pass(&state) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let out = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, Resp> {
        let (custody, handle) = admit(&ks, &npub, &pass)?;
        let blob = custody
            .seal(&handle, body.plaintext.trim_end())
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        Ok(json!({"ok": true, "npub": npub, "nip44": blob.nip44}))
    })
    .await
    .unwrap_or_else(|e| Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)));
    match out {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct OpenBody {
    nip44: String,
}

/// Dev/debug only — returns plaintext to the caller. The cockpit warns
/// before calling this.
pub async fn credential_open(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (ks, npub, _dir, _raw, _manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let body: OpenBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let pass = match require_pass(&state) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let out = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, Resp> {
        let (custody, handle) = admit(&ks, &npub, &pass)?;
        let blob = apiary_core::manifest::EncryptedBlob {
            nip44: body.nip44.trim().to_string(),
        };
        let plaintext = custody
            .open(&handle, &blob)
            .map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
        Ok(json!({"ok": true, "npub": npub, "plaintext": plaintext.as_str()}))
    })
    .await
    .unwrap_or_else(|e| Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)));
    match out {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

// ---------------------------------------------------------------- buzz

#[derive(serde::Deserialize)]
pub struct RelayQuery {
    relay: String,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default = "default_limit")]
    limit: usize,
}
fn default_limit() -> usize {
    30
}

/// Open an authenticated Buzz session for one operation.
fn buzz_session_op<T: Send + 'static>(
    ks: Keystore,
    npub: String,
    pass: String,
    relay: String,
    f: impl FnOnce(
            &mut apiary_runtime::buzz::BuzzSession,
            &Custody,
            &apiary_core::custody::AgentHandle,
            &std::path::Path,
        ) -> Result<T, crate::ops::Resp>
        + Send
        + 'static,
) -> tokio::task::JoinHandle<Result<T, Resp>> {
    tokio::task::spawn_blocking(move || {
        let dir = ks.agent_dir(&npub);
        let (custody, handle) = admit(&ks, &npub, &pass)?;
        let mut session = apiary_runtime::buzz::BuzzSession::connect(&relay, &custody, &handle)
            .map_err(|e| err(StatusCode::BAD_GATEWAY, e))?;
        f(&mut session, &custody, &handle, &dir)
    })
}

pub async fn buzz_channels(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    Query(q): Query<RelayQuery>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (ks, npub, _dir, _raw, _m) = match gate(&state, &headers, "GET", &uri, None, &npub) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let pass = match require_pass(&state) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let relay = q.relay.clone();
    let out = buzz_session_op(ks, npub, pass, relay.clone(), move |session, _c, _h, _d| {
        let channels: Vec<serde_json::Value> = session
            .channels()
            .map_err(|e| err(StatusCode::BAD_GATEWAY, e))?
            .iter()
            .filter_map(|e| {
                let mut id = None;
                let mut name = None;
                for t in e.tags.iter() {
                    let s = t.as_slice();
                    match s.first().map(String::as_str) {
                        Some("d") => id = s.get(1).cloned(),
                        Some("name") => name = s.get(1).cloned(),
                        _ => {}
                    }
                }
                Some(json!({"id": id?, "name": name}))
            })
            .collect();
        Ok(json!({"ok": true, "relay": relay, "channels": channels}))
    })
    .await
    .unwrap_or_else(|e| Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)));
    match out {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

pub async fn buzz_read(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    Query(q): Query<RelayQuery>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (ks, npub, _dir, _raw, _m) = match gate(&state, &headers, "GET", &uri, None, &npub) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let pass = match require_pass(&state) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let Some(channel) = q.channel.clone() else {
        return err(StatusCode::BAD_REQUEST, "channel is required").into_response();
    };
    let limit = q.limit;
    let out = buzz_session_op(
        ks,
        npub,
        pass,
        q.relay.clone(),
        move |session, _c, _h, _d| {
            let msgs: Vec<serde_json::Value> = session
                .read_channel(&channel, limit)
                .map_err(|e| err(StatusCode::BAD_GATEWAY, e))?
                .iter()
                .map(|e| {
                    json!({
                        "id": e.id.to_hex(),
                        "at": e.created_at.as_secs(),
                        "author": e.pubkey.to_hex(),
                        "content": e.content,
                    })
                })
                .collect();
            Ok(json!({"ok": true, "channel": channel, "messages": msgs}))
        },
    )
    .await
    .unwrap_or_else(|e| Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)));
    match out {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct BuzzPostBody {
    relay: String,
    channel: String,
    message: String,
}

pub async fn buzz_post(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (ks, npub, _dir, _raw, _m) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let body: BuzzPostBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let pass = match require_pass(&state) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let relay = body.relay.clone();
    let out = buzz_session_op(ks, npub, pass, relay.clone(), move |session, c, h, dir| {
        let event = session
            .post(&body.channel, &body.message, &[])
            .map_err(|e| err(StatusCode::BAD_GATEWAY, e))?;
        // Membership acts are part of the record — same entry the CLI writes.
        EpisodicLog::open(dir)
            .append(
                c,
                h,
                apiary_core::log::Tier::Self_,
                &apiary_core::log::EntryBody {
                    action: "buzz.post".into(),
                    model: None,
                    cost: None,
                    harness: None,
                    outcome: "ok".into(),
                    detail: Some(json!({
                        "relay": relay,
                        "channel": body.channel,
                        "event": event.id.to_hex(),
                        "chars": body.message.len(),
                    })),
                },
            )
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        Ok(json!({
            "ok": true,
            "channel": body.channel,
            "event": event.id.to_hex(),
        }))
    })
    .await
    .unwrap_or_else(|e| Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)));
    match out {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct BuzzProfileBody {
    relay: String,
    name: String,
    #[serde(default)]
    about: Option<String>,
    #[serde(default)]
    picture: Option<String>,
}

pub async fn buzz_profile(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (ks, npub, _dir, _raw, _m) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let body: BuzzProfileBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let pass = match require_pass(&state) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let relay = body.relay.clone();
    let out = buzz_session_op(ks, npub, pass, relay.clone(), move |session, c, h, dir| {
        let event = session
            .set_profile(&body.name, body.about.as_deref(), body.picture.as_deref())
            .map_err(|e| err(StatusCode::BAD_GATEWAY, e))?;
        EpisodicLog::open(dir)
            .append(
                c,
                h,
                apiary_core::log::Tier::Public,
                &apiary_core::log::EntryBody {
                    action: "buzz.profile".into(),
                    model: None,
                    cost: None,
                    harness: None,
                    outcome: "ok".into(),
                    detail: Some(json!({
                        "relay": relay,
                        "name": body.name,
                        "event": event.id.to_hex(),
                    })),
                },
            )
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        Ok(json!({"ok": true, "name": body.name, "event": event.id.to_hex()}))
    })
    .await
    .unwrap_or_else(|e| Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)));
    match out {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct BuzzJoinBody {
    relay: String,
    channel: String,
}

pub async fn buzz_join(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (ks, npub, _dir, _raw, _m) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let body: BuzzJoinBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let pass = match require_pass(&state) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let out = buzz_session_op(ks, npub, pass, body.relay.clone(), move |session, _c, _h, _d| {
        let event = session
            .join_channel(&body.channel)
            .map_err(|e| err(StatusCode::BAD_GATEWAY, e))?;
        Ok(json!({
            "ok": true,
            "channel": body.channel,
            "event": event.id.to_hex(),
            "note": "join requested — open channels admit immediately, private ones await an admin",
        }))
    })
    .await
    .unwrap_or_else(|e| Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)));
    match out {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

// ---------------------------------------------------------------- listener

// ---------------------------------------------------------------- activation

/// Host-local operational state: while a marker file exists in the agent's
/// directory, this host considers the agent ACTIVE and supervises its
/// declared standing presence. Deliberately NOT in the manifest — which
/// workspace the agent lives in is constitutional (presence.buzz, ratified);
/// whether this host is currently running it is an operator switch.
pub fn is_active(dir: &std::path::Path) -> bool {
    dir.join("active").exists()
}

/// Archival is deliberately host-local, like activation. It does not alter
/// or re-ratify the portable identity; it removes the agent from the normal
/// workspace and prevents new work until a governor restores it.
pub fn is_archived(dir: &std::path::Path) -> bool {
    dir.join("archived").exists()
}

fn stop_agent_processes(state: &AppState, npub: &str) {
    let mut listeners = state.listeners.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(mut presence) = listeners.remove(npub) {
        stop_all(&mut presence);
    }
    state
        .supervisor_notes
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(npub);
}

fn clear_agent_runtime_state(state: &AppState, npub: &str) {
    stop_agent_processes(state, npub);
    state
        .admitted
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(npub);
    state
        .pending_oauth
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|_, grant| grant.npub != npub);
    state.decisions.invalidate(npub);
}

#[derive(serde::Deserialize)]
pub struct ArchiveBody {
    archived: bool,
}

pub async fn archive_agent(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (_ks, npub, dir, _raw, _manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(value) => value,
            Err(error) => return error.into_response(),
        };
    let body: ArchiveBody = match serde_json::from_slice(&raw_body) {
        Ok(body) => body,
        Err(error) => return err(StatusCode::BAD_REQUEST, error).into_response(),
    };
    let marker = dir.join("archived");
    if body.archived {
        clear_agent_runtime_state(&state, &npub);
        if let Err(error) = std::fs::remove_file(dir.join("active")) {
            if error.kind() != std::io::ErrorKind::NotFound {
                return err(StatusCode::INTERNAL_SERVER_ERROR, error).into_response();
            }
        }
        if let Err(error) = std::fs::write(&marker, b"1") {
            return err(StatusCode::INTERNAL_SERVER_ERROR, error).into_response();
        }
    } else if let Err(error) = std::fs::remove_file(&marker) {
        if error.kind() != std::io::ErrorKind::NotFound {
            return err(StatusCode::INTERNAL_SERVER_ERROR, error).into_response();
        }
    }
    Json(json!({
        "ok": true,
        "npub": npub,
        "archived": body.archived,
        "active": false,
        "note": if body.archived {
            "agent archived — standing presence stopped and protected key material evicted from memory"
        } else {
            "agent restored — it remains inactive until explicitly activated"
        },
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
pub struct DeleteAgentBody {
    confirmation: String,
}

pub async fn delete_agent(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (_ks, npub, dir, _raw, _manifest) =
        match gate(&state, &headers, "DELETE", &uri, Some(&raw_body), &npub) {
            Ok(value) => value,
            Err(error) => return error.into_response(),
        };
    let body: DeleteAgentBody = match serde_json::from_slice(&raw_body) {
        Ok(body) => body,
        Err(error) => return err(StatusCode::BAD_REQUEST, error).into_response(),
    };
    if !is_archived(&dir) {
        return err(
            StatusCode::CONFLICT,
            "archive the agent before permanently deleting it",
        )
        .into_response();
    }
    if body.confirmation.trim() != npub {
        return err(
            StatusCode::BAD_REQUEST,
            "confirmation must be the agent's exact npub",
        )
        .into_response();
    }
    if let Err(error) = require_pass(&state) {
        return error.into_response();
    }
    clear_agent_runtime_state(&state, &npub);
    let removed_tokens = match nip98::delete_control_tokens_for_agent(&state, &npub) {
        Ok(count) => count,
        Err(error) => return err(StatusCode::INTERNAL_SERVER_ERROR, error).into_response(),
    };
    if let Err(error) = std::fs::remove_dir_all(&dir) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, error).into_response();
    }
    Json(json!({
        "ok": true,
        "deleted": npub,
        "removed_control_tokens": removed_tokens,
        "note": "agent identity, configuration, credentials, and local history permanently deleted",
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
pub struct ActiveBody {
    active: bool,
}

pub async fn set_active(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (_ks, npub, dir, _raw, manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let body: ActiveBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let marker = dir.join("active");
    let result = if body.active {
        std::fs::write(&marker, b"1")
    } else {
        match std::fs::remove_file(&marker) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    };
    if let Err(e) = result {
        return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
    }
    // Deactivation takes effect immediately rather than on the next
    // supervisor tick — every channel and the lease keeper.
    if !body.active {
        stop_agent_processes(&state, &npub);
    }
    Json(json!({
        "ok": true,
        "npub": npub,
        "active": body.active,
        "declared_channels": manifest.presence.channels.keys().cloned().collect::<Vec<_>>(),
        "note": if body.active {
            "active — the supervisor starts declared presence within ~10s"
        } else {
            "inactive — standing presence stopped; one-shot runs stay available"
        },
    }))
    .into_response()
}

// ---------------------------------------------------------------- supervisor

// ---------------------------------------------------------------- connectors

/// The host connector library: named, reusable connector CONFIGURATIONS
/// (kind + caps), stored host-side in connectors.yaml. Deliberately no
/// secrets — a credential is sealed per-agent at grant time, because NIP-44
/// blobs bind to one key and a library secret would be a shared secret.
///
/// Granting copies a library entry into an agent's manifest connectors[]
/// (sealing a credential to that agent if provided). That edit changes the
/// manifest hash, so every grant is ratified by a governor — and because the
/// grant lives in the manifest, it travels with the agent: portability
/// includes capabilities and their sealed credentials. The destination
/// host must merely bind the kind (BOUND_KINDS); an unbindable declared
/// connector fails loudly at run start.
#[derive(serde::Serialize, serde::Deserialize, Default)]
pub struct ConnectorLibrary {
    #[serde(default)]
    pub connectors: Vec<LibraryEntry>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct LibraryEntry {
    /// Human label, unique in the library ("publish-main").
    pub name: String,
    /// Connector kind the host binds ("nostr-publish").
    pub kind: String,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub caps: std::collections::BTreeMap<String, serde_json::Value>,
}

/// Trusted setup templates, not grants. Catalog entries contain no secret
/// and do not enter an agent manifest until a human configures, grants, and
/// approves them. Remote registry discovery can sit behind this curated
/// layer later without making registry publication a trust decision.
fn connector_catalog() -> serde_json::Value {
    json!([
        {
            "id": "apiary-control",
            "name": "Apiary management",
            "description": "Inspect and manage the Apiary agents assigned to this agent identity. Every operation remains subject to per-agent governance and host-manager authorization.",
            "kind": "mcp",
            "risk": "read + write agent control",
            "publisher": "Apiary",
            "source": "built-in control plane",
            "setup": "credential",
            "credential_label": "Agent MCP access token",
            "caps": {
                "transport": "http",
                "url": "apiary://local/mcp",
                "access": "read-write",
                "allowed_tools": ["apiary_describe", "apiary_list_agents", "apiary_get_agent_environment", "apiary_request"]
            }
        },
        {
            "id": "web-search-research",
            "name": "Full web search & research",
            "description": "Search Brave's independent web index, then open and inspect public sources with the bundled page reader.",
            "kind": "web-search",
            "risk": "read-only public network",
            "publisher": "Apiary + Brave Search",
            "source": "https://api-dashboard.search.brave.com/documentation/quickstart",
            "setup": "credential",
            "credential_label": "Brave Search API key",
            "caps": {
                "provider": "brave",
                "country": "US",
                "search_lang": "en",
                "safesearch": "moderate",
                "max_results": 10,
                "fetch_public_pages": true,
                "fetch_max_bytes": 262144
            }
        },
        {
            "id": "web-research",
            "name": "Web page reader",
            "description": "Open public HTTPS pages when you already have a URL. Private networks stay blocked and every redirect is rechecked.",
            "kind": "web-fetch",
            "risk": "read-only public network",
            "publisher": "Apiary",
            "source": "built-in",
            "setup": "none",
            "caps": {"allow_all_public": true, "allowed_domains": [], "allow_subdomains": false, "max_bytes": 262144}
        },
        {
            "id": "files-readonly",
            "name": "Files and documents",
            "description": "List, search, and read approved text files without exposing the rest of the device.",
            "kind": "files",
            "risk": "read-only local",
            "publisher": "Apiary",
            "source": "built-in",
            "setup": "folders",
            "caps": {"roots": [], "extensions": ["txt","md","json","jsonl","yaml","yml","csv","tsv","log","xml","html","toml"], "max_bytes": 262144}
        },
        {
            "id": "git-readonly",
            "name": "Git repositories",
            "description": "Inspect status, history, diffs, revisions, and tracked text in approved repositories.",
            "kind": "git",
            "risk": "read-only local",
            "publisher": "Apiary",
            "source": "built-in",
            "setup": "repositories",
            "caps": {"repos": []}
        },
        {
            "id": "github-readonly",
            "name": "GitHub",
            "description": "Read repository contents and search code through GitHub's official remote MCP server.",
            "kind": "mcp",
            "risk": "read-only account",
            "publisher": "GitHub",
            "source": "https://github.com/github/github-mcp-server",
            "setup": "credential",
            "credential_label": "GitHub access token",
            "caps": {
                "transport": "http",
                "url": "https://api.githubcopilot.com/mcp/x/repos/readonly",
                "access": "read-only",
                "allowed_tools": ["get_file_contents", "search_code", "search_repositories"]
            }
        }
    ])
}

fn library_path(state: &AppState) -> std::path::PathBuf {
    state.home.join("connectors.yaml")
}

fn load_library(state: &AppState) -> Result<ConnectorLibrary, Resp> {
    let p = library_path(state);
    if !p.exists() {
        return Ok(ConnectorLibrary::default());
    }
    let raw = std::fs::read_to_string(&p).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    serde_yaml::from_str(&raw).map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("connectors.yaml: {e}"),
        )
    })
}

pub async fn connectors_get(
    State(state): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let pq = uri
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| uri.path().to_string());
    if let Err(e) = nip98::check(&state, &headers, "GET", &pq, None) {
        return e.into_response();
    }
    match load_library(&state) {
        Ok(lib) => Json(json!({
            "ok": true,
            "library": lib.connectors,
            "host_binds": apiary_runtime::connector::BOUND_KINDS,
            "catalog": connector_catalog(),
        }))
        .into_response(),
        Err(e) => e.into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct LibraryBody {
    library: Vec<LibraryEntry>,
}

/// Native folder picker, provided by the desktop (Tauri dialog) when the
/// daemon runs inside it. Headless hostd has none — the cockpit falls
/// back to a typed path.
pub type FolderPicker = dyn Fn() -> Option<String> + Send + Sync;
static FOLDER_PICKER: std::sync::OnceLock<Box<FolderPicker>> = std::sync::OnceLock::new();
pub fn set_folder_picker(f: Box<FolderPicker>) {
    let _ = FOLDER_PICKER.set(f);
}

/// POST /api/host/pick-folder — open the system folder dialog and return
/// the chosen path (admin). {ok:false, unavailable:true} when headless.
pub async fn pick_folder(
    State(state): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let pq = uri
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| uri.path().to_string());
    let signer = match nip98::check(&state, &headers, "POST", &pq, Some(&raw_body)) {
        Ok(sig) => sig,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = nip98::authorize_admin(&state, signer) {
        return e.into_response();
    }
    let Some(picker) = FOLDER_PICKER.get() else {
        return Json(json!({"ok": false, "unavailable": true, "error": "no native folder picker on this host — type the path"})).into_response();
    };
    // Must NOT run on the UI main thread (the dialog blocks it) — a
    // blocking task is exactly right.
    let picked = tokio::task::spawn_blocking(picker).await.ok().flatten();
    match picked {
        Some(p) => Json(json!({"ok": true, "path": p})).into_response(),
        None => Json(json!({"ok": false, "cancelled": true})).into_response(),
    }
}

/// POST /api/connectors/discover — probe an MCP configuration and return
/// its tools, so a human can pick `allowed_tools` from a list instead of
/// guessing names. Body: {"caps": {...mcp caps...}, "bearer": "…"?}. For
/// an HTTP server that answers 401 the reply says auth_required (grant
/// the connector to an agent to run OAuth, then discover again with the
/// agent's token via …/agents/{npub}/connectors/{name}/discover). Admin.
pub async fn connectors_discover(
    State(state): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let pq = uri
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| uri.path().to_string());
    let signer = match nip98::check(&state, &headers, "POST", &pq, Some(&raw_body)) {
        Ok(sig) => sig,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = nip98::authorize_admin(&state, signer) {
        return e.into_response();
    }
    let body: serde_json::Value = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let caps = body["caps"].clone();
    let bearer = body["bearer"].as_str().map(String::from);
    let local_control_url = std::fs::read_to_string(state.home.join("control.json"))
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .and_then(|value| value["url"].as_str().map(String::from));
    let res = tokio::task::spawn_blocking(move || -> Result<Vec<serde_json::Value>, String> {
        let cap_str = |k: &str| caps.get(k).and_then(|v| v.as_str()).map(String::from);
        let cap_list = |k: &str| -> Vec<String> {
            caps.get(k)
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default()
        };
        let transport = cap_str("transport").unwrap_or_else(|| "stdio".into());
        let binding = match transport.as_str() {
            "stdio" => apiary_runtime::mcp::Binding::Stdio {
                command: cap_str("command").ok_or("mcp stdio requires command")?,
                args: cap_list("args"),
                env_passthrough: cap_list("env"),
            },
            "http" => apiary_runtime::mcp::Binding::Http {
                url: match cap_str("url").ok_or("mcp http requires url")?.as_str() {
                    "apiary://local/mcp" => local_control_url
                        .clone()
                        .ok_or("local Apiary control discovery is unavailable")?,
                    url => url.to_string(),
                },
                bearer,
            },
            other => return Err(format!("transport '{other}' not supported (stdio | http)")),
        };
        let mut client =
            apiary_runtime::mcp::McpClient::connect(binding).map_err(|e| e.to_string())?;
        let tools = client.tools_list().map_err(|e| e.to_string())?;
        Ok(tools
            .into_iter()
            .map(
                |t| json!({"name": t.name, "description": t.description, "read_only": t.read_only}),
            )
            .collect())
    })
    .await
    .unwrap_or_else(|e| Err(e.to_string()));
    match res {
        Ok(tools) => Json(json!({"ok": true, "tools": tools})).into_response(),
        Err(e) if e.contains("mcp-auth-required") => Json(json!({
            "ok": false,
            "auth_required": true,
            "error": "the server wants OAuth — grant this connector to an agent (the grant runs the flow), then discover with that agent",
            "challenge": e,
        }))
        .into_response(),
        Err(e) => err(StatusCode::BAD_GATEWAY, e).into_response(),
    }
}

/// POST /api/agents/{npub}/connectors/{name}/discover — like the host
/// discover, but with the agent's sealed credential (post-OAuth), so tools
/// behind auth can be listed and allowed. Governor.
pub async fn agent_connector_discover(
    State(state): State<App>,
    AxPath((npub, name)): AxPath<(String, String)>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (ks, npub, _dir, _raw, manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    // Grants are keyed by kind; `name` here is the library entry name and
    // is matched against caps.library_name when present, else the sole
    // mcp grant (or the one whose url/command matches).
    let Some(entry) = manifest
        .connectors
        .iter()
        .filter(|c| c.kind == "mcp")
        .find(|c| {
            c.caps.get("library_name").and_then(|v| v.as_str()) == Some(name.as_str())
                || c.caps.get("url").and_then(|v| v.as_str()) == Some(name.as_str())
                || c.caps.get("command").and_then(|v| v.as_str()) == Some(name.as_str())
        })
        .or_else(|| {
            let mcps: Vec<_> = manifest
                .connectors
                .iter()
                .filter(|c| c.kind == "mcp")
                .collect();
            if mcps.len() == 1 {
                Some(mcps[0])
            } else {
                None
            }
        })
        .cloned()
    else {
        return err(
            StatusCode::NOT_FOUND,
            format!("no mcp connector matching '{name}' granted to this agent"),
        )
        .into_response();
    };
    let (custody, handle) = match crate::admit_agent(&state, &ks, &npub) {
        Ok(v) => v,
        Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, e).into_response(),
    };
    let (bearer, oauth_refresh) = match &entry.credential {
        Some(blob) => match custody.open(&handle, blob) {
            Ok(z) => {
                let raw = z.as_str().to_string();
                match serde_json::from_str::<serde_json::Value>(&raw) {
                    Ok(v) if v["type"] == "oauth" => (
                        v["access_token"].as_str().map(String::from),
                        // Keep the whole OAuth object: a stale access token
                        // is refreshed exactly like the tool-call path does.
                        Some(v),
                    ),
                    _ => (Some(raw), None),
                }
            }
            Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
        },
        None => (None, None),
    };
    let caps = serde_json::to_value(&entry.caps).unwrap_or_default();
    let local_control_url = std::fs::read_to_string(state.home.join("control.json"))
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .and_then(|value| value["url"].as_str().map(String::from));
    let res = tokio::task::spawn_blocking(move || -> Result<Vec<serde_json::Value>, String> {
        let cap_str = |k: &str| caps.get(k).and_then(|v| v.as_str()).map(String::from);
        let cap_list = |k: &str| -> Vec<String> {
            caps.get(k)
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default()
        };
        let binding = match cap_str("transport")
            .unwrap_or_else(|| "stdio".into())
            .as_str()
        {
            "stdio" => apiary_runtime::mcp::Binding::Stdio {
                command: cap_str("command").ok_or("mcp stdio requires command")?,
                args: cap_list("args"),
                env_passthrough: cap_list("env"),
            },
            _ => apiary_runtime::mcp::Binding::Http {
                url: match cap_str("url").ok_or("mcp http requires url")?.as_str() {
                    "apiary://local/mcp" => local_control_url
                        .clone()
                        .ok_or("local Apiary control discovery is unavailable")?,
                    url => url.to_string(),
                },
                bearer,
            },
        };
        // Connect + list, with one refresh retry on a stale OAuth token,
        // the same bounded recovery the tool-call path has. Discovery is
        // how an allowlist gets fixed; it must not require a fresh token.
        let probe = |bearer: Option<String>| -> Result<Vec<apiary_runtime::mcp::McpTool>, String> {
            let b = match &binding {
                apiary_runtime::mcp::Binding::Http { url, .. } => {
                    apiary_runtime::mcp::Binding::Http {
                        url: url.clone(),
                        bearer,
                    }
                }
                other => other.clone(),
            };
            let mut client =
                apiary_runtime::mcp::McpClient::connect(b).map_err(|e| e.to_string())?;
            client.tools_list().map_err(|e| e.to_string())
        };
        let first_bearer = match &binding {
            apiary_runtime::mcp::Binding::Http { bearer, .. } => bearer.clone(),
            _ => None,
        };
        let tools = match probe(first_bearer) {
            Ok(t) => t,
            Err(e) if e.contains("mcp-auth-required") => {
                let fresh = oauth_refresh
                    .as_ref()
                    .and_then(|o| apiary_runtime::connector::refresh_access_token(o).ok())
                    .ok_or(format!(
                        "token expired and refresh failed; re-grant the connector (CONNECT WITH \
                         OAUTH) to re-authorize. Original: {e}"
                    ))?;
                probe(Some(fresh))?
            }
            Err(e) => return Err(e),
        };
        Ok(tools
            .into_iter()
            .map(
                |t| json!({"name": t.name, "description": t.description, "read_only": t.read_only}),
            )
            .collect())
    });
    // A hard deadline: a hung MCP server or OAuth token endpoint must
    // surface as an error, never as a cockpit spinner that outlives hope.
    let res = match tokio::time::timeout(std::time::Duration::from_secs(75), res).await {
        Ok(joined) => joined.unwrap_or_else(|e| Err(e.to_string())),
        Err(_) => Err(
            "discovery timed out after 75s — the MCP server or its OAuth token endpoint is not              answering"
                .to_string(),
        ),
    };
    match res {
        Ok(tools) => Json(json!({"ok": true, "tools": tools})).into_response(),
        Err(e) => err(StatusCode::BAD_GATEWAY, e).into_response(),
    }
}

/// POST /api/agents/{npub}/connectors/{kind}/allowed_tools
/// {"tools":[…], "tool_access":{"name":"read-only|read-write"}}
/// — rewrite an mcp grant's allowlist and optional per-tool access policy
/// (after Discover). An amendment:
/// re-ratify afterward. Governor.
pub async fn connector_set_allowed_tools(
    State(state): State<App>,
    AxPath((npub, kind)): AxPath<(String, String)>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (_ks, npub, dir, raw, mut manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let body: serde_json::Value = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let mut tools: Vec<String> = body["tools"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let tool_access = match body.get("tool_access") {
        Some(value) if !value.is_null() => {
            let Some(policies) = value.as_object() else {
                return err(StatusCode::BAD_REQUEST, "tool_access must be an object")
                    .into_response();
            };
            for (name, mode) in policies {
                if name.trim().is_empty() || name.len() > 256 {
                    return err(
                        StatusCode::BAD_REQUEST,
                        "tool_access has an invalid tool name",
                    )
                    .into_response();
                }
                if !matches!(mode.as_str(), Some("read-only" | "read-write")) {
                    return err(
                        StatusCode::BAD_REQUEST,
                        format!("tool_access.{name} must be read-only or read-write"),
                    )
                    .into_response();
                }
            }
            Some(policies.clone())
        }
        _ => None,
    };
    if let Some(policies) = &tool_access {
        tools = policies.keys().cloned().collect();
    }
    if tools.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "tools must name at least one tool (or *)",
        )
        .into_response();
    }
    let Some(c) = manifest.connectors.iter_mut().find(|c| c.kind == kind) else {
        return err(
            StatusCode::NOT_FOUND,
            format!("agent has no '{kind}' connector"),
        )
        .into_response();
    };
    c.caps.insert("allowed_tools".into(), json!(tools));
    if let Some(policies) = tool_access {
        c.caps.insert("tool_access".into(), json!(policies));
        c.caps.insert("access".into(), json!("mixed"));
    } else {
        c.caps.remove("tool_access");
    }
    let tool_access_now = c.caps.get("tool_access").cloned();
    let access_now = c.caps.get("access").cloned();
    let yaml = match serde_yaml::to_string(&manifest) {
        Ok(y) => y,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    if let Err(error) = persist_manifest(&dir, &raw, &yaml) {
        return error.into_response();
    }
    Json(json!({
        "ok": true, "npub": npub, "kind": kind, "allowed_tools": tools,
        "tool_access": tool_access_now, "access": access_now,
        "manifest_sha256": ceremony::manifest_hash(&yaml), "ratified": false,
        "note": "allowlist changed — re-ratify in the Manifest tab",
    }))
    .into_response()
}

/// POST /api/agents/{npub}/connectors/{kind}/caps {"caps": {...}} — merge
/// keys into a grant's caps (e.g. {"write": true} on a vault grant). An
/// amendment: re-ratify afterward. Governor.
pub async fn connector_patch_caps(
    State(state): State<App>,
    AxPath((npub, kind)): AxPath<(String, String)>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (_ks, npub, dir, raw, mut manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let body: serde_json::Value = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let Some(patch) = body["caps"].as_object() else {
        return err(StatusCode::BAD_REQUEST, "caps object required").into_response();
    };
    let Some(c) = manifest.connectors.iter_mut().find(|c| c.kind == kind) else {
        return err(
            StatusCode::NOT_FOUND,
            format!("agent has no '{kind}' connector"),
        )
        .into_response();
    };
    for (k, v) in patch {
        c.caps.insert(k.clone(), v.clone());
    }
    let caps_now = c.caps.clone();
    let yaml = match serde_yaml::to_string(&manifest) {
        Ok(y) => y,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    if let Err(error) = persist_manifest(&dir, &raw, &yaml) {
        return error.into_response();
    }
    Json(json!({
        "ok": true, "npub": npub, "kind": kind, "caps": caps_now,
        "manifest_sha256": ceremony::manifest_hash(&yaml), "ratified": false,
        "note": "caps changed — re-ratify in the Manifest tab",
    }))
    .into_response()
}

pub async fn connectors_put(
    State(state): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let pq = uri
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| uri.path().to_string());
    let signer = match nip98::check(&state, &headers, "PUT", &pq, Some(&raw_body)) {
        Ok(sig) => sig,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = nip98::authorize_admin(&state, signer) {
        return e.into_response();
    }
    let body: LibraryBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let mut seen = std::collections::HashSet::new();
    for e2 in &body.library {
        if e2.name.trim().is_empty() {
            return err(StatusCode::BAD_REQUEST, "library entry with empty name").into_response();
        }
        if !seen.insert(e2.name.clone()) {
            return err(
                StatusCode::BAD_REQUEST,
                format!("duplicate library name '{}'", e2.name),
            )
            .into_response();
        }
        if !apiary_runtime::connector::BOUND_KINDS.contains(&e2.kind.as_str()) {
            return err(
                StatusCode::BAD_REQUEST,
                format!(
                    "kind '{}' is not bindable by this host (host binds: {})",
                    e2.kind,
                    apiary_runtime::connector::BOUND_KINDS.join(", ")
                ),
            )
            .into_response();
        }
    }
    let lib = ConnectorLibrary {
        connectors: body.library,
    };
    let yaml = match serde_yaml::to_string(&lib) {
        Ok(y) => y,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    if let Err(e) = std::fs::write(library_path(&state), yaml) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
    }
    Json(json!({"ok": true, "count": lib.connectors.len()})).into_response()
}

#[derive(serde::Deserialize)]
pub struct GrantBody {
    /// Library entry name to grant.
    name: String,
    /// Optional secret to seal to THIS agent (API key etc.). Never stored
    /// anywhere else — the sealed blob lands in the manifest.
    #[serde(default)]
    credential: Option<String>,
}

pub async fn connector_grant(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (ks, npub, dir, raw, mut manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let body: GrantBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let lib = match load_library(&state) {
        Ok(l) => l,
        Err(e) => return e.into_response(),
    };
    let Some(entry) = lib.connectors.iter().find(|c| c.name == body.name) else {
        return err(
            StatusCode::NOT_FOUND,
            format!("no library entry named '{}'", body.name),
        )
        .into_response();
    };
    // Seal the credential to THIS agent, if one was provided.
    let credential = match body.credential.as_deref().filter(|c| !c.is_empty()) {
        None => None,
        Some(secret) => {
            let pass = match require_pass(&state) {
                Ok(p) => p,
                Err(e) => return e.into_response(),
            };
            let npub2 = npub.clone();
            let secret = secret.to_string();
            let sealed = tokio::task::spawn_blocking(move || {
                let (custody, handle) = admit(&ks, &npub2, &pass)?;
                custody
                    .seal(&handle, secret.trim_end())
                    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))
            })
            .await
            .unwrap_or_else(|e| Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)));
            match sealed {
                Ok(blob) => Some(blob),
                Err(e) => return e.into_response(),
            }
        }
    };
    match write_grant(&dir, &raw, &mut manifest, entry, credential) {
        Ok(sha) => Json(json!({
            "ok": true,
            "npub": npub,
            "granted": entry.name,
            "kind": entry.kind,
            "manifest_sha256": sha,
            "ratified": false,
            "note": "grant written to the manifest — a capability change is an amendment; re-ratify before the agent runs again",
        }))
        .into_response(),
        Err(e) => e.into_response(),
    }
}

/// Upsert a library entry into a manifest (one entry per kind) and persist.
fn write_grant(
    dir: &std::path::Path,
    expected_raw: &str,
    manifest: &mut apiary_core::manifest::Manifest,
    entry: &LibraryEntry,
    credential: Option<apiary_core::manifest::EncryptedBlob>,
) -> Result<String, Resp> {
    manifest.connectors.retain(|c| c.kind != entry.kind);
    let mut caps = entry.caps.clone();
    // Library-only provenance helps the cockpit explain a curated template,
    // but is not an agent capability and should not travel in its manifest.
    caps.remove("catalog_id");
    caps.insert("library_name".into(), json!(entry.name));
    manifest.connectors.push(apiary_core::manifest::Connector {
        kind: entry.kind.clone(),
        credential,
        caps,
    });
    let yaml =
        serde_yaml::to_string(manifest).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    persist_manifest(dir, expected_raw, &yaml)
}

pub async fn connector_revoke(
    State(state): State<App>,
    AxPath((npub, kind)): AxPath<(String, String)>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (_ks, npub, dir, raw, mut manifest) =
        match gate(&state, &headers, "DELETE", &uri, None, &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let before = manifest.connectors.len();
    manifest.connectors.retain(|c| c.kind != kind);
    if manifest.connectors.len() == before {
        return err(
            StatusCode::NOT_FOUND,
            format!("agent has no '{kind}' connector"),
        )
        .into_response();
    }
    let yaml = match serde_yaml::to_string(&manifest) {
        Ok(y) => y,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    if let Err(error) = persist_manifest(&dir, &raw, &yaml) {
        return error.into_response();
    }
    Json(json!({
        "ok": true,
        "npub": npub,
        "revoked": kind,
        "manifest_sha256": ceremony::manifest_hash(&yaml),
        "ratified": false,
        "note": "revocation is an amendment too — re-ratify. Until then the agent cannot run at all.",
    }))
    .into_response()
}

// ---------------------------------------------------------------- rename

#[derive(serde::Deserialize)]
pub struct RenameBody {
    name: String,
}

/// Rename the host-local label. The identity is the keypair — the name is
/// for humans. The Buzz display name (kind-0 profile) is separate and
/// published from the Buzz tab; the mention trigger defaults to the new
/// name the next time the listener starts.
pub async fn rename_agent(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (_ks, npub, dir, _raw, _m) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let body: RenameBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let name = body.name.trim();
    if name.is_empty() || name.len() > 60 {
        return err(StatusCode::BAD_REQUEST, "name must be 1–60 characters").into_response();
    }
    if let Err(e) = std::fs::write(dir.join("name"), name) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
    }
    Json(json!({
        "ok": true,
        "npub": npub,
        "name": name,
        "note": "label renamed — the Buzz display name (kind-0 profile) and a running listener's trigger update separately",
    }))
    .into_response()
}

// ---------------------------------------------------------------- oauth

/// An OAuth grant in flight: everything recorded BEFORE the browser
/// redirect that the callback must verify against (PKCE verifier, expected
/// issuer per RFC 9207, and which agent/library entry this authorizes).
#[derive(Clone)]
pub struct PendingOauth {
    pub npub: String,
    pub entry: LibraryEntry,
    pub verifier: String,
    pub issuer: String,
    pub iss_advertised: bool,
    pub token_endpoint: String,
    pub client_id: String,
    pub resource: String,
    pub created_at: u64,
}

struct OauthDiscovery {
    issuer: String,
    iss_advertised: bool,
    authorization_endpoint: String,
    token_endpoint: String,
    registration_endpoint: Option<String>,
    scopes: Vec<String>,
}

fn rand_hex() -> String {
    apiary_core::identity::generate()
        .secret_key()
        .to_secret_hex()
}

fn http_get_json(client: &reqwest::blocking::Client, url: &str) -> Option<serde_json::Value> {
    client
        .get(url)
        .header("accept", "application/json")
        .send()
        .ok()
        .filter(|r| r.status().is_success())
        .and_then(|r| r.json().ok())
}

/// RFC 9728 protected-resource metadata → RFC 8414 / OIDC discovery.
fn discover(resource_url: &str) -> Result<OauthDiscovery, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())?;
    let parsed = reqwest::Url::parse(resource_url).map_err(|e| format!("caps.url: {e}"))?;
    let origin = format!(
        "{}://{}{}",
        parsed.scheme(),
        parsed.host_str().unwrap_or_default(),
        parsed.port().map(|p| format!(":{p}")).unwrap_or_default()
    );
    let path = parsed.path().trim_end_matches('/');
    // Path-aware well-known first (RFC 9728 §3.1), then root.
    let prm = http_get_json(
        &client,
        &format!("{origin}/.well-known/oauth-protected-resource{path}"),
    )
    .or_else(|| {
        http_get_json(
            &client,
            &format!("{origin}/.well-known/oauth-protected-resource"),
        )
    })
    .ok_or("server publishes no OAuth protected-resource metadata (RFC 9728)")?;
    let auth_server = prm["authorization_servers"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .ok_or("protected-resource metadata lists no authorization_servers")?
        .trim_end_matches('/')
        .to_string();
    let scopes: Vec<String> = prm["scopes_supported"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let as_parsed = reqwest::Url::parse(&auth_server).map_err(|e| e.to_string())?;
    let as_origin = format!(
        "{}://{}{}",
        as_parsed.scheme(),
        as_parsed.host_str().unwrap_or_default(),
        as_parsed
            .port()
            .map(|p| format!(":{p}"))
            .unwrap_or_default()
    );
    let as_path = as_parsed.path().trim_end_matches('/');
    let meta = http_get_json(
        &client,
        &format!("{as_origin}/.well-known/oauth-authorization-server{as_path}"),
    )
    .or_else(|| {
        http_get_json(
            &client,
            &format!("{as_origin}/.well-known/oauth-authorization-server"),
        )
    })
    .or_else(|| {
        http_get_json(
            &client,
            &format!("{auth_server}/.well-known/openid-configuration"),
        )
    })
    .ok_or("authorization server publishes no metadata (RFC 8414 / OIDC discovery)")?;
    let issuer = meta["issuer"].as_str().unwrap_or(&auth_server).to_string();
    let iss_advertised = meta["authorization_response_iss_parameter_supported"]
        .as_bool()
        .unwrap_or(false);
    let authorization_endpoint = meta["authorization_endpoint"]
        .as_str()
        .ok_or("AS metadata has no authorization_endpoint")?
        .to_string();
    let token_endpoint = meta["token_endpoint"]
        .as_str()
        .ok_or("AS metadata has no token_endpoint")?
        .to_string();
    Ok(OauthDiscovery {
        issuer,
        iss_advertised,
        authorization_endpoint,
        token_endpoint,
        registration_endpoint: meta["registration_endpoint"].as_str().map(String::from),
        scopes,
    })
}

/// Register Apiary as a public OAuth client when an MCP authorization
/// server still advertises RFC 7591 DCR. The 2026 MCP spec prefers Client
/// ID Metadata Documents, but keeps DCR for compatibility; a user should
/// not have to create and paste a client id when the server explicitly
/// offers registration.
fn register_oauth_client(
    registration_endpoint: &str,
    redirect_uri: &str,
    scope: &str,
) -> Result<String, String> {
    let endpoint = reqwest::Url::parse(registration_endpoint)
        .map_err(|e| format!("registration_endpoint: {e}"))?;
    if endpoint.scheme() != "https" {
        return Err("OAuth registration_endpoint must use HTTPS".into());
    }
    let redirect =
        reqwest::Url::parse(redirect_uri).map_err(|e| format!("OAuth redirect URI: {e}"))?;
    let loopback = matches!(redirect.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    let application_type = if loopback { "native" } else { "web" };
    let mut body = json!({
        "client_name": "Apiary",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "application_type": application_type
    });
    if !scope.is_empty() {
        body["scope"] = json!(scope);
    }
    let response = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())?
        .post(endpoint)
        .header("accept", "application/json")
        .json(&body)
        .send()
        .map_err(|e| format!("OAuth client registration: {e}"))?;
    let status = response.status();
    let value: serde_json::Value = response
        .json()
        .map_err(|e| format!("OAuth client registration response: {e}"))?;
    if !status.is_success() {
        return Err(format!(
            "OAuth client registration refused ({status}): {value}"
        ));
    }
    value["client_id"]
        .as_str()
        .filter(|id| !id.trim().is_empty())
        .map(String::from)
        .ok_or_else(|| "OAuth client registration returned no client_id".into())
}

#[derive(serde::Deserialize)]
pub struct OauthStartBody {
    /// Library entry name (kind must be mcp, caps.url + caps.oauth_client_id).
    name: String,
}

pub async fn oauth_start(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (_ks, npub, _dir, _raw, _m) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let body: OauthStartBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    if state.passphrase_clone().is_none() {
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "unlock the keystore first — the tokens must be sealed to the agent at grant time",
        )
        .into_response();
    }
    let lib = match load_library(&state) {
        Ok(l) => l,
        Err(e) => return e.into_response(),
    };
    let Some(entry) = lib.connectors.iter().find(|c| c.name == body.name).cloned() else {
        return err(
            StatusCode::NOT_FOUND,
            format!("no library entry '{}'", body.name),
        )
        .into_response();
    };
    let cap = |k: &str| entry.caps.get(k).and_then(|v| v.as_str()).map(String::from);
    let Some(resource_url) = cap("url") else {
        return err(StatusCode::BAD_REQUEST, "entry has no caps.url").into_response();
    };
    let configured_client_id = cap("oauth_client_id");
    let scope_override = cap("oauth_scopes");
    let resource_url2 = resource_url.clone();
    let discovered = tokio::task::spawn_blocking(move || discover(&resource_url2)).await;
    let discovered = match discovered {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return err(StatusCode::BAD_GATEWAY, e).into_response(),
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    let verifier = format!("{}{}", rand_hex(), rand_hex());
    let challenge = {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(verifier.as_bytes()))
    };
    let oauth_state = rand_hex();
    let redirect_uri = format!("{}/oauth/callback", state.origin);
    let scope = scope_override.unwrap_or_else(|| discovered.scopes.join(" "));
    let client_id = match configured_client_id {
        Some(id) => id,
        None => match discovered.registration_endpoint.as_deref() {
            Some(endpoint) => {
                let endpoint = endpoint.to_string();
                let redirect = redirect_uri.clone();
                let scope = scope.clone();
                match tokio::task::spawn_blocking(move || {
                    register_oauth_client(&endpoint, &redirect, &scope)
                })
                .await
                {
                    Ok(Ok(id)) => id,
                    Ok(Err(e)) => return err(StatusCode::BAD_GATEWAY, e).into_response(),
                    Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
                }
            }
            None => {
                return err(
                    StatusCode::BAD_REQUEST,
                    "the OAuth server offers neither automatic client registration nor a client id; enter its pre-registered client id",
                )
                .into_response()
            }
        },
    };
    let mut params = vec![
        ("response_type", "code".to_string()),
        ("client_id", client_id.clone()),
        ("redirect_uri", redirect_uri.clone()),
        ("state", oauth_state.clone()),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256".to_string()),
        ("resource", resource_url.clone()),
    ];
    if !scope.is_empty() {
        params.push(("scope", scope));
    }
    let auth_url =
        match reqwest::Url::parse_with_params(&discovered.authorization_endpoint, &params) {
            Ok(u) => u.to_string(),
            Err(e) => {
                return err(
                    StatusCode::BAD_GATEWAY,
                    format!("authorization_endpoint: {e}"),
                )
                .into_response()
            }
        };
    state
        .pending_oauth
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(
            oauth_state.clone(),
            PendingOauth {
                npub,
                entry,
                verifier,
                issuer: discovered.issuer,
                iss_advertised: discovered.iss_advertised,
                token_endpoint: discovered.token_endpoint,
                client_id,
                resource: resource_url,
                created_at: now_secs(),
            },
        );
    Json(json!({
        "ok": true,
        "auth_url": auth_url,
        "state": oauth_state,
        "note": "authorize in the browser; the callback grants the connector with tokens sealed to the agent",
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
pub struct CallbackQuery {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

/// HTML-escape untrusted text for the callback page. The authorization
/// server (and its error strings) are NOT ours — a malicious AS returning
/// markup with a valid state must render as text, never execute.
fn html_escape(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#39;".to_string(),
            c => c.to_string(),
        })
        .collect()
}

fn callback_page(title: &str, detail: &str) -> impl IntoResponse {
    let title = html_escape(title);
    let detail = html_escape(detail);
    (
        [(
            "content-security-policy",
            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'",
        )],
        axum::response::Html(format!(
            "<!doctype html><meta charset=utf-8><title>Apiary</title>\
             <body style=\"background:#14120e;color:#e8e0cf;font:16px ui-monospace,monospace;\
             display:flex;align-items:center;justify-content:center;height:100vh\">\
             <div style=\"max-width:60ch\"><h2 style=\"color:#e8b04b\">{title}</h2><p>{detail}</p></div>"
        )),
    )
}

/// The browser lands here after consent. Public route (no host token — the
/// browser doesn't have it); the `state` parameter is the correlation and
/// the PKCE verifier never left this process.
pub async fn oauth_callback(
    State(state): State<App>,
    Query(q): Query<CallbackQuery>,
) -> impl IntoResponse {
    let Some(st) = q.state.clone() else {
        return callback_page("Missing state", "This callback carries no state parameter.");
    };
    let pending = {
        let mut grants = state
            .pending_oauth
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let cutoff = now_secs().saturating_sub(15 * 60);
        grants.retain(|_, grant| grant.created_at > cutoff);
        grants.get(&st).cloned()
    };
    let Some(pending) = pending else {
        return callback_page(
            "Unknown or expired grant",
            "No OAuth grant is waiting for this state. Start again from the Connectors tab.",
        );
    };
    if q.error.is_some() {
        // RFC 9207: on iss mismatch we must not even display the error.
        let iss_ok = match &q.iss {
            Some(i) => *i == pending.issuer,
            None => !pending.iss_advertised,
        };
        state
            .pending_oauth
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&st);
        return if iss_ok {
            callback_page(
                "Authorization refused",
                &format!(
                    "{} — {}",
                    q.error.as_deref().unwrap_or("error"),
                    q.error_description.as_deref().unwrap_or("no description")
                ),
            )
        } else {
            callback_page(
                "Authorization response rejected",
                "Issuer mismatch (RFC 9207).",
            )
        };
    }
    // RFC 9207 validation matrix before the code touches any token endpoint.
    match (&q.iss, pending.iss_advertised) {
        (Some(i), _) if *i != pending.issuer => {
            return callback_page(
                "Authorization response rejected",
                "The iss parameter does not match the discovered issuer (RFC 9207).",
            )
        }
        (None, true) => {
            return callback_page(
                "Authorization response rejected",
                "The authorization server advertises iss support but sent none (RFC 9207).",
            )
        }
        _ => {}
    }
    let Some(code) = q.code else {
        return callback_page(
            "Missing code",
            "The authorization response carries no code.",
        );
    };
    let Some(pass) = state.passphrase_clone() else {
        return callback_page("Keystore locked", "Unlock Apiary and grant again.");
    };
    let redirect_uri = format!("{}/oauth/callback", state.origin);
    let home = state.home.clone();
    let outcome = tokio::task::spawn_blocking(move || -> Result<String, String> {
        let form = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", pending.client_id.clone()),
            ("code_verifier", pending.verifier.clone()),
            ("resource", pending.resource.clone()),
        ];
        let resp = reqwest::blocking::Client::new()
            .post(&pending.token_endpoint)
            .form(&form)
            .send()
            .map_err(|e| format!("token endpoint: {e}"))?;
        let status = resp.status();
        let tokens: serde_json::Value = resp.json().map_err(|e| format!("token body: {e}"))?;
        if !status.is_success() {
            return Err(format!("token endpoint refused the grant ({status})"));
        }
        let access = tokens["access_token"]
            .as_str()
            .ok_or_else(|| "token endpoint returned no access token".to_string())?;
        let credential = json!({
            "type": "oauth",
            "access_token": access,
            "refresh_token": tokens.get("refresh_token").and_then(|v| v.as_str()),
            "token_endpoint": pending.token_endpoint,
            "client_id": pending.client_id,
            "issuer": pending.issuer,
            "resource": pending.resource,
            "obtained_at": now_secs(),
            "expires_in": tokens.get("expires_in").and_then(|v| v.as_u64()),
        })
        .to_string();
        // Seal to the agent, write the grant.
        let ks = Keystore::open(&home).map_err(|e| e.to_string())?;
        let keys = ks.load(&pending.npub, &pass).map_err(|e| e.to_string())?;
        let mut custody = Custody::new();
        let handle = custody.admit(keys);
        let blob = custody
            .seal(&handle, &credential)
            .map_err(|e| e.to_string())?;
        let dir = ks.agent_dir(&pending.npub);
        let raw = std::fs::read_to_string(dir.join("manifest.yaml")).map_err(|e| e.to_string())?;
        let mut manifest =
            apiary_core::manifest::Manifest::from_yaml(&raw).map_err(|e| e.to_string())?;
        write_grant(&dir, &raw, &mut manifest, &pending.entry, Some(blob))
            .map_err(|(_, j)| j.0.to_string())?;
        Ok(pending.entry.name.clone())
    })
    .await
    .unwrap_or_else(|e| Err(e.to_string()));
    match outcome {
        Ok(name) => {
            state
                .pending_oauth
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .remove(&st);
            callback_page(
                "Connector granted",
                &format!(
                    "'{name}' is authorized and its tokens are sealed to the agent. \
                     Return to Apiary and re-ratify the manifest — nothing runs unratified."
                ),
            )
        }
        Err(e) => callback_page("Grant failed", &e),
    }
}

// ---------------------------------------------------------------- lease

pub async fn lease_status(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (_ks, npub, _dir, _raw, manifest) = match gate(&state, &headers, "GET", &uri, None, &npub) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let relays = manifest.memory.log_relays.clone();
    let host = apiary_runtime::lease::host_id(&state.home);
    if relays.is_empty() {
        return Json(json!({
            "ok": true,
            "npub": npub,
            "mechanism": "relay-event",
            "coordinated": false,
            "host_id": host,
            "note": "no memory.log_relays declared — presence runs without cross-host coordination",
        }))
        .into_response();
    }
    let agent_hex = match apiary_core::identity::parse_npub(&npub) {
        Ok(pk) => pk.to_hex(),
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let configuration =
        serde_json::to_string(&json!({"relays": relays, "host": host})).unwrap_or_default();
    let key = format!("lease:{npub}");
    let state_for_view = state.clone();
    let npub_for_view = npub.clone();
    let host_for_view = host.clone();
    let view = tokio::task::spawn_blocking(move || {
        state_for_view.decisions.observation(
            &key,
            &configuration,
            std::time::Duration::from_secs(10),
            || match apiary_runtime::lease::fetch(&relays, &agent_hex) {
                Some(lease) => {
                    let expired = lease.expired(now_secs());
                    json!({
                        "ok": true,
                        "npub": npub_for_view,
                        "mechanism": "relay-event",
                        "coordinated": true,
                        "host_id": host_for_view,
                        "lease": {
                            "holder": lease.host,
                            "ours": lease.host == host_for_view,
                            "seq": lease.seq,
                            "expires_at": lease.expires_at,
                            "expired": expired,
                        },
                    })
                }
                None => json!({
                    "ok": true,
                    "npub": npub_for_view,
                    "mechanism": "relay-event",
                    "coordinated": true,
                    "host_id": host_for_view,
                    "lease": null,
                }),
            },
        )
    })
    .await
    .unwrap_or_else(|_| {
        json!({
                "ok": true,
                "npub": npub,
                "mechanism": "relay-event",
                "coordinated": true,
                "host_id": host,
                "lease": null,
        })
    });
    Json(view).into_response()
}

/// The human decision "contested-human" defers to: supersede a live foreign
/// lease. The losing host yields at its next heartbeat; until then, up to
/// one heartbeat interval of overlap is inherent to lease coordination.
pub async fn lease_takeover(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (ks, npub, _dir, _raw, manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let relays = manifest.memory.log_relays.clone();
    if relays.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "no memory.log_relays — nothing to take over",
        )
        .into_response();
    }
    let pass = match require_pass(&state) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let host = apiary_runtime::lease::host_id(&state.home);
    let expiry = manifest.lease.expiry_secs.max(20);
    let agent_hex = match apiary_core::identity::parse_npub(&npub) {
        Ok(pk) => pk.to_hex(),
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let npub2 = npub.clone();
    let host2 = host.clone();
    let out = tokio::task::spawn_blocking(move || -> Result<u64, Resp> {
        let (custody, handle) = admit(&ks, &npub2, &pass)?;
        apiary_runtime::lease::takeover(&custody, &handle, &relays, &agent_hex, &host2, expiry)
            .map_err(|e| err(StatusCode::BAD_GATEWAY, e))
    })
    .await
    .unwrap_or_else(|e| Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)));
    match out {
        Ok(seq) => {
            // Clear any contested note so the supervisor retries promptly.
            state
                .supervisor_notes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&npub);
            Json(json!({
                "ok": true,
                "npub": npub,
                "host_id": host,
                "seq": seq,
                "note": "lease taken — this host's supervisor starts the listener within a tick; the previous host yields at its next heartbeat",
            }))
            .into_response()
        }
        Err(e) => e.into_response(),
    }
}

// ---------------------------------------------------------------- portability

/// Filesystem-safe slug for export filenames: the host-local name is
/// user-controlled text, never a path. Anything outside [A-Za-z0-9_-]
/// drops; empty falls back to the npub prefix.
fn export_slug(name: &str, npub: &str) -> String {
    let slug: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(40)
        .collect();
    if slug.is_empty() {
        npub.chars().take(16).collect()
    } else {
        slug
    }
}

/// Export the agent to a bundle file under <home>/exports/. The key inside
/// stays NIP-49-locked; the passphrase travels human-to-human.
#[derive(serde::Deserialize, Default)]
pub struct ExportBody {
    /// Re-encrypt the traveling key under this handoff secret (the host
    /// keystore passphrase never travels). Empty/absent = verbatim copy.
    #[serde(default)]
    export_passphrase: Option<String>,
    /// Seal the whole bundle to this recipient key (npub or hex) as a
    /// signed kind-4602 envelope. Mutually exclusive with the passphrase.
    #[serde(default)]
    to_npub: Option<String>,
}

pub async fn export_agent(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (_ks, npub, dir, _raw, _m) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let body: ExportBody = serde_json::from_slice(&raw_body).unwrap_or_default();
    let export_pass = body.export_passphrase.filter(|p| !p.is_empty());
    let to_npub = body.to_npub.filter(|p| !p.is_empty());
    if export_pass.is_some() && to_npub.is_some() {
        return err(
            StatusCode::BAD_REQUEST,
            "choose ONE: a handoff passphrase or a recipient npub, not both",
        )
        .into_response();
    }
    if let Some(recipient) = &to_npub {
        let recipient_pk = match apiary_core::identity::parse_npub(recipient) {
            Ok(pk) => pk,
            Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
        };
        let Some(session_pass) = state.passphrase_clone() else {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "unlock the keystore first — sealing signs with the agent's key",
            )
            .into_response();
        };
        let dir2 = dir.clone();
        let npub2 = npub.clone();
        let sealed = tokio::task::spawn_blocking(move || {
            apiary_core::portability::seal(&dir2, &npub2, &session_pass, &recipient_pk)
        })
        .await
        .unwrap_or_else(|e| Err(apiary_core::Error::Keystore(e.to_string())));
        let envelope = match sealed {
            Ok(v) => v,
            Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
        };
        let exports = state.home.join("exports");
        if let Err(e) = std::fs::create_dir_all(&exports) {
            return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
        }
        let name = std::fs::read_to_string(dir.join("name"))
            .unwrap_or_default()
            .trim()
            .to_string();
        let file = exports.join(format!(
            "{}-{}.apiary-sealed.json",
            export_slug(&name, &npub),
            now_secs()
        ));
        if let Err(e) = std::fs::write(
            &file,
            serde_json::to_string_pretty(&envelope).unwrap_or_default(),
        ) {
            return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600));
        }
        return Json(json!({
            "ok": true,
            "npub": npub,
            "path": file.display().to_string(),
            "sealed_to": recipient,
            "note": "sealed kind-4602 envelope — only that key can open it; the whole bundle is signed by the agent, so any tampering or truncation is detectable. Safe to send over any channel.",
        }))
        .into_response();
    }
    let bundle = match &export_pass {
        Some(ep) => {
            let Some(session_pass) = state.passphrase_clone() else {
                return err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "unlock the keystore first — re-encrypting the key needs it open",
                )
                .into_response();
            };
            let dir2 = dir.clone();
            let npub2 = npub.clone();
            let ep2 = ep.clone();
            match tokio::task::spawn_blocking(move || {
                apiary_core::portability::export_with_passphrase(
                    &dir2,
                    &npub2,
                    Some((&session_pass, &ep2)),
                )
            })
            .await
            {
                Ok(Ok(b)) => b,
                Ok(Err(e)) => return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
                Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
            }
        }
        None => match apiary_core::portability::export(&dir, &npub) {
            Ok(b) => b,
            Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
        },
    };
    let name = std::fs::read_to_string(dir.join("name"))
        .unwrap_or_default()
        .trim()
        .to_string();
    let exports = state.home.join("exports");
    if let Err(e) = std::fs::create_dir_all(&exports) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
    }
    let file = exports.join(format!(
        "{}-{}.apiary.json",
        export_slug(&name, &npub),
        now_secs()
    ));
    let pretty = serde_json::to_string_pretty(&bundle).unwrap_or_default();
    if let Err(e) = std::fs::write(&file, pretty) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600));
    }
    Json(json!({
        "ok": true,
        "npub": npub,
        "path": file.display().to_string(),
        "log_entries": bundle["log"].as_array().map(|a| a.len()).unwrap_or(0),
        "index_rows": bundle["index_jsonl"].as_str().map(|s| s.lines().count()).unwrap_or(0),
        "handoff_passphrase": export_pass.is_some(),
        "note": if export_pass.is_some() {
            "key re-encrypted under the handoff passphrase — share it out of band, never alongside the file; your keystore passphrase did not travel"
        } else {
            "key still locked with THIS keystore's passphrase — for handing to someone else, use a handoff passphrase instead"
        },
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
pub struct ImportBody {
    bundle: serde_json::Value,
    /// The sender's export passphrase, when the bundle was re-encrypted
    /// for handoff. Absent = the bundle uses this keystore's passphrase.
    #[serde(default)]
    bundle_passphrase: Option<String>,
    /// For sealed envelopes: which keystore-held key receives (default:
    /// the envelope's p tag, if that key is held here).
    #[serde(default)]
    as_npub: Option<String>,
}

pub async fn import_agent(
    State(state): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let pq = uri
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| uri.path().to_string());
    let signer = match nip98::check(&state, &headers, "POST", &pq, Some(&raw_body)) {
        Ok(sig) => sig,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = nip98::authorize_admin(&state, signer) {
        return e.into_response();
    }
    let body: ImportBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let pass = match require_pass(&state) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let home = state.home.clone();
    let out = tokio::task::spawn_blocking(move || {
        let ks = Keystore::open(&home).map_err(|e| e.to_string())?;
        apiary_core::portability::import_any(
            &ks,
            &body.bundle,
            body.bundle_passphrase.as_deref().filter(|p| !p.is_empty()),
            &pass,
            body.as_npub.as_deref().filter(|p| !p.is_empty()),
        )
        .map_err(|e| e.to_string())
    })
    .await
    .unwrap_or_else(|e| Err(e.to_string()));
    match out {
        Ok(r) => Json(json!({
            "ok": true,
            "npub": r.npub,
            "name": r.name,
            "log_entries": r.log_entries,
            "ratified": r.ratified,
            "index_rows": r.index_rows,
            "index_dropped": r.index_dropped,
            "note": "imported INACTIVE — activate in Overview to run standing presence; the lease referees any host overlap",
        }))
        .into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, e).into_response(),
    }
}

// ============================================================ presence

/// One running channel thread for one agent.
pub struct ChannelHandle {
    pub stop: Arc<AtomicBool>,
    pub done: Arc<AtomicBool>,
    pub started_at: u64,
    pub lines: Arc<Mutex<VecDeque<String>>>,
}

/// The per-agent lease keeper thread: one lease spans every channel.
pub struct KeeperHandle {
    pub stop: Arc<AtomicBool>,
    pub done: Arc<AtomicBool>,
    pub lost: Arc<AtomicBool>,
    pub lines: Arc<Mutex<VecDeque<String>>>,
}

/// Everything the host is running for one agent's standing presence.
#[derive(Default)]
pub struct AgentPresence {
    /// Manifest hash the presence started under — a diverging disk hash
    /// bounces every channel (amendment-bounce, now agent-wide).
    pub manifest_sha: String,
    pub keeper: Option<KeeperHandle>,
    pub channels: std::collections::HashMap<String, ChannelHandle>,
    /// Threads from the previous manifest generation. A replacement must not
    /// start until these have left their in-flight channel/model calls, or two
    /// Telegram long polls can claim the same update.
    pub retiring: Vec<Arc<AtomicBool>>,
}

fn stop_channels(p: &mut AgentPresence) {
    for (_, ch) in p.channels.drain() {
        ch.stop.store(true, Ordering::Relaxed);
        p.retiring.push(ch.done);
    }
}

fn stop_all(p: &mut AgentPresence) {
    stop_channels(p);
    if let Some(k) = p.keeper.take() {
        k.stop.store(true, Ordering::Relaxed);
        p.retiring.push(k.done);
    }
}

/// The channel kinds this host can start for a manifest entry: built-ins
/// plus installed Channel Plugin Protocol plugins.
pub fn available_kinds(state: &AppState) -> Vec<String> {
    let mut kinds: Vec<String> = apiary_runtime::presence::PRESENCE_KINDS
        .iter()
        .map(|s| s.to_string())
        .collect();
    if let Ok(reg) = apiary_runtime::plugin::load_registry(&state.home) {
        for p in reg.plugins {
            if !kinds.contains(&p.name) {
                kinds.push(p.name);
            }
        }
    }
    kinds
}

/// Spawn one channel thread. All slow work (scrypt key load, network
/// connects) happens inside the thread; failures land in the ring buffer
/// and flip `done` so the supervisor can reap, note, and back off.
#[allow(clippy::too_many_arguments)]
fn spawn_channel(
    state: &App,
    npub: &str,
    kind: &str,
    dir: std::path::PathBuf,
    manifest: apiary_core::manifest::Manifest,
    keeper_lost: Option<Arc<AtomicBool>>,
) -> Result<ChannelHandle, String> {
    let entry = manifest
        .presence
        .channel(kind)
        .cloned()
        .ok_or_else(|| format!("manifest declares no presence.{kind}"))?;
    if state.passphrase_clone().is_none() {
        return Err("keystore is locked — unlock first".into());
    }
    let state = state.clone();
    let npub = npub.to_string();
    let kind = kind.to_string();
    let stop = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let lines = Arc::new(Mutex::new(VecDeque::new()));
    let handle = ChannelHandle {
        stop: stop.clone(),
        done: done.clone(),
        started_at: now_secs(),
        lines: lines.clone(),
    };
    // Installed plugin specs resolve outside the thread (cheap, fallible
    // in a way the caller should see immediately).
    let plugin_spec = if apiary_runtime::presence::PRESENCE_KINDS.contains(&kind.as_str()) {
        None
    } else {
        let reg = apiary_runtime::plugin::load_registry(&state.home).map_err(|e| e.to_string())?;
        Some(
            reg.plugins
                .into_iter()
                .find(|p| p.name == kind)
                .ok_or_else(|| {
                    format!("presence.{kind} declared but no such plugin is installed")
                })?,
        )
    };
    std::thread::spawn(move || {
        let fail = |lines: &Mutex<VecDeque<String>>, done: &AtomicBool, msg: String| {
            push_line(lines, msg);
            done.store(true, Ordering::Relaxed);
        };
        let ks = match Keystore::open(&state.home) {
            Ok(k) => k,
            Err(e) => return fail(&lines, &done, format!("keystore: {e}")),
        };
        let (custody, agent_handle) = match crate::admit_agent(&state, &ks, &npub) {
            Ok(v) => v,
            Err(error) => return fail(&lines, &done, format!("channel died: {error}")),
        };
        let name = std::fs::read_to_string(dir.join("name"))
            .unwrap_or_default()
            .trim()
            .to_string();
        // Open the sealed platform credential just-in-time, in-thread.
        let credential_plain = match &entry.credential {
            None => None,
            Some(blob) => match custody.open(&agent_handle, blob) {
                Ok(z) => Some(z.as_str().to_string()),
                Err(e) => return fail(&lines, &done, format!("channel died: credential: {e}")),
            },
        };
        let sink_lines = lines.clone();
        let sink_kind = kind.clone();
        let mut sink = move |l: String| {
            // Failures must be loud in the supervisor log, not only in the
            // GUI ring buffer — a silent refusal cost a live debugging round.
            if l.contains("failed") || l.contains("refused") || l.contains("died") {
                eprintln!("supervisor[{sink_kind}]: {l}");
            }
            push_line(&sink_lines, l);
        };
        let on_tick_lost = keeper_lost.clone();
        let result: Result<(), apiary_runtime::Error> = (|| {
            let mut adapter: Box<dyn apiary_runtime::presence::ChannelAdapter> = match kind.as_str()
            {
                "buzz" => {
                    let relay = entry
                        .str_config("relay")
                        .ok_or_else(|| {
                            apiary_runtime::Error::Provider(
                                "presence.buzz requires config relay".into(),
                            )
                        })?
                        .to_string();
                    let trigger = entry
                        .str_config("trigger")
                        .map(String::from)
                        .unwrap_or_else(|| format!("@{name}"));
                    Box::new(apiary_runtime::buzz::BuzzAdapter::connect_with_cursor(
                        &relay,
                        &custody,
                        &agent_handle,
                        trigger,
                        Some(dir.join("presence").join("buzz-recent.json")),
                    )?)
                }
                "telegram" => {
                    let token = credential_plain.as_deref().ok_or_else(|| {
                        apiary_runtime::Error::Provider(
                            "presence.telegram requires a sealed bot-token credential".into(),
                        )
                    })?;
                    Box::new(apiary_runtime::telegram::TelegramAdapter::connect(
                        token,
                        entry.list_config("allowed_chats"),
                    )?)
                }
                "slack" => {
                    let cred = credential_plain.as_deref().ok_or_else(|| {
                        apiary_runtime::Error::Provider(
                            "presence.slack requires a sealed {app_token, bot_token} credential"
                                .into(),
                        )
                    })?;
                    Box::new(apiary_runtime::slack::SlackAdapter::connect(
                        cred,
                        entry.list_config("allowed_channels"),
                    )?)
                }
                _ => {
                    let spec = plugin_spec.as_ref().expect("resolved before spawn");
                    let config = serde_json::to_value(&entry.config).unwrap_or_default();
                    Box::new(apiary_runtime::plugin::PluginAdapter::connect(
                        spec,
                        &config,
                        credential_plain.as_deref(),
                    )?)
                }
            };
            apiary_runtime::presence::run_presence(
                adapter.as_mut(),
                &manifest,
                &dir,
                &custody,
                &agent_handle,
                &stop,
                || {
                    Ok(on_tick_lost
                        .as_ref()
                        .map(|l| !l.load(Ordering::Relaxed))
                        .unwrap_or(true))
                },
                &mut sink,
            )
        })();
        match result {
            Ok(()) => push_line(&lines, format!("{kind}: channel stopped")),
            Err(e) => push_line(&lines, format!("channel died: {e}")),
        }
        done.store(true, Ordering::Relaxed);
    });
    Ok(handle)
}

fn spawn_keeper(
    state: &App,
    npub: &str,
    manifest: &apiary_core::manifest::Manifest,
) -> Result<Option<KeeperHandle>, String> {
    let relays = manifest.memory.log_relays.clone();
    if relays.is_empty() {
        return Ok(None); // uncoordinated, loudly noted by the caller
    }
    if state.passphrase_clone().is_none() {
        return Err("keystore is locked — unlock first".into());
    }
    let state = state.clone();
    let npub = npub.to_string();
    let heartbeat = manifest.lease.heartbeat_secs;
    let expiry = manifest.lease.expiry_secs;
    let stop = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let lost = Arc::new(AtomicBool::new(false));
    let lines = Arc::new(Mutex::new(VecDeque::new()));
    let handle = KeeperHandle {
        stop: stop.clone(),
        done: done.clone(),
        lost: lost.clone(),
        lines: lines.clone(),
    };
    std::thread::spawn(move || {
        let sink_lines = lines.clone();
        let mut sink = move |l: String| push_line(&sink_lines, l);
        let run = (|| -> Result<(), apiary_runtime::Error> {
            let ks = Keystore::open(&state.home)?;
            let (custody, agent_handle) =
                crate::admit_agent(&state, &ks, &npub).map_err(apiary_runtime::Error::Provider)?;
            let agent_hex = agent_handle.pubkey().to_hex();
            let host = apiary_runtime::lease::host_id(&state.home);
            apiary_runtime::lease::run_keeper(
                &custody,
                &agent_handle,
                &relays,
                &agent_hex,
                &host,
                heartbeat,
                expiry,
                &stop,
                &lost,
                &mut sink,
            )
        })();
        if let Err(e) = run {
            push_line(&lines, format!("lease keeper died: {e}"));
            lost.store(true, Ordering::Relaxed);
        }
        done.store(true, Ordering::Relaxed);
    });
    Ok(Some(handle))
}

pub fn spawn_supervisor(state: App) {
    tokio::spawn(async move {
        let mut backoff: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        loop {
            reconcile(&state, &mut backoff);
            crate::routines::reconcile_routines(&state);
            crate::watches::reconcile_watches(&state);
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }
    });
}

const RETRY_BACKOFF_SECS: u64 = 30;

/// Reconcile desired presence (ACTIVE + declared + ratified + unlocked,
/// lease permitting) with running threads, per (agent, channel). One
/// channel failing never blocks its siblings; the keeper failing stops
/// them all — the lease is agent-wide.
fn reconcile(state: &App, backoff: &mut std::collections::HashMap<String, u64>) {
    let Ok(ks) = Keystore::open(&state.home) else {
        return;
    };
    let Ok(agents) = ks.list() else {
        return;
    };
    let kinds_available = available_kinds(state);
    for npub in agents {
        let dir = ks.agent_dir(&npub);
        let active = is_active(&dir);
        let raw = std::fs::read_to_string(dir.join("manifest.yaml")).unwrap_or_default();
        let disk_sha = ceremony::manifest_hash(&raw);
        let manifest = match apiary_core::manifest::Manifest::from_yaml(&raw) {
            Ok(m) => Some(m),
            Err(e) => {
                // Loud: an unloadable manifest silently stopping the agent
                // is the least legible failure there is.
                state
                    .supervisor_notes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(
                        npub.clone(),
                        format!("manifest does not load — everything is stopped: {e}"),
                    );
                // Once per manifest revision, not once per 10s tick — the
                // note map above keeps it visible in the UI the whole time.
                static NOTED: std::sync::OnceLock<Mutex<std::collections::HashMap<String, String>>> =
                    std::sync::OnceLock::new();
                let mut noted = NOTED
                    .get_or_init(Default::default)
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                if noted.get(&npub) != Some(&disk_sha) {
                    noted.insert(npub.clone(), disk_sha.clone());
                    eprintln!("supervisor: manifest for {npub} does not load: {e}");
                }
                None
            }
        };
        if active {
            if let Some(manifest) = manifest.clone() {
                apiary_runtime::index::schedule_refresh(manifest, dir.clone());
            }
        }
        // Inert MCP connectors (granted, no tools ticked) are legal but
        // surprising — keep a note on the agent card until they're fixed.
        if let Some(m) = manifest.as_ref() {
            let inert: Vec<String> = m
                .connectors
                .iter()
                .filter(|c| c.grants_no_tools())
                .map(|c| {
                    c.caps
                        .get("library_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("mcp")
                        .to_string()
                })
                .collect();
            let mut notes = state
                .supervisor_notes
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let key = format!("{npub}:inert-connectors");
            if inert.is_empty() {
                notes.remove(&key);
            } else {
                notes.insert(
                    key,
                    format!(
                        "connector {} grants no tools yet — Connectors tab → \
                         DISCOVER TOOLS → tick what it may use → APPLY, then ratify",
                        inert.join(", ")
                    ),
                );
            }
        }
        let mut map = state.listeners.lock().unwrap_or_else(|e| e.into_inner());
        let presence = map.entry(npub.clone()).or_default();
        presence
            .retiring
            .retain(|done| !done.load(Ordering::Relaxed));

        // Inactive, unparseable, or amended: everything stops.
        let declared: Vec<String> = manifest
            .as_ref()
            .map(|m| m.presence.channels.keys().cloned().collect())
            .unwrap_or_default();
        // Routine-only agents (no presence, but routines + log_relays) still
        // need the lease keeper — routines fire on exactly one host.
        let has_routines = manifest
            .as_ref()
            .map(|m| !m.routines.is_empty() && !m.memory.log_relays.is_empty())
            .unwrap_or(false);
        if !active || manifest.is_none() || (declared.is_empty() && !has_routines) {
            stop_all(presence);
            presence
                .retiring
                .retain(|done| !done.load(Ordering::Relaxed));
            if presence.retiring.is_empty() {
                map.remove(&npub);
            }
            continue;
        }
        if !presence.channels.is_empty() && presence.manifest_sha != disk_sha {
            eprintln!("supervisor: manifest changed for {npub} — bouncing all channels");
            stop_all(presence);
            presence.manifest_sha.clear();
            continue; // restart next tick, ratification permitting
        }
        if !presence.retiring.is_empty() {
            continue; // never overlap two generations of a channel adapter
        }
        let manifest = manifest.expect("checked above");

        // Ratification gates everything (checked only when we may start).
        let needs_start = presence.keeper.is_none()
            || declared.iter().any(|k| !presence.channels.contains_key(k));
        if needs_start {
            if !crate::agent_decision(state, &dir, &npub, &raw, &manifest).ratified {
                state
                    .supervisor_notes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(
                        npub.clone(),
                        "manifest is not ratified — nothing runs".into(),
                    );
                stop_all(presence);
                continue;
            }
            if state.passphrase_clone().is_none() {
                continue; // locked: wait quietly
            }
        }

        // Keeper first: the lease spans all channels.
        let mut keeper_lost = None;
        if let Some(k) = &presence.keeper {
            if k.lost.load(Ordering::Relaxed) {
                let keeper_done = k.done.load(Ordering::Relaxed);
                // Contested or superseded: stop channels; retry the claim
                // after backoff (a released/expired foreign lease clears it).
                let note = k
                    .lines
                    .lock()
                    .ok()
                    .and_then(|q| q.iter().rev().find(|l| l.contains("lease")).cloned())
                    .unwrap_or_else(|| "lease unavailable".into());
                state
                    .supervisor_notes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(npub.clone(), note);
                stop_channels(presence);
                if keeper_done
                    && now_secs().saturating_sub(*backoff.get(&npub).unwrap_or(&0))
                        >= RETRY_BACKOFF_SECS
                {
                    presence.keeper = None; // re-claim next tick
                }
                continue;
            }
            keeper_lost = Some(k.lost.clone());
        } else {
            match spawn_keeper(state, &npub, &manifest) {
                Ok(Some(k)) => {
                    keeper_lost = Some(k.lost.clone());
                    presence.keeper = Some(k);
                    presence.manifest_sha = disk_sha.clone();
                    backoff.insert(npub.clone(), now_secs());
                }
                Ok(None) => {
                    presence.manifest_sha = disk_sha.clone();
                    state
                        .supervisor_notes
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(
                            npub.clone(),
                            "no memory.log_relays — presence runs WITHOUT cross-host coordination"
                                .into(),
                        );
                }
                Err(e) => {
                    eprintln!("supervisor: keeper for {npub}: {e}");
                    continue;
                }
            }
        }

        // Channels: start what's declared, reap what died.
        let mut started_any = false;
        for kind in &declared {
            if !kinds_available.contains(kind) {
                state
                    .supervisor_notes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(
                        format!("{npub}:{kind}"),
                        format!("presence.{kind} declared but not installed on this host"),
                    );
                continue;
            }
            if let Some(ch) = presence.channels.get(kind) {
                if !ch.done.load(Ordering::Relaxed) {
                    continue; // healthy
                }
                // Reap, keep last words, back off before restart.
                let last = ch
                    .lines
                    .lock()
                    .ok()
                    .and_then(|q| q.iter().rev().find(|l| l.contains("died")).cloned());
                if let Some(l) = last {
                    state
                        .supervisor_notes
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(format!("{npub}:{kind}"), l);
                }
                presence.channels.remove(kind);
            }
            let key = format!("{npub}:{kind}");
            if now_secs().saturating_sub(*backoff.get(&key).unwrap_or(&0)) < RETRY_BACKOFF_SECS {
                continue;
            }
            backoff.insert(key.clone(), now_secs());
            match spawn_channel(
                state,
                &npub,
                kind,
                dir.clone(),
                manifest.clone(),
                keeper_lost.clone(),
            ) {
                Ok(handle) => {
                    eprintln!("supervisor: started {kind} channel for {npub}");
                    presence.channels.insert(kind.clone(), handle);
                    presence.manifest_sha = disk_sha.clone();
                    started_any = true;
                    state
                        .supervisor_notes
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&key);
                }
                Err(e) => {
                    eprintln!("supervisor: {kind} for {npub}: {e}");
                    state
                        .supervisor_notes
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(key, e);
                }
            }
        }
        if started_any {
            state
                .supervisor_notes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&npub);
        }
    }
}

// -------------------------------------------------- presence endpoints

#[derive(serde::Deserialize)]
pub struct ChannelQuery {
    #[serde(default)]
    channel: Option<String>,
}

pub async fn listener_status(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (_ks, npub, dir, _raw, m) = match gate(&state, &headers, "GET", &uri, None, &npub) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let active = is_active(&dir);
    let declared: Vec<String> = m.presence.channels.keys().cloned().collect();
    let notes = state
        .supervisor_notes
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let map = state.listeners.lock().unwrap_or_else(|e| e.into_inner());
    let presence = map.get(&npub);
    let mut channels = serde_json::Map::new();
    for kind in &declared {
        let running = presence
            .and_then(|p| p.channels.get(kind))
            .map(|c| !c.done.load(Ordering::Relaxed))
            .unwrap_or(false);
        let lines: Vec<String> = presence
            .and_then(|p| p.channels.get(kind))
            .and_then(|c| {
                c.lines
                    .lock()
                    .ok()
                    .map(|q| q.iter().rev().take(30).rev().cloned().collect())
            })
            .unwrap_or_default();
        channels.insert(
            kind.clone(),
            json!({
                "running": running,
                "lines": lines,
                "note": notes.get(&format!("{npub}:{kind}")),
            }),
        );
    }
    let keeper = presence.and_then(|p| p.keeper.as_ref()).map(|k| {
        json!({
            "running": !k.done.load(Ordering::Relaxed),
            "lost": k.lost.load(Ordering::Relaxed),
            "lines": k.lines.lock().ok().map(|q| q.iter().rev().take(10).rev().cloned().collect::<Vec<_>>()),
        })
    });
    Json(json!({
        "ok": true,
        "npub": npub,
        "active": active,
        "declared": declared,
        "channels": channels,
        "lease_keeper": keeper,
        "supervisor_note": notes.get(&npub),
    }))
    .into_response()
}

/// Manual stop of one channel (or all when none named). Deactivation is
/// the real switch; this is the override for a single misbehaving channel.
pub async fn listener_stop(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    Query(q): Query<ChannelQuery>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (_ks, npub, _dir, _raw, _m) = match gate(&state, &headers, "DELETE", &uri, None, &npub) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let mut map = state.listeners.lock().unwrap_or_else(|e| e.into_inner());
    let Some(presence) = map.get_mut(&npub) else {
        return err(StatusCode::NOT_FOUND, "no presence running for this agent").into_response();
    };
    match q.channel {
        Some(kind) => match presence.channels.remove(&kind) {
            Some(ch) => {
                ch.stop.store(true, Ordering::Relaxed);
                Json(json!({"ok": true, "npub": npub, "stopped": kind,
                    "note": "the supervisor restarts declared channels while the agent is ACTIVE — deactivate to stop for real"}))
                .into_response()
            }
            None => err(
                StatusCode::NOT_FOUND,
                format!("no running '{kind}' channel"),
            )
            .into_response(),
        },
        None => {
            stop_all(presence);
            map.remove(&npub);
            Json(json!({"ok": true, "npub": npub, "stopped": "all",
                "note": "the supervisor restarts declared channels while the agent is ACTIVE — deactivate to stop for real"}))
            .into_response()
        }
    }
}

#[derive(serde::Deserialize)]
pub struct PresenceBody {
    /// Channel kind: a built-in (buzz, telegram, slack) or an installed
    /// plugin name.
    kind: String,
    /// Platform secret to seal to the agent (bot token; for slack a JSON
    /// {"app_token":…,"bot_token":…}). Sealed here, never stored elsewhere.
    #[serde(default)]
    credential: Option<String>,
    /// Kind-specific config keys (relay, allowed_chats, …).
    #[serde(default)]
    config: std::collections::BTreeMap<String, serde_json::Value>,
}

/// Declare (or update) a presence channel: an amendment — where the agent
/// lives is constitutional, so the hash changes and a human re-ratifies.
pub async fn presence_declare(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (ks, npub, dir, raw, mut manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let body: PresenceBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    if !available_kinds(&state).contains(&body.kind) {
        return err(
            StatusCode::BAD_REQUEST,
            format!(
                "'{}' is not a channel this host can run (built-ins: {}; plus installed plugins)",
                body.kind,
                apiary_runtime::presence::PRESENCE_KINDS.join(", ")
            ),
        )
        .into_response();
    }
    let credential = match body.credential.as_deref().filter(|c| !c.is_empty()) {
        None => None,
        Some(secret) => {
            let pass = match require_pass(&state) {
                Ok(p) => p,
                Err(e) => return e.into_response(),
            };
            let npub2 = npub.clone();
            let secret = secret.to_string();
            let sealed = tokio::task::spawn_blocking(move || {
                let (custody, handle) = admit(&ks, &npub2, &pass)?;
                custody
                    .seal(&handle, secret.trim())
                    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))
            })
            .await
            .unwrap_or_else(|e| Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)));
            match sealed {
                Ok(blob) => Some(blob),
                Err(e) => return e.into_response(),
            }
        }
    };
    manifest.presence.channels.insert(
        body.kind.clone(),
        apiary_core::manifest::PresenceChannel {
            credential,
            config: body.config,
        },
    );
    let yaml = match serde_yaml::to_string(&manifest) {
        Ok(y) => y,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    if let Err(error) = persist_manifest(&dir, &raw, &yaml) {
        return error.into_response();
    }
    Json(json!({
        "ok": true,
        "npub": npub,
        "declared": body.kind,
        "manifest_sha256": ceremony::manifest_hash(&yaml),
        "ratified": false,
        "note": "presence declared — where the agent lives is constitutional; re-ratify, and the supervisor starts the channel while the agent is ACTIVE",
    }))
    .into_response()
}

pub async fn presence_revoke(
    State(state): State<App>,
    AxPath((npub, kind)): AxPath<(String, String)>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (_ks, npub, dir, raw, mut manifest) =
        match gate(&state, &headers, "DELETE", &uri, None, &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    if manifest.presence.channels.remove(&kind).is_none() {
        return err(
            StatusCode::NOT_FOUND,
            format!("no presence.{kind} declared"),
        )
        .into_response();
    }
    let yaml = match serde_yaml::to_string(&manifest) {
        Ok(y) => y,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    if let Err(error) = persist_manifest(&dir, &raw, &yaml) {
        return error.into_response();
    }
    Json(json!({
        "ok": true,
        "npub": npub,
        "revoked": kind,
        "manifest_sha256": ceremony::manifest_hash(&yaml),
        "ratified": false,
        "note": "presence removed — an amendment; re-ratify. The supervisor bounces the channel within a tick.",
    }))
    .into_response()
}
