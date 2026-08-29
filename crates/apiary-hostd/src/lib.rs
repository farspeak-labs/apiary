//! apiary-hostd — the host daemon (SPEC §2). REST for governance reads and
//! writes, an AG-UI-compatible SSE stream for live runs, Buzz membership
//! operations with managed listeners, NIP-98 auth, and the cockpit served
//! at /. Custody never leaves this process: clients get JSON about the
//! agent, never key material.
//!
//! This crate is BOTH a library and a binary: the `apiary-hostd` daemon and
//! the Tauri desktop app build the same router — the GUI is a client
//! (SPEC §2), never a second implementation.

pub mod access;
pub mod agent_store;
pub mod agui;
pub mod control_mcp;
pub mod decision_gate;
pub mod events;
pub mod nip46;
pub mod nip98;
pub mod ops;
pub mod routines;
pub mod errands;
pub mod watches;

use apiary_core::{
    ceremony,
    custody::Custody,
    keystore::Keystore,
    log::EpisodicLog,
    manifest::{Constitution, Manifest},
};
use axum::{
    extract::{OriginalUri, Path as AxPath, Query, State},
    http::StatusCode,
    middleware,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use nostr::prelude::PublicKey;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;

pub type RememberPassphrase = Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync + 'static>;
pub type ForgetPassphrase = Arc<dyn Fn() -> Result<(), String> + Send + Sync + 'static>;

pub struct AppState {
    pub home: PathBuf,
    /// Unlockable at runtime (GUI unlock screen) — None means locked:
    /// reads work, anything needing key material refuses.
    pub passphrase: std::sync::RwLock<Option<String>>,
    /// Desktop-only Keychain writer. The daemon remains portable and keeps
    /// its existing explicit-unlock behavior when this is absent.
    pub remember_passphrase: Option<RememberPassphrase>,
    pub forget_passphrase: Option<ForgetPassphrase>,
    pub automatic_unlock: std::sync::atomic::AtomicBool,
    pub auth: AuthMode,
    /// Canonical origin for exact NIP-98 URL matching.
    pub origin: String,
    /// HOST managers (nip98 mode): only these keys may perform
    /// host-scoped operations — founding/importing agents, editing the
    /// connector library, locking/unlocking. Per-agent operations stay
    /// governor-bound to that agent's suspend keys; this list is the
    /// authority over the HOST itself (its keystore slots, its inference
    /// credentials, its configuration). CLI `--admin` entries bootstrap the
    /// persistent manager registry. Empty in nip98 mode = host-scoped
    /// operations refuse, loudly.
    pub managers: std::sync::RwLock<access::ManagerRegistry>,
    /// Per-launch bearer token (desktop mode). When set, EVERY request must
    /// present it — the desktop webview gets it in its boot URL, so other
    /// local processes cannot drive the embedded daemon.
    pub token: Option<String>,
    /// Short-lived browser sessions created by one NIP-98 signature. The
    /// cookie is only authentication; every route still applies the ordinary
    /// host-manager or per-agent authorization gate to the bound signer.
    pub browser_sessions:
        std::sync::Mutex<std::collections::HashMap<String, nip98::BrowserSession>>,
    /// NIP-46 connections waiting for a remote signer's approval. Keys are
    /// opaque, high-entropy capabilities returned only to the initiating UI.
    pub pending_nip46: std::sync::Mutex<std::collections::HashMap<String, nip46::RemoteSigner>>,
    /// Connected remote signers, keyed by the human user pubkey. Only the
    /// disposable client key lives here; the human private key never enters
    /// Apiary.
    pub remote_signers: std::sync::Mutex<std::collections::HashMap<String, nip46::RemoteSigner>>,
    /// Per-process credential published only into the host's 0600 state
    /// directory. A desktop client that already authenticated over SSH may
    /// exchange it for an ordinary manager-bound browser session. It is
    /// replaced on every daemon launch and is never accepted as API auth.
    pub desktop_token: Option<String>,
    /// Process-private capability used only when the MCP control adapter
    /// dispatches into the existing REST router. This preserves one set of
    /// authorization gates without trusting caller-supplied identity headers.
    pub internal_token: String,
    /// Serializes the hash-chained MCP control audit file.
    pub control_audit: std::sync::Mutex<()>,
    /// Serializes the persistent control-token registry and revocation checks.
    pub control_tokens: std::sync::Mutex<()>,
    /// Managed Buzz mention listeners, one per agent.
    pub listeners: std::sync::Mutex<std::collections::HashMap<String, ops::AgentPresence>>,
    /// In-flight OAuth grants, keyed by the `state` parameter.
    pub pending_oauth: std::sync::Mutex<std::collections::HashMap<String, ops::PendingOauth>>,
    /// Last supervisor outcome per agent (contested lease, failed start…),
    /// surfaced by the listener status endpoint.
    pub supervisor_notes: std::sync::Mutex<std::collections::HashMap<String, String>>,
    /// Decrypted agent keys, cached while UNLOCKED so a run does not pay
    /// NIP-49 scrypt (seconds in debug builds) every time. Same trust
    /// posture as holding the passphrase, which derives exactly these;
    /// cleared on lock. Keyed by npub.
    pub admitted: std::sync::Mutex<std::collections::HashMap<String, nostr::prelude::Keys>>,
    /// Off-chain projection of signed governance decisions. It never grants
    /// authority of its own: configuration changes select a new cache key
    /// and signed history is re-evaluated before the answer can become true.
    pub decisions: decision_gate::DecisionGate,
}

impl AppState {
    pub fn passphrase_clone(&self) -> Option<String> {
        self.passphrase.read().ok().and_then(|g| g.clone())
    }
}

/// Publish the current control-plane address for local agents. The file is
/// only discovery metadata—never a bearer token—and lets portable manifests
/// use `apiary://local/mcp` across desktop port changes and headless hosts.
pub fn write_control_discovery(state: &AppState) -> Result<(), std::io::Error> {
    std::fs::create_dir_all(&state.home)?;
    let path = state.home.join("control.json");
    let body = serde_json::to_vec_pretty(&json!({
        "url": format!("{}/mcp", state.origin.trim_end_matches('/')),
        "host_id": apiary_runtime::lease::host_id(&state.home),
    }))?;
    std::fs::write(&path, body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Publish the ephemeral SSH-to-desktop session credential. Reading this
/// file requires the same OS account that can administer the headless host;
/// public HTTP clients never receive it.
pub fn write_desktop_access(state: &AppState) -> Result<(), std::io::Error> {
    let Some(token) = state.desktop_token.as_deref() else {
        return Ok(());
    };
    std::fs::create_dir_all(&state.home)?;
    let path = state.home.join("desktop-access.json");
    let body = serde_json::to_vec(&json!({ "version": 1, "token": token }))?;
    std::fs::write(&path, body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq)]
pub enum AuthMode {
    Open,
    Nip98,
}

pub type App = Arc<AppState>;

/// The one router. The daemon binary and the desktop app both serve this.
pub fn build_router(state: App) -> Router {
    Router::new()
        .route("/", get(cockpit))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/app.js", get(cockpit_js))
        .route("/cockpit-api.js", get(cockpit_api_js))
        .route("/cockpit-inference.js", get(cockpit_inference_js))
        .route("/signin.js", get(signin_js))
        .route("/api/status", get(ops::status))
        .route(
            "/api/session",
            post(ops::browser_session_create).delete(ops::browser_session_delete),
        )
        .route("/api/nip46/connect", post(nip46::connect_start))
        .route("/api/nip46/connect/continue", post(nip46::connect_continue))
        .route("/api/nip46/sign", post(nip46::sign))
        .route("/api/desktop/session", post(ops::desktop_session_create))
        .route("/api/unlock", post(ops::unlock))
        .route("/api/unlock/forget", post(ops::forget_automatic_unlock))
        .route("/api/lock", post(ops::lock))
        .route("/api/owners", get(ops::owners_get).post(ops::owners_create))
        .route(
            "/api/managers",
            get(ops::managers_get).post(ops::managers_upsert),
        )
        .route(
            "/api/managers/{npub}",
            axum::routing::delete(ops::managers_remove),
        )
        .route("/api/key", get(ops::key_normalize))
        .route(
            "/api/connectors",
            get(ops::connectors_get).put(ops::connectors_put),
        )
        .route("/api/connectors/discover", post(ops::connectors_discover))
        .route("/api/host/pick-folder", post(ops::pick_folder))
        .route("/api/events", get(events::events))
        .route("/api/control/audit", get(ops::control_audit_get))
        .route("/api/control/tokens", get(ops::control_tokens_all_get))
        .route("/mcp", post(control_mcp::handle))
        .route(
            "/api/agents/{npub}/connectors/{name}/discover",
            post(ops::agent_connector_discover),
        )
        .route(
            "/api/agents/{npub}/connectors/{kind}/allowed_tools",
            post(ops::connector_set_allowed_tools),
        )
        .route(
            "/api/agents/{npub}/connectors/{kind}/caps",
            post(ops::connector_patch_caps),
        )
        .route("/api/agents", get(list_agents))
        .route("/api/agents/found", post(found_agent))
        .route("/api/agents/import", post(ops::import_agent))
        .route(
            "/api/agents/{npub}",
            axum::routing::delete(ops::delete_agent),
        )
        .route("/api/agents/{npub}/archive", post(ops::archive_agent))
        .route("/api/agents/{npub}/export", post(ops::export_agent))
        .route(
            "/api/agents/{npub}/manifest",
            get(get_manifest).put(put_manifest),
        )
        .route("/api/agents/{npub}/ratify", post(ratify_agent))
        .route(
            "/api/agents/{npub}/control-token",
            post(ops::control_token_issue),
        )
        .route(
            "/api/agents/{npub}/control-tokens",
            get(ops::control_tokens_get),
        )
        .route(
            "/api/agents/{npub}/control-tokens/{id}",
            axum::routing::delete(ops::control_token_revoke),
        )
        .route(
            "/api/agents/{npub}/constitution",
            post(ops::constitution_set),
        )
        .route(
            "/api/agents/{npub}/skills",
            get(ops::skills_get).post(ops::skill_upsert),
        )
        .route(
            "/api/agents/{npub}/skills/{name}",
            axum::routing::delete(ops::skill_delete),
        )
        .route(
            "/api/agents/{npub}/harnesses",
            get(ops::harnesses_get).post(ops::harness_upsert),
        )
        .route(
            "/api/agents/{npub}/harnesses/discover",
            get(ops::harnesses_discover),
        )
        .route(
            "/api/agents/{npub}/harnesses/{name}",
            axum::routing::delete(ops::harness_delete),
        )
        .route("/api/agents/{npub}/ratify/export", post(ops::ratify_export))
        .route("/api/agents/{npub}/ratify/import", post(ops::ratify_import))
        .route("/api/agents/{npub}/log", get(get_log))
        .route("/api/agents/{npub}/log/publish", post(ops::log_publish))
        .route("/api/agents/{npub}/log/remote", get(ops::log_remote))
        .route("/api/agents/{npub}/run", post(agui::run_stream))
        .route("/api/agents/{npub}/ag-ui", post(agui::run_stream))
        .route("/api/agents/{npub}/spend", get(ops::spend_status))
        .route(
            "/api/agents/{npub}/inference",
            get(ops::inference_status).post(ops::inference_upsert),
        )
        .route(
            "/api/agents/{npub}/inference/default",
            post(ops::inference_set_default),
        )
        .route(
            "/api/agents/{npub}/inference/fallback",
            post(ops::inference_set_fallback),
        )
        .route(
            "/api/agents/{npub}/inference/{name}/test",
            post(ops::inference_test),
        )
        .route(
            "/api/agents/{npub}/inference/{name}",
            axum::routing::delete(ops::inference_delete),
        )
        .route(
            "/api/agents/{npub}/credential/seal",
            post(ops::credential_seal),
        )
        .route(
            "/api/agents/{npub}/credential/open",
            post(ops::credential_open),
        )
        .route("/api/agents/{npub}/buzz/channels", get(ops::buzz_channels))
        .route("/api/agents/{npub}/buzz/read", get(ops::buzz_read))
        .route("/api/agents/{npub}/buzz/post", post(ops::buzz_post))
        .route("/api/agents/{npub}/buzz/profile", post(ops::buzz_profile))
        .route("/api/agents/{npub}/buzz/join", post(ops::buzz_join))
        .route("/api/agents/{npub}/active", post(ops::set_active))
        .route("/api/agents/{npub}/governors", post(ops::governors_set))
        .route("/api/agents/{npub}/connectors", post(ops::connector_grant))
        .route(
            "/api/agents/{npub}/connectors/oauth",
            post(ops::oauth_start),
        )
        .route("/oauth/callback", get(ops::oauth_callback))
        .route("/api/agents/{npub}/name", post(ops::rename_agent))
        .route("/api/agents/{npub}/proposal", get(routines::get_proposal))
        .route(
            "/api/agents/{npub}/founding-proposal",
            get(routines::get_founding_proposal),
        )
        .route(
            "/api/agents/{npub}/founding-proposal/{decision}",
            post(routines::decide_founding_proposal),
        )
        .route(
            "/api/agents/{npub}/proposal/{decision}",
            post(routines::decide_proposal),
        )
        .route("/api/agents/{npub}/routines", get(routines::list_routines))
        .route("/api/agents/{npub}/watches", get(watches::list_watches))
        .route("/api/agents/{npub}/errands", get(errands::list_errands))
        .route(
            "/api/agents/{npub}/errands/cancel",
            post(errands::cancel_errand),
        )
        .route(
            "/api/agents/{npub}/buzz/claim-invite",
            post(errands::join_relay),
        )
        .route(
            "/api/agents/{npub}/buzz/membership",
            get(errands::buzz_membership),
        )
        .route(
            "/api/agents/{npub}/routines/{name}/run",
            post(routines::run_routine_now),
        )
        .route(
            "/api/agents/{npub}/routines/{name}/{action}",
            post(routines::pause_routine),
        )
        .route("/api/agents/{npub}/lease", get(ops::lease_status))
        .route(
            "/api/agents/{npub}/lease/takeover",
            post(ops::lease_takeover),
        )
        .route(
            "/api/agents/{npub}/connectors/{kind}",
            axum::routing::delete(ops::connector_revoke),
        )
        .route("/api/agents/{npub}/presence", post(ops::presence_declare))
        .route(
            "/api/agents/{npub}/presence/{kind}",
            axum::routing::delete(ops::presence_revoke),
        )
        .route(
            "/api/agents/{npub}/listener",
            get(ops::listener_status).delete(ops::listener_stop),
        )
        .with_state(state)
        .layer(middleware::map_response(no_store))
}

/// Apiary's cockpit and APIs are private control-plane material. Apply the
/// cache boundary centrally so a newly added route cannot accidentally be
/// cached by a browser, reverse proxy, or CDN.
async fn no_store(mut response: axum::response::Response) -> axum::response::Response {
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

/// Minimal liveness probe. It intentionally exposes no version, state path,
/// agent roster, or authentication configuration.
async fn healthz() -> impl IntoResponse {
    Json(json!({ "ok": true }))
}

/// A NIP-98 host without a manager is unreachable by design and therefore not
/// ready for public traffic. Open mode is ready because its trust boundary is
/// the loopback/SSH listener itself.
async fn readyz(State(state): State<App>) -> axum::response::Response {
    let ready = state.auth == AuthMode::Open
        || state
            .managers
            .read()
            .map(|managers| !managers.is_empty())
            .unwrap_or(false);
    if ready {
        Json(json!({ "ok": true })).into_response()
    } else {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "host manager is not configured",
        )
        .into_response()
    }
}

/// Restrictive CSP: no inline script, no external anything. Rendering uses
/// textContent throughout (see cockpit.js) — the CSP is the backstop.
const CSP: &str =
    "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'";

async fn cockpit(
    State(state): State<App>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    let authorized = cockpit_navigation_authorized(&state, &headers);
    let document = if authorized {
        include_str!("cockpit.html")
    } else {
        include_str!("signin.html")
    };
    (
        [
            ("content-security-policy", CSP),
            ("cache-control", "no-store"),
        ],
        Html(document),
    )
        .into_response()
}

fn cockpit_navigation_authorized(state: &AppState, headers: &axum::http::HeaderMap) -> bool {
    state.auth == AuthMode::Open
        || nip98::browser_navigation_signer(state, headers)
            .ok()
            .flatten()
            .is_some_and(|signer| nip98::authorize_cockpit(state, Some(signer)).is_ok())
}

async fn cockpit_js(
    State(state): State<App>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    if !cockpit_navigation_authorized(&state, &headers) {
        return StatusCode::NOT_FOUND.into_response();
    }
    (
        [
            ("content-type", "application/javascript; charset=utf-8"),
            ("content-security-policy", CSP),
            ("cache-control", "no-store"),
        ],
        include_str!("cockpit.js"),
    )
        .into_response()
}

async fn cockpit_api_js(
    State(state): State<App>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    if !cockpit_navigation_authorized(&state, &headers) {
        return StatusCode::NOT_FOUND.into_response();
    }
    (
        [
            ("content-type", "application/javascript; charset=utf-8"),
            ("content-security-policy", CSP),
            ("cache-control", "no-store"),
        ],
        include_str!("cockpit_api.js"),
    )
        .into_response()
}

async fn cockpit_inference_js(
    State(state): State<App>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    if !cockpit_navigation_authorized(&state, &headers) {
        return StatusCode::NOT_FOUND.into_response();
    }
    (
        [
            ("content-type", "application/javascript; charset=utf-8"),
            ("content-security-policy", CSP),
            ("cache-control", "no-store"),
        ],
        include_str!("cockpit_inference.js"),
    )
        .into_response()
}

async fn signin_js() -> impl IntoResponse {
    (
        [
            ("content-type", "application/javascript; charset=utf-8"),
            ("content-security-policy", CSP),
            ("cache-control", "no-store"),
        ],
        include_str!("signin.js"),
    )
}

pub fn err(
    status: StatusCode,
    msg: impl std::fmt::Display,
) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(json!({"ok": false, "error": msg.to_string()})))
}

fn normalize(npub: &str) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let pk =
        apiary_core::identity::parse_npub(npub).map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
    apiary_core::identity::to_npub(&pk).map_err(|e| err(StatusCode::BAD_REQUEST, e))
}

/// Shared per-request context: keystore + validated agent dir.
pub fn agent_ctx(
    state: &AppState,
    npub: &str,
) -> Result<(Keystore, String, PathBuf), (StatusCode, Json<serde_json::Value>)> {
    let ks = Keystore::open(&state.home).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let npub = normalize(npub)?;
    let dir = ks.agent_dir(&npub);
    if !dir.join("manifest.yaml").exists() {
        return Err(err(StatusCode::NOT_FOUND, format!("no agent {npub}")));
    }
    Ok((ks, npub, dir))
}

pub fn load_manifest(
    dir: &std::path::Path,
) -> Result<(String, Manifest), (StatusCode, Json<serde_json::Value>)> {
    let raw = std::fs::read_to_string(dir.join("manifest.yaml"))
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    // Unvalidated on purpose: the API must be able to SHOW and REPAIR an
    // invalid manifest (e.g. an mcp grant missing its allowlist) — the
    // cockpit's fix flow runs through these endpoints. Anything that
    // EXECUTES the agent checks validate() and refuses with the reason.
    let m = Manifest::from_yaml_unvalidated(&raw)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok((raw, m))
}

fn snapshot_approved_manifest(dir: &std::path::Path, raw: &str) -> std::io::Result<()> {
    let path = dir.join("manifest.approved.yaml");
    std::fs::write(&path, raw)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// The autonomy previously in force for this agent — the last manifest a
/// ratification approved. Absent (never ratified) means nothing granted.
pub fn approved_autonomy(dir: &std::path::Path) -> apiary_core::manifest::Autonomy {
    std::fs::read_to_string(dir.join("manifest.approved.yaml"))
        .ok()
        .and_then(|raw| Manifest::from_yaml_unvalidated(&raw).ok())
        .map(|m| m.governance.autonomy)
        .unwrap_or_default()
}

/// **Autonomy can never grant autonomy.** A ratification that widens
/// `governance.autonomy` must be signed by a person: an identity that is
/// not itself an agent on this host. Without this rail, one agent holding
/// `autonomy.ratify` could grant every capability to itself and to every
/// other agent, and the human door would close behind it.
pub fn check_autonomy_grant(
    ks: &Keystore,
    dir: &std::path::Path,
    candidate: &Manifest,
    ratifier: &PublicKey,
) -> Result<(), String> {
    let previous = approved_autonomy(dir);
    if !candidate.governance.autonomy.expands_beyond(&previous) {
        return Ok(());
    }
    let ratifier_npub = apiary_core::identity::to_npub(ratifier).unwrap_or_default();
    let is_agent = ks
        .list()
        .map(|agents| agents.iter().any(|npub| npub == &ratifier_npub))
        .unwrap_or(false);
    if is_agent {
        return Err(format!(
            "this ratification would grant autonomy ({}) and is signed by an agent. \
             Autonomy can never grant autonomy: a person must ratify it.",
            candidate.governance.autonomy.granted().join(", ")
        ));
    }
    Ok(())
}

pub fn suspend_pks(manifest: &Manifest) -> Vec<PublicKey> {
    let mut keys = manifest
        .governance
        .suspend_keys
        .iter()
        .filter_map(|k| apiary_core::identity::parse_npub(k).ok())
        .collect::<Vec<_>>();
    keys.extend(
        manifest
            .governance
            .managers
            .iter()
            .filter(|manager| manager.role == apiary_core::manifest::ManagerRole::Governor)
            .filter_map(|manager| apiary_core::identity::parse_npub(&manager.npub).ok()),
    );
    keys.sort();
    keys.dedup();
    keys
}

pub fn agent_decision(
    state: &AppState,
    dir: &std::path::Path,
    npub: &str,
    raw: &str,
    manifest: &Manifest,
) -> decision_gate::AgentDecision {
    state
        .decisions
        .evaluate(dir, npub, raw, &suspend_pks(manifest))
}

fn path_and_query(uri: &axum::http::Uri) -> String {
    uri.path_and_query()
        .map(|pq| pq.to_string())
        .unwrap_or_else(|| uri.path().to_string())
}

async fn list_agents(
    State(state): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let signer = match nip98::check(&state, &headers, "GET", &path_and_query(&uri), None) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let ks = match Keystore::open(&state.home) {
        Ok(k) => k,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    let mut agents = Vec::new();
    for npub in ks.list().unwrap_or_default() {
        let dir = ks.agent_dir(&npub);
        let name = std::fs::read_to_string(dir.join("name")).ok();
        let Ok((raw, m)) = load_manifest(&dir) else {
            continue;
        };
        // In nip98 mode the roster shows only agents the signer governs.
        if nip98::authorize_agent_request(&state, signer, &m, "GET", &path_and_query(&uri)).is_err()
        {
            continue;
        }
        let decision = agent_decision(&state, &dir, &npub, &raw, &m);
        // What this agent is waiting on a person for. A pending request that
        // is only visible after clicking into the agent is a request nobody
        // knows about — the roster is where you look first, so it has to say.
        let mut waiting: Vec<&str> = Vec::new();
        if !decision.ratified && !ops::is_archived(&dir) {
            waiting.push("approval");
        }
        if apiary_runtime::proposal::read_proposal(&dir).is_some() {
            waiting.push("amendment");
        }
        if apiary_runtime::proposal::read_founding_request(&dir).is_some() {
            waiting.push("new agent");
        }
        agents.push(json!({
            "npub": npub,
            "name": name,
            "ratified": decision.ratified,
            "log_entries": decision.log_entries,
            "active": ops::is_active(&dir),
            "archived": ops::is_archived(&dir),
            "waiting_on_you": waiting,
            "declared_channels": m.presence.channels.keys().cloned().collect::<Vec<_>>(),
        }));
    }
    Json(json!({"ok": true, "agents": agents})).into_response()
}

async fn get_manifest(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let signer = match nip98::check(&state, &headers, "GET", &path_and_query(&uri), None) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let (_ks, npub, dir) = match agent_ctx(&state, &npub) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    match load_manifest(&dir) {
        Ok((raw, m)) => {
            if let Err(e) =
                nip98::authorize_agent_request(&state, signer, &m, "GET", &path_and_query(&uri))
            {
                return e.into_response();
            }
            let decision = agent_decision(&state, &dir, &npub, &raw, &m);
            Json(json!({
                "ok": true,
                "npub": npub,
                "yaml": raw,
                "approved_yaml": std::fs::read_to_string(dir.join("manifest.approved.yaml")).ok(),
                "manifest": serde_json::to_value(&m).unwrap_or_default(),
                "ratified": decision.ratified,
                "manifest_sha256": decision.manifest_sha256,
            }))
            .into_response()
        }
        Err(e) => e.into_response(),
    }
}

#[derive(serde::Deserialize)]
struct LogQuery {
    #[serde(default = "default_tail")]
    tail: usize,
}
fn default_tail() -> usize {
    50
}

async fn get_log(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    Query(q): Query<LogQuery>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let signer = match nip98::check(&state, &headers, "GET", &path_and_query(&uri), None) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let (_ks, npub, dir) = match agent_ctx(&state, &npub) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    match load_manifest(&dir) {
        Ok((_, m)) => {
            if let Err(e) =
                nip98::authorize_agent_request(&state, signer, &m, "GET", &path_and_query(&uri))
            {
                return e.into_response();
            }
        }
        Err(e) => return e.into_response(),
    }
    let log = EpisodicLog::open(&dir);
    let chain = log
        .verify()
        .map(|n| json!({"valid": true, "entries": n}))
        .unwrap_or_else(|e| json!({"valid": false, "error": e.to_string()}));
    let entries: Vec<serde_json::Value> = log
        .tail(q.tail)
        .unwrap_or_default()
        .iter()
        .map(|e| {
            json!({
                "id": e.id.to_hex(),
                "at": e.created_at.as_secs(),
                "signer": e.pubkey.to_hex(),
                "body": EpisodicLog::parse_body(e).ok(),
            })
        })
        .collect();
    Json(json!({"ok": true, "npub": npub, "chain": chain, "entries": entries})).into_response()
}

#[derive(serde::Deserialize)]
struct PutManifestBody {
    yaml: String,
}

/// Amend the constitution. Validation is structural; the governance effect
/// is automatic: a changed hash means the ratification no longer matches,
/// so the agent refuses to run until re-ratified. Amendments are cheap;
/// unratified amendments are inert.
async fn put_manifest(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let signer = match nip98::check(
        &state,
        &headers,
        "PUT",
        &path_and_query(&uri),
        Some(&raw_body),
    ) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let body: PutManifestBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let (_ks, npub, dir) = match agent_ctx(&state, &npub) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    // Governorship is checked against the CURRENT constitution — the one
    // being amended — so a stranger cannot grant themselves authority by
    // writing a manifest that names them.
    let current_raw = match load_manifest(&dir) {
        Ok((current_raw, current)) => {
            if let Err(e) = nip98::authorize_agent_request(
                &state,
                signer,
                &current,
                "PUT",
                &path_and_query(&uri),
            ) {
                return e.into_response();
            }
            current_raw
        }
        Err(e) => return e.into_response(),
    };
    let manifest = match Manifest::from_yaml(&body.yaml) {
        Ok(m) => m,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    // The manifest's identity must stay the agent's own.
    let identity_ok = apiary_core::identity::parse_npub(&manifest.identity.npub)
        .ok()
        .and_then(|pk| apiary_core::identity::to_npub(&pk).ok())
        .is_some_and(|n| n == npub);
    if !identity_ok {
        return err(
            StatusCode::BAD_REQUEST,
            "manifest identity.npub must match the agent",
        )
        .into_response();
    }
    let manifest_sha256 = match agent_store::replace_manifest(&dir, &current_raw, &body.yaml) {
        Ok(revision) => revision,
        Err(agent_store::StoreError::Conflict { current_revision }) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({
                    "ok": false,
                    "error": "the agent changed while this amendment was being prepared; reload and try again",
                    "code": "manifest_revision_conflict",
                    "current_revision": current_revision,
                })),
            )
                .into_response()
        }
        Err(agent_store::StoreError::Io(error)) => {
            return err(StatusCode::INTERNAL_SERVER_ERROR, error).into_response()
        }
    };
    Json(json!({
        "ok": true,
        "npub": npub,
        "manifest_sha256": manifest_sha256,
        "ratified": false,
        "note": "amendment saved — re-ratify before the agent runs again",
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
struct RatifyBody {
    /// Ratifying governor's key (npub or hex) — keystore-held, listed in suspend_keys.
    r#as: String,
}

async fn ratify_agent(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let signer = match nip98::check(
        &state,
        &headers,
        "POST",
        &path_and_query(&uri),
        Some(&raw_body),
    ) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let body: RatifyBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let (ks, npub, dir) = match agent_ctx(&state, &npub) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let (raw, manifest) = match load_manifest(&dir) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    if let Err(e) =
        nip98::authorize_agent_request(&state, signer, &manifest, "POST", &path_and_query(&uri))
    {
        return e.into_response();
    }
    let as_key = match normalize(&body.r#as) {
        Ok(k) => k,
        Err(e) => return e.into_response(),
    };
    let listed = suspend_pks(&manifest);
    let ratifier_pk = match apiary_core::identity::parse_npub(&as_key) {
        Ok(pk) if listed.contains(&pk) => pk,
        Ok(_) => {
            return err(
                StatusCode::FORBIDDEN,
                "ratifier is not a listed suspend key",
            )
            .into_response()
        }
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    // A host-held governor key signs ONLY for the identity that proved possession
    // of that same key: in nip98 mode the request signer must BE the
    // ratifier. (Open mode is local trust — same as holding the keystore.)
    if signer.is_some() && signer != Some(ratifier_pk) {
        return err(
            StatusCode::FORBIDDEN,
            "ratification must be signed by the ratifying key itself (as == request signer)",
        )
        .into_response();
    }
    if let Err(e) = check_autonomy_grant(&ks, &dir, &manifest, &ratifier_pk) {
        return err(StatusCode::FORBIDDEN, e).into_response();
    }
    let pass = match state.passphrase_clone() {
        Some(p) => p,
        None => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "keystore is locked — unlock with the passphrase first",
            )
            .into_response()
        }
    };
    let (agent_keys, human_keys) = match (ks.load(&npub, &pass), ks.load(&as_key, &pass)) {
        (Ok(a), Ok(h)) => (a, h),
        (Err(e), _) | (_, Err(e)) => return err(StatusCode::UNAUTHORIZED, e).into_response(),
    };
    let mut custody = Custody::new();
    let agent_handle = custody.admit(agent_keys);
    let human_handle = custody.admit(human_keys);
    let log = EpisodicLog::open(&dir);
    let result = ceremony::sign_manifest(&custody, &agent_handle, &log, &raw)
        .and_then(|s| ceremony::ratify(&custody, &human_handle, &log, &npub, &raw).map(|r| (s, r)));
    match result {
        Ok((signed, ratified)) => {
            // The signatures are authoritative. A failed review snapshot
            // must not report the already-completed ceremony as failed.
            let snapshot_warning = snapshot_approved_manifest(&dir, &raw)
                .err()
                .map(|e| e.to_string());
            state.decisions.invalidate(&npub);
            Json(json!({
                "ok": true,
                "npub": npub,
                "ratified_by": as_key,
                "manifest_sha256": ceremony::manifest_hash(&raw),
                "events": {"signed": signed.id.to_hex(), "ratified": ratified.id.to_hex()},
                "snapshot_warning": snapshot_warning,
            }))
            .into_response()
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

#[derive(serde::Deserialize)]
struct FoundBody {
    name: String,
    /// What this agent is for — the seed of its constitution.
    purpose: String,
    /// Human suspend keys (npub/hex). At least one required.
    suspend_keys: Vec<String>,
    /// "anthropic" to draft the manifest with a model; anything else (or
    /// missing credentials) falls back to the conservative template.
    #[serde(default)]
    draft_with: Option<String>,
    /// The shape of agent: "assistant" (default), "coding", or "watcher".
    /// Carries the settings that only work as a set.
    #[serde(default)]
    preset: Option<String>,
    /// Where a coding agent's checkout, or a watcher's folder, lives.
    #[serde(default)]
    workdir: Option<String>,
}

/// The founding flow (SPEC §12.5, generative-UI-first): generate identity,
/// DRAFT a manifest from the purpose — by a model when available, template
/// otherwise — and return it for human review. Founding is the moment of
/// maximum ignorance: the draft is a hypothesis, not a commitment; nothing
/// runs until ratified.
async fn found_agent(
    State(state): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let signer = match nip98::check(
        &state,
        &headers,
        "POST",
        &path_and_query(&uri),
        Some(&raw_body),
    ) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = nip98::authorize_admin(&state, signer) {
        return e.into_response();
    }
    let body: FoundBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    if body.purpose.trim().is_empty() {
        return err(StatusCode::BAD_REQUEST, "agent purpose is required").into_response();
    }
    if body.suspend_keys.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "at least one independent governor identity is required",
        )
        .into_response();
    }
    let suspend: Vec<String> = match body
        .suspend_keys
        .iter()
        .map(|k| normalize(k).map_err(|(_, e)| e))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    // The founder must govern what they found: in nip98 mode the request
    // signer must be among the new agent's suspend keys.
    if state.auth == AuthMode::Nip98 {
        let listed = suspend
            .iter()
            .filter_map(|k| apiary_core::identity::parse_npub(k).ok())
            .collect::<Vec<_>>();
        if let Err(e) = nip98::authorize_governor(&state, signer, &listed) {
            return e.into_response();
        }
    }
    // A shape only applies when the host can actually back it: a coding
    // preset with no harness on this machine would write a command that is
    // not there, which is the failure mode presets exist to remove.
    let discovered = ops::discovered_harness_for_preset();
    let preset = Preset::parse(
        body.preset.as_deref(),
        body.workdir.as_deref(),
        discovered
            .as_ref()
            .map(|(command, args)| (command.as_str(), args.as_slice())),
    );
    match create_agent(
        &state,
        &body.name,
        &body.purpose,
        &suspend,
        body.draft_with.as_deref(),
        None,
        preset.as_ref(),
    )
    .await
    {
        Ok((npub, yaml, drafted_by)) => Json(json!({
            "ok": true,
            "npub": npub,
            "name": body.name,
            "yaml": yaml,
            "drafted_by": drafted_by,
            "ratified": false,
            "note": "review the draft, amend as needed, then ratify — nothing runs unratified",
        }))
        .into_response(),
        Err((code, message)) => err(code, message).into_response(),
    }
}

/// Mint an agent: identity, keystore entry, drafted manifest, name file.
///
/// Shared by the two ways an agent comes to exist — a person filling in the
/// founding form, and a person APPROVING another agent's founding request.
/// The second is not a lesser path: approving a specific request IS the
/// decision, and building exactly what was approved is execution rather than
/// a new authority. Making someone retype an approved spec into a form is
/// ceremony mistaken for control.
///
/// Either way the result is inert — unratified, inactive, and governed by
/// the humans named in `suspend`.
pub(crate) async fn create_agent(
    state: &App,
    name: &str,
    purpose: &str,
    suspend: &[String],
    draft_with: Option<&str>,
    shape: Option<&apiary_runtime::proposal::FoundingRequest>,
    preset: Option<&Preset>,
) -> Result<(String, String, String), (StatusCode, String)> {
    let pass = state.passphrase_clone().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "keystore is locked — unlock with the passphrase first".to_string(),
    ))?;
    let ks = Keystore::open(&state.home)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let keys = apiary_core::identity::generate();
    let npub = apiary_core::identity::to_npub(&keys.public_key())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    ks.store(&keys, &pass)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let purpose = purpose.trim().to_string();
    let template = template_manifest(&npub, suspend, &purpose);
    let (draft, drafted_by) = if draft_with == Some("anthropic") {
        match draft_manifest_with_model(&npub, &purpose, suspend, &template).await {
            Ok(y) => (y, "anthropic"),
            Err(e) => {
                eprintln!("founding draft fell back to template: {e}");
                (template.clone(), "template (model draft failed)")
            }
        }
    } else {
        (template.clone(), "template")
    };
    // Whatever drafted it, it must parse and pass invariants — or we fall
    // back to the template rather than storing an invalid constitution.
    let (mut manifest, mut drafted_by) = match Manifest::from_yaml(&draft) {
        Ok(manifest) => (manifest, drafted_by.to_string()),
        Err(_) => (
            Manifest::from_yaml(&template).expect("founding template must be valid"),
            "template (model draft invalid)".to_string(),
        ),
    };
    // The purpose is authoritative input, not something a drafting model may
    // paraphrase away.
    manifest.constitution.purpose = purpose;
    // An APPROVED request is a specification, not a suggestion: what the
    // governor read is what gets built.
    if let Some(shape) = shape {
        if !shape.role.trim().is_empty() {
            manifest.constitution.role = shape.role.trim().to_string();
        }
        if !shape.principles.is_empty() {
            manifest.constitution.principles = shape.principles.clone();
        }
        if !shape.boundaries.is_empty() {
            manifest.constitution.boundaries = shape.boundaries.clone();
        }
        if let Some(tokens) = shape.tokens_per_day {
            manifest
                .governance
                .budgets
                .insert("tokens_per_day".into(), json!(tokens));
        }
        drafted_by = format!("the founding request {} filed", shape.by);
    }
    if let Some(preset) = preset {
        preset.apply(&mut manifest);
    }
    let yaml = manifest
        .to_yaml()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let dir = ks.agent_dir(&npub);
    agent_store::create_manifest(&dir, &yaml)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    std::fs::write(dir.join("name"), name)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok((npub, yaml, drafted_by))
}

/// A shape of agent, applied to the drafted manifest as a unit.
///
/// The hard part of founding a working agent was never typing — it was
/// knowing that a coding agent needs a harness grant AND `routing.harness`
/// AND a proactive allowance AND a workdir that is not the deployed tree,
/// and that a watcher without `proactive_tokens_per_day` is inert. Those
/// facts live in scope docs and in whoever founded the last one. A preset
/// carries them together, so the pieces that only work as a set arrive as
/// a set.
///
/// A preset never invents a capability the host cannot back: no discovered
/// harness means no harness grant, and the cockpit says so rather than
/// writing a command that is not there.
#[derive(Debug, Clone)]
pub(crate) enum Preset {
    /// Answers people. The default shape, and the template already is one.
    Assistant,
    /// Works on code in a checkout, through a real coding loop.
    Coding {
        harness_command: String,
        harness_args: Vec<String>,
        workdir: String,
    },
    /// Acts on change rather than on being asked.
    Watcher { vault: String, path: String },
}

impl Preset {
    pub(crate) fn parse(
        name: Option<&str>,
        workdir: Option<&str>,
        harness: Option<(&str, &[String])>,
    ) -> Option<Self> {
        match name.map(str::trim).unwrap_or("") {
            "coding" => {
                let (command, args) = harness?;
                Some(Preset::Coding {
                    harness_command: command.to_string(),
                    harness_args: args.to_vec(),
                    workdir: workdir?.trim().to_string(),
                })
            }
            "watcher" => Some(Preset::Watcher {
                vault: "Watched".into(),
                path: workdir?.trim().to_string(),
            }),
            "assistant" => Some(Preset::Assistant),
            _ => None,
        }
    }

    fn apply(&self, manifest: &mut Manifest) {
        match self {
            Preset::Assistant => {}
            Preset::Coding {
                harness_command,
                harness_args,
                workdir,
            } => {
                manifest.harnesses.push(apiary_core::manifest::HarnessGrant {
                    name: "coder".into(),
                    kind: "acp".into(),
                    command: harness_command.clone(),
                    args: harness_args.clone(),
                    access: apiary_core::manifest::HarnessAccess::Full,
                    // Its own HOME, so the host user's credentials are not
                    // in scope. It needs its own login — the readiness panel
                    // says so, because nothing else would.
                    profile: apiary_core::manifest::HarnessProfile::Isolated,
                    // NOT no-network: that profile denies the whole process,
                    // and a loop that cannot reach a model cannot run.
                    sandbox: apiary_core::manifest::HarnessSandbox::None,
                    allowed_tools: Vec::new(),
                    inherit_env: Vec::new(),
                    metering: apiary_core::manifest::HarnessMetering::Estimated,
                    estimated_tokens_per_run: Some(60_000),
                    workdir: Some(workdir.clone()),
                });
                // Pointing work at it is a separate line, and without it the
                // grant sits unused — the exact gap that made the first
                // builder agent unreachable by conversation.
                manifest.routing.harness = Some("coder".into());
                // Coding runs are long; the fence that matters is per-run.
                manifest
                    .governance
                    .budgets
                    .insert("tokens_per_day".into(), json!(1_000_000));
                manifest
                    .governance
                    .budgets
                    .insert("proactive_tokens_per_day".into(), json!(200_000));
            }
            Preset::Watcher { vault, path } => {
                manifest.memory.vaults.push(apiary_core::manifest::VaultRef {
                    name: vault.clone(),
                    path: path.clone(),
                    kind: None,
                });
                // A watch with no proactive allowance is inert, and says so
                // only on an endpoint nobody visits.
                manifest
                    .governance
                    .budgets
                    .entry("proactive_tokens_per_day".into())
                    .or_insert(json!(40_000));
            }
        }
    }
}

/// The inference slot a NEW agent starts with.
///
/// Founding must not hand back an agent that cannot think. Defaulting to a
/// provider whose credential this host does not have produces something that
/// looks finished, passes validation, and fails every single run — which is
/// exactly what happened to the first agent founded from a request here.
///
/// So: use the API key when the host actually holds one, otherwise fall back
/// to the local Claude Code sign-in, which needs no key of its own.
fn template_inference() -> (&'static str, &'static str) {
    if std::env::var("ANTHROPIC_API_KEY").is_ok_and(|v| !v.is_empty()) {
        ("anthropic", "claude-opus-5")
    } else {
        ("claude-code", "claude-sonnet-5")
    }
}

fn template_manifest(npub: &str, suspend: &[String], purpose: &str) -> String {
    let keys: String = suspend.iter().map(|k| format!("    - {k}\n")).collect();
    let constitution = serde_yaml::to_string(&Constitution {
        purpose: purpose.to_string(),
        ..Default::default()
    })
    .expect("constitution must serialize");
    let constitution = constitution
        .lines()
        .map(|line| format!("  {line}\n"))
        .collect::<String>();
    let (provider, model) = template_inference();
    format!(
        "manifest_version: 1\n\
         identity:\n  npub: {npub}\n\
         constitution:\n{constitution}\
         inference:\n\
         - name: workhorse\n  provider: {provider}\n  model: {model}\n\
         routing:\n  default: workhorse\n\
         connectors: []\n\
         memory:\n  log: local\n  index: local\n\
         governance:\n  suspend_keys:\n{keys}  budgets:\n    tokens_per_day: 100000\n"
    )
}

/// Ask a model to draft the constitution from the purpose statement.
/// The draft is reviewed by a human before anything is ratified — the model
/// proposes, the human disposes.
async fn draft_manifest_with_model(
    npub: &str,
    purpose: &str,
    suspend: &[String],
    template: &str,
) -> Result<String, String> {
    let npub = npub.to_string();
    let purpose = purpose.to_string();
    let suspend = suspend.to_vec();
    let template = template.to_string();
    tokio::task::spawn_blocking(move || {
        let provider = apiary_runtime::inference::AnthropicProvider::from_env()
            .ok_or("no ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN in daemon environment")?;
        use apiary_runtime::inference::Provider;
        let system = "You draft founding manifests for Apiary agents. Output ONLY valid YAML, \
                      no fences, no commentary. Constraints: manifest_version 1; identity.npub \
                      exactly as given; suspend_keys exactly as given; connectors only from: \
                      nostr-publish (needs caps.relays list). Budgets conservative. The routing \
                      pool may use providers: anthropic, ollama. Preserve constitution.purpose \
                      exactly; add a concise role, voice, principles, and boundaries that fit it. \
                      Follow the template's shape.";
        let prompt = format!(
            "Template:\n{template}\nAgent npub: {npub}\nSuspend keys: {suspend:?}\n\
             Purpose of this agent: {purpose}\n\nDraft the manifest YAML."
        );
        let completion = provider
            .complete("claude-opus-5", system, &prompt, &[], 8192)
            .map_err(|e| e.to_string())?;
        if completion.outcome != "ok" {
            return Err(format!("draft stopped: {}", completion.outcome));
        }
        Ok(completion
            .text
            .trim()
            .trim_start_matches("```yaml")
            .trim_start_matches("```")
            .trim_end_matches("```")
            .trim()
            .to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Load an agent's keys into a fresh custody and hand back (custody, handle).
/// Used by the run stream; requires the daemon's passphrase.
pub fn admit_agent(
    state: &AppState,
    ks: &Keystore,
    npub: &str,
) -> Result<(Custody, apiary_core::custody::AgentHandle), String> {
    let pass = state
        .passphrase_clone()
        .ok_or("keystore is locked — unlock with the passphrase first")?;
    // Hold the small admission lock across the deliberately expensive load.
    // Without this, Buzz, Telegram, the lease keeper, and a concurrent task
    // can all miss the cache together and perform the same NIP-49 KDF. Key
    // admission is rare; serializing it is substantially cheaper and avoids
    // a CPU spike while channels appear stuck in "Starting".
    let keys = {
        let mut admitted = state
            .admitted
            .lock()
            .map_err(|_| "agent admission cache is unavailable".to_string())?;
        if let Some(keys) = admitted.get(npub) {
            keys.clone()
        } else {
            let keys = ks.load(npub, &pass).map_err(|e| e.to_string())?;
            admitted.insert(npub.to_string(), keys.clone());
            keys
        }
    };
    let mut custody = Custody::new();
    let handle = custody.admit(keys);
    Ok((custody, handle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::ManagerRegistry;
    use apiary_core::identity;
    use axum::{body::Body, http::Request};
    use nostr::prelude::Keys;
    use tower::ServiceExt;

    fn test_state(auth: AuthMode) -> App {
        test_state_with(auth, Vec::new(), None)
    }

    fn test_state_with(
        auth: AuthMode,
        managers: Vec<nostr::prelude::PublicKey>,
        desktop_token: Option<&str>,
    ) -> App {
        let home = std::env::temp_dir().join(format!(
            "apiary-hostd-router-test-{}-{}",
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
            auth,
            origin: "https://apiary.example".into(),
            managers: std::sync::RwLock::new(ManagerRegistry::in_memory(managers)),
            token: None,
            browser_sessions: std::sync::Mutex::new(std::collections::HashMap::new()),
            pending_nip46: std::sync::Mutex::new(std::collections::HashMap::new()),
            remote_signers: std::sync::Mutex::new(std::collections::HashMap::new()),
            desktop_token: desktop_token.map(str::to_string),
            internal_token: "router-test-internal".into(),
            control_audit: std::sync::Mutex::new(()),
            control_tokens: std::sync::Mutex::new(()),
            listeners: std::sync::Mutex::new(std::collections::HashMap::new()),
            pending_oauth: std::sync::Mutex::new(std::collections::HashMap::new()),
            supervisor_notes: std::sync::Mutex::new(std::collections::HashMap::new()),
            admitted: std::sync::Mutex::new(std::collections::HashMap::new()),
            decisions: Default::default(),
        })
    }

    /// The one rail of full autonomy: a manifest that WIDENS
    /// governance.autonomy may be ratified by a person, never by an agent
    /// on this host — otherwise autonomy propagates itself and the human
    /// door closes for good.
    #[test]
    fn autonomy_can_never_grant_autonomy() {
        let home = std::env::temp_dir().join(format!(
            "apiary-autonomy-rail-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        let ks = Keystore::open(&home).unwrap();
        let pass = "rail-test-passphrase";
        ks.verify_or_initialize_workspace(pass).unwrap();
        // A lead agent (in the keystore) and a person (not).
        let lead = Keys::generate();
        ks.store(&lead, pass).unwrap();
        let person = Keys::generate().public_key();
        let subject = identity::to_npub(&Keys::generate().public_key()).unwrap();
        let dir = ks.agent_dir(&subject);
        std::fs::create_dir_all(&dir).unwrap();

        let with_autonomy = |flags: &str| -> Manifest {
            Manifest::from_yaml(&format!(
                "manifest_version: 1\nidentity:\n  npub: {subject}\ninference:\n  \
                 - name: brain\n    provider: mock\nrouting:\n  default: brain\n\
                 memory:\n  log: local\ngovernance:\n  suspend_keys:\n    - {}\n{flags}",
                identity::to_npub(&person).unwrap()
            ))
            .unwrap()
        };
        let plain = with_autonomy("");
        let autonomous = with_autonomy("  autonomy:\n    ratify: true\n    open_credentials: true\n");

        // Nothing granted: either signer may ratify.
        assert!(check_autonomy_grant(&ks, &dir, &plain, &lead.public_key()).is_ok());
        assert!(check_autonomy_grant(&ks, &dir, &plain, &person).is_ok());
        // Granting autonomy: the person may, the agent may not.
        assert!(check_autonomy_grant(&ks, &dir, &autonomous, &person).is_ok());
        let refused = check_autonomy_grant(&ks, &dir, &autonomous, &lead.public_key())
            .expect_err("an agent must not be able to grant autonomy");
        assert!(refused.contains("Autonomy can never grant autonomy"), "{refused}");
        assert!(refused.contains("open credentials"), "names what it would grant: {refused}");

        // Once a person HAS granted it, the agent may ratify manifests that
        // do not widen it further — autonomy is usable, just not self-issued.
        snapshot_approved_manifest(&dir, &autonomous.to_yaml().unwrap()).unwrap();
        assert!(check_autonomy_grant(&ks, &dir, &autonomous, &lead.public_key()).is_ok());
        let wider = with_autonomy(
            "  autonomy:\n    ratify: true\n    open_credentials: true\n    export: true\n",
        );
        assert!(check_autonomy_grant(&ks, &dir, &wider, &lead.public_key()).is_err());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn founding_template_persists_the_exact_purpose() {
        let agent = identity::to_npub(&Keys::generate().public_key()).unwrap();
        let human = identity::to_npub(&Keys::generate().public_key()).unwrap();
        let purpose = "Research markets: distinguish facts from inference\nand cite sources.";
        let yaml = template_manifest(&agent, &[human], purpose);
        let manifest = Manifest::from_yaml(&yaml).unwrap();
        assert_eq!(manifest.constitution.purpose, purpose);
    }

    #[test]
    fn public_sign_in_page_does_not_disclose_the_cockpit() {
        let page = include_str!("signin.html");
        assert!(page.contains("Authentication required"));
        assert!(page.contains("Sign in with Nostr"));
        for private_label in ["New agent", "People &amp; access", "Host status", "Agents"] {
            assert!(!page.contains(private_label));
        }
        assert!(!page.contains("/app.js"));
    }

    #[test]
    fn cockpit_keeps_transport_and_catalog_out_of_the_renderer() {
        let html = include_str!("cockpit.html");
        let renderer = include_str!("cockpit.js");
        let transport = include_str!("cockpit_api.js");
        let inference = include_str!("cockpit_inference.js");

        assert!(html.contains("<script type=\"module\" src=\"/app.js\"></script>"));
        assert!(renderer.contains("createApiaryClient"));
        assert!(renderer.contains("inferenceModels"));
        assert!(!renderer.contains("async function nip98Authorization"));
        assert!(!renderer.contains("const inferenceModels ="));
        assert!(transport.contains("async function nip98Authorization"));
        assert!(inference.contains("export const inferenceModels"));
    }

    #[test]
    fn cockpit_authenticates_oauth_mcp_before_tool_discovery() {
        let renderer = include_str!("cockpit.js");

        assert!(renderer.contains("OAuth sign-in (recommended)"));
        assert!(renderer.contains("SAVE & CONNECT WITH OAUTH"));
        assert!(renderer.contains("Authenticate first. Apiary will discover"));
        assert!(renderer.contains("Connect with OAuth below before discovering tools."));
        assert!(renderer.contains("function renderMcpToolPolicyPicker"));
        assert!(renderer.contains("Set category…"));
        assert!(renderer.contains("tool_access"));
    }

    #[test]
    fn cockpit_exposes_archive_before_permanent_agent_deletion() {
        let renderer = include_str!("cockpit.js");

        assert!(renderer.contains("Archive agent"));
        assert!(renderer.contains("Restore agent"));
        assert!(renderer.contains("Permanently delete this agent"));
        assert!(renderer.contains("Type ${expected} to confirm"));
        assert!(renderer.contains("api('/archive')"));
        assert!(renderer.contains("method: 'DELETE'"));
    }

    #[test]
    fn cockpit_overview_exposes_a_copyable_full_agent_nostr_id() {
        let renderer = include_str!("cockpit.js");
        let shell = include_str!("cockpit.html");

        assert!(renderer.contains("function copyableNostrId(value)"));
        assert!(renderer.contains("copyableNostrId(sel)"));
        assert!(renderer.contains("Copy Nostr ID"));
        assert!(renderer.contains("navigator.clipboard.writeText"));
        assert!(shell.contains(".agent-public-id-value"));
        assert!(shell.contains("user-select:all"));
    }

    #[test]
    fn cockpit_remote_signer_uses_inline_setup_and_the_desktop_browser_bridge() {
        let renderer = include_str!("cockpit.js");

        assert!(renderer.contains("Bunker connection string"));
        assert!(renderer.contains("bunker://…"));
        assert!(renderer.contains("showRemoteSignerAuthorization(status, result.auth_url"));
        assert!(renderer.contains("if (DESKTOP) openExternalUrl(url)"));
        assert!(renderer.contains("desktopAction('open-external', { url })"));
        assert!(!renderer.contains("window.prompt("));
    }

    #[test]
    fn cockpit_preserves_technical_values_without_text_assistance() {
        let renderer = include_str!("cockpit.js");

        for attribute in [
            "autocapitalize', 'none",
            "autocorrect', 'off",
            "data-gramm', 'false",
        ] {
            assert!(renderer.contains(attribute));
        }
        assert!(renderer.contains("function technicalInput(control)"));
        assert!(renderer.contains("technicalInput(el('input', 'grow'))"));
        assert!(renderer.contains("technicalInput(el('input', 'relay-address'))"));
        assert!(renderer.contains("inp.placeholder = 'wss://your-buzz-relay'"));

        let shell = include_str!("cockpit.html");
        assert!(shell.contains("input.relay-address"));
        assert!(shell.contains("width:100%"));
    }

    #[tokio::test]
    async fn agent_archive_and_permanent_delete_are_enforced() {
        let state = test_state(AuthMode::Open);
        let passphrase = "correct horse battery staple";
        *state.passphrase.write().unwrap() = Some(passphrase.to_string());
        let keystore = Keystore::open(&state.home).unwrap();
        let keys = Keys::generate();
        let agent = identity::to_npub(&keys.public_key()).unwrap();
        let governor = identity::to_npub(&Keys::generate().public_key()).unwrap();
        keystore.store(&keys, passphrase).unwrap();
        let dir = keystore.agent_dir(&agent);
        let yaml = template_manifest(&agent, &[governor], "Test lifecycle controls");
        agent_store::create_manifest(&dir, &yaml).unwrap();
        std::fs::write(dir.join("name"), "Lifecycle test").unwrap();
        std::fs::write(dir.join("active"), b"1").unwrap();
        let app = build_router(state.clone());

        let archive = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/agents/{agent}/archive"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"archived":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(archive.status(), StatusCode::OK);
        assert!(dir.join("archived").exists());
        assert!(!dir.join("active").exists());

        let roster = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/agents")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(roster.status(), StatusCode::OK);
        let roster_body = axum::body::to_bytes(roster.into_body(), usize::MAX)
            .await
            .unwrap();
        let roster: serde_json::Value = serde_json::from_slice(&roster_body).unwrap();
        assert_eq!(roster["agents"][0]["archived"], true);

        let run_while_archived = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/agents/{agent}/active"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"active":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(run_while_archived.status(), StatusCode::CONFLICT);

        let wrong_confirmation = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/agents/{agent}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"confirmation":"Lifecycle test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_confirmation.status(), StatusCode::BAD_REQUEST);
        assert!(dir.exists());

        let delete = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/agents/{agent}"))
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"confirmation":"{agent}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(delete.status(), StatusCode::OK);
        assert!(!dir.exists());
        let _ = std::fs::remove_dir_all(&state.home);
    }

    #[tokio::test]
    async fn every_control_plane_response_is_marked_no_store() {
        let app = build_router(test_state(AuthMode::Nip98));
        for path in [
            "/",
            "/app.js",
            "/cockpit-api.js",
            "/cockpit-inference.js",
            "/api/status",
        ] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.headers().get(axum::http::header::CACHE_CONTROL),
                Some(&axum::http::HeaderValue::from_static("no-store")),
                "missing private cache boundary on {path}"
            );
            if path.ends_with(".js") {
                assert_eq!(response.status(), StatusCode::NOT_FOUND);
            }
        }
    }

    #[tokio::test]
    async fn health_is_public_but_nip98_readiness_requires_a_manager() {
        let app = build_router(test_state(AuthMode::Nip98));
        let health = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);
        let readiness = app
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(readiness.status(), StatusCode::SERVICE_UNAVAILABLE);

        let open = build_router(test_state(AuthMode::Open))
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(open.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn ssh_desktop_credential_opens_only_a_manager_bound_session() {
        let manager = Keys::generate().public_key();
        let token = "11".repeat(32);
        let app = build_router(test_state_with(
            AuthMode::Nip98,
            vec![manager],
            Some(&token),
        ));
        let request = |authorization: Option<String>| {
            let mut request = Request::builder()
                .method("POST")
                .uri("/api/desktop/session")
                .header("content-type", "application/json");
            if let Some(authorization) = authorization {
                request = request.header("authorization", authorization);
            }
            request.body(Body::from("{}")).unwrap()
        };

        let refused = app.clone().oneshot(request(None)).await.unwrap();
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);

        let accepted = app
            .clone()
            .oneshot(request(Some(format!("Bearer {token}"))))
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);
        let cookie = accepted
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(cookie.starts_with("apiary_session="));
        assert!(!cookie.contains("Secure"));
        let cookie = cookie.split(';').next().unwrap();

        let cockpit = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cockpit.status(), StatusCode::OK);
        let body = axum::body::to_bytes(cockpit.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&body).contains("New agent"));
    }
    #[test]
    fn cockpit_workspace_fields_rehydrate_from_agent_state() {
        let renderer = include_str!("cockpit.js");

        assert!(renderer.contains("function workspaceDraftKey"));
        assert!(renderer.contains("manifest.presence && manifest.presence.buzz"));
        assert!(renderer.contains("relayInput(configuredRelay)"));
        assert!(renderer.contains("inp.oninput = () => saveWorkspaceDraft('relay'"));
        assert!(renderer.contains("pName.value = workspaceDraft('profile.name'"));
        assert!(renderer.contains("pAbout.value = workspaceDraft('profile.about'"));
        assert!(renderer.contains("workspaceDraft('channel.id')"));
        assert!(renderer.contains("saveWorkspaceDraft('channel.id', id)"));
        assert!(renderer.contains("saveWorkspaceDraft('channel.name', displayName)"));
        assert!(!renderer.contains("saveWorkspaceDraft('message"));
        assert!(!renderer.contains("saveWorkspaceDraft('credential"));
        assert!(!renderer.contains("saveWorkspaceDraft('passphrase"));
    }
}
