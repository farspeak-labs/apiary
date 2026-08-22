//! Watch firing — the supervisor's event side (SCOPE_proactive-agents).
//!
//! Every 10s tick, beside `reconcile_routines`: for each ACTIVE agent with
//! `manifest.watches`, scan what it watches, and when a debounced change is
//! ready, fire an ordinary governed run. Same gates as a routine (ratified,
//! unlocked, lease held, not already running) — an event-triggered run is
//! not a privileged one. The difference is the budget: this run draws on the
//! proactive allowance, because nobody asked for it.
//!
//! Silence is the expected outcome. A run that changed nothing is recorded
//! as `watch.quiet` and delivers nothing; the cockpit counts those so an
//! agent doing nothing and an agent that is broken do not look alike.

use crate::{admit_agent, routines::gate, routines::note, App};
use apiary_core::keystore::Keystore;
use apiary_core::log::{EntryBody, EpisodicLog, Tier};
use apiary_core::manifest::{Manifest, Watch};
use apiary_runtime::watches::{scan_vault, step, task_text, Step, WatchesFile};
use chrono::Utc;
use serde_json::json;
use std::sync::{Mutex, OnceLock};

/// Watch runs in flight, keyed "npub/name" — the overlap guard.
fn running() -> &'static Mutex<std::collections::HashSet<String>> {
    static R: OnceLock<Mutex<std::collections::HashSet<String>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(Default::default()))
}

/// One supervisor tick over all agents' watches.
pub fn reconcile_watches(state: &App) {
    let Ok(ks) = Keystore::open(&state.home) else {
        return;
    };
    let Ok(agents) = ks.list() else {
        return;
    };
    let now = Utc::now();
    for npub in agents {
        let dir = ks.agent_dir(&npub);
        if !crate::ops::is_active(&dir) {
            continue;
        }
        let raw = std::fs::read_to_string(dir.join("manifest.yaml")).unwrap_or_default();
        let Ok(manifest) = Manifest::from_yaml(&raw) else {
            continue; // presence reconcile already noted the load failure
        };
        if manifest.watches.is_empty() {
            continue;
        }
        let file = WatchesFile::open(&dir);
        let mut state_file = file.load();
        for w in &manifest.watches {
            if !w.enabled {
                continue;
            }
            let key = format!("{npub}/{}", w.name);
            // Scan first: changes are recorded even while a gate holds the
            // fire, so a locked keystore loses nothing but the timing.
            let record = state_file.watches.entry(w.name.clone()).or_default();
            let changes = match w.on.as_str() {
                "vault" => {
                    let Some(path) = w
                        .vault
                        .as_deref()
                        .and_then(|name| manifest.memory.vaults.iter().find(|v| v.name == name))
                        .map(|v| v.path.clone())
                    else {
                        continue;
                    };
                    scan_vault(
                        std::path::Path::new(&path),
                        record.seen_through,
                        w.match_path.as_deref(),
                    )
                }
                _ => continue,
            };
            match step(w, record, changes, now) {
                Step::Wait => {}
                Step::Refused { seen } => {
                    note(
                        state,
                        &npub,
                        &w.name,
                        format!(
                            "{seen} change(s) seen after today's {} run limit — not queued; \
                             raise max_per_day if this is routinely too low",
                            w.max_per_day
                        ),
                    );
                }
                Step::Fire { paths } => {
                    // Gates last: they decide whether THIS fire happens now.
                    if let Some(reason) = gate(state, &npub, &raw, &manifest, &dir, &key) {
                        note(state, &npub, &w.name, format!("waiting: {reason}"));
                        // Put the fire back — a gate is a delay, not a loss.
                        record.pending_since = Some(now);
                        record.pending_paths = paths;
                        record.fires_today = record.fires_today.saturating_sub(1);
                        continue;
                    }
                    running().lock().unwrap().insert(key.clone());
                    let st = state.clone();
                    let w2 = w.clone();
                    let m2 = manifest.clone();
                    let dir2 = dir.clone();
                    let npub2 = npub.clone();
                    tokio::task::spawn_blocking(move || {
                        let (outcome, quiet) = fire(&st, &npub2, &m2, &w2, &dir2, &paths);
                        let f = WatchesFile::open(&dir2);
                        let mut s = f.load();
                        let e = s.watches.entry(w2.name.clone()).or_default();
                        e.last_outcome = Some(outcome);
                        // Absorb our own output: an agent that drafts into the
                        // folder it watches must not hear its own echo.
                        apiary_runtime::watches::absorb_through(e, chrono::Utc::now());
                        if quiet {
                            e.quiet_runs += 1;
                        } else {
                            e.acting_runs += 1;
                        }
                        let _ = f.save(&s);
                        running().lock().unwrap().remove(&key);
                    });
                }
            }
        }
        let _ = file.save(&state_file);
    }
}

/// Run one watch. Returns (outcome, quiet) — quiet meaning the run only
/// looked at the world, as judged by the host, not by the model.
fn fire(
    state: &App,
    npub: &str,
    manifest: &Manifest,
    w: &Watch,
    dir: &std::path::Path,
    paths: &[String],
) -> (String, bool) {
    let fired_at = Utc::now();
    let Ok(ks) = Keystore::open(&state.home) else {
        return ("error: keystore".into(), true);
    };
    let (custody, handle) = match admit_agent(state, &ks, npub) {
        Ok(v) => v,
        Err(e) => return (format!("error: {e}"), true),
    };
    let log = EpisodicLog::open(dir);
    let ctx = apiary_runtime::routing::TaskContext {
        task_class: Some("watch".into()),
        tokens_per_run: w.budget.tokens_per_run,
        lane: apiary_runtime::spend::Lane::Proactive,
        ..Default::default()
    };
    let vault = w.vault.clone().unwrap_or_default();
    let task = task_text(w, paths, &vault);
    let result = apiary_runtime::runner::run_task(manifest, dir, &custody, &handle, &task, &ctx);
    if result.is_ok() {
        apiary_runtime::index::schedule_refresh(manifest.clone(), dir.to_path_buf());
    }
    let (outcome, text, run_event, acted) = match &result {
        Ok(out) => (
            out.completion.outcome.clone(),
            out.completion.text.trim().to_string(),
            Some(out.log_event_id.clone()),
            out.acted,
        ),
        Err(e) => (format!("error: {e}"), String::new(), None, false),
    };
    let failed = result.is_err();
    let quiet = !acted && !failed;
    // Delivery is opt-in: a watch says nothing unless its ratified config
    // names a target. Otherwise the agent's own send tools are the voice.
    let mut delivered = Vec::new();
    if result.is_ok() && !text.is_empty() {
        for d in &w.deliver {
            delivered.push(crate::routines::deliver(
                state, manifest, &custody, &handle, npub, &w.name, d, &text,
            ));
        }
    }
    // A quiet run gets a compact body: it is worth knowing that it happened
    // and cost something, not worth storing what it decided not to do.
    let detail = if quiet {
        json!({
            "watch": w.name,
            "fired_at": fired_at.to_rfc3339(),
            "changed_paths": paths.len(),
            "run_event": run_event,
        })
    } else {
        json!({
            "watch": w.name,
            "fired_at": fired_at.to_rfc3339(),
            "changed": paths,
            "run_event": run_event,
            "delivered": delivered,
            "response_chars": text.len(),
        })
    };
    let _ = log.append(
        &custody,
        &handle,
        Tier::Self_,
        &EntryBody {
            action: if quiet { "watch.quiet" } else { "watch.run" }.into(),
            model: result.as_ref().ok().map(|o| o.completion.model.clone()),
            cost: None,
            harness: Some("native".into()),
            outcome: outcome.clone(),
            detail: Some(detail),
        },
    );
    note(
        state,
        npub,
        &w.name,
        format!(
            "{} {} change(s) → {}",
            if quiet { "observed" } else { "acted on" },
            paths.len(),
            outcome
        ),
    );
    (outcome, quiet)
}

// ------------------------------------------------------------- endpoints

use axum::{
    extract::{OriginalUri, Path as AxPath, State},
    response::IntoResponse,
    Json,
};

/// GET /api/agents/{npub}/watches — configured watches with their live
/// state: what is pending, what fired today, and how much of it was quiet.
pub async fn list_watches(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (_ks, npub, dir, _raw, manifest) =
        match crate::ops::gate_pub(&state, &headers, "GET", &uri, None, &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let st = WatchesFile::open(&dir).load();
    let notes = state
        .supervisor_notes
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let running_now = running().lock().unwrap().clone();
    let allowance =
        apiary_runtime::spend::proactive_tokens_per_day(&manifest.governance.budgets).unwrap_or(None);
    let items: Vec<serde_json::Value> = manifest
        .watches
        .iter()
        .map(|w| {
            let rec = st.watches.get(&w.name).cloned().unwrap_or_default();
            let vault_path = w
                .vault
                .as_deref()
                .and_then(|name| manifest.memory.vaults.iter().find(|v| v.name == name))
                .map(|v| v.path.clone());
            json!({
                "name": w.name,
                "on": w.on,
                "vault": w.vault,
                "vault_path": vault_path,
                "match": w.match_path,
                "task": w.task,
                "debounce": w.debounce,
                "max_per_day": w.max_per_day,
                "enabled": w.enabled,
                "deliver": w.deliver,
                "running": running_now.contains(&format!("{npub}/{}", w.name)),
                "pending_since": rec.pending_since,
                "pending_paths": rec.pending_paths,
                "fires_today": rec.fires_today,
                "last_fired": rec.last_fired,
                "last_outcome": rec.last_outcome,
                "quiet_runs": rec.quiet_runs,
                "acting_runs": rec.acting_runs,
                "note": notes.get(&format!("{npub}:routine:{}", w.name)),
            })
        })
        .collect();
    Json(json!({
        "ok": true,
        "watches": items,
        "proactive_allowance": allowance,
        "note": if allowance.unwrap_or(0) == 0 && !manifest.watches.is_empty() {
            Some("These watches cannot run: this agent has no proactive allowance. \
                  Set governance.budgets.proactive_tokens_per_day and ratify it.")
        } else {
            None
        },
    }))
    .into_response()
}
