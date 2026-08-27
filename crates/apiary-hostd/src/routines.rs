//! Routine firing — the supervisor's clock side (SCOPE_routines).
//!
//! Every 10s tick: for each ACTIVE agent with `manifest.routines`, ask the
//! schedule engine which routines are due; for each, check the gates
//! (ratified, unlocked, lease held or uncoordinated, not already running),
//! then fire a governed run in a blocking task, deliver the reply through
//! the surfaces the agent already has, and write `routine.run` /
//! `routine.skipped` entries into the signed log. `routines.json` records
//! the slot so nothing fires twice for it.
//!
//! What this deliberately is not: a workflow engine. One routine = one
//! governed run = the runner's bounded loop.

use crate::{admit_agent, agent_decision, ceremony, App};
use apiary_core::keystore::Keystore;
use apiary_core::log::{EntryBody, EpisodicLog, Tier};
use apiary_core::manifest::{Delivery, Manifest, Routine};
use apiary_runtime::routines::{due_slot, jitter_secs, parse_schedule, RoutinesFile, Schedule};
use chrono::{DateTime, Utc};
use serde_json::json;
use std::sync::atomic::Ordering;
use std::sync::{Mutex, OnceLock};

/// Routines in flight, keyed "npub/name" — the overlap guard.
fn running() -> &'static Mutex<std::collections::HashSet<String>> {
    static R: OnceLock<Mutex<std::collections::HashSet<String>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(Default::default()))
}

/// One supervisor tick over all agents.
pub fn reconcile_routines(state: &App) {
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
        if manifest.routines.is_empty() {
            continue;
        }
        let file = RoutinesFile::open(&dir);
        let mut st = file.load();
        if st.since.is_none() {
            // First sight on this host: catch_up never reaches back before now.
            st.since = Some(now);
            let _ = file.save(&st);
        }
        let since = st.since.unwrap_or(now);
        for r in &manifest.routines {
            let sched = match parse_schedule(r) {
                Ok(s) => s,
                Err(e) => {
                    note(state, &npub, &r.name, format!("schedule error: {e}"));
                    continue;
                }
            };
            let rec = st.routines.entry(r.name.clone()).or_default().clone();
            let Some(slot) = due_slot(&sched, r, &rec, since, now) else {
                continue;
            };
            // Jitter: fire a little after the slot, deterministically.
            let fire_at = slot + chrono::Duration::seconds(jitter_secs(&r.name, slot));
            if now < fire_at {
                continue;
            }
            let key = format!("{npub}/{}", r.name);
            // Gates that skip THIS slot (recorded so we don't retry it every tick).
            if let Some(reason) = gate(state, &npub, &raw, &manifest, &dir, &key) {
                match reason.as_str() {
                    // Transient: try the same slot next tick.
                    "locked" | "lease-not-held" | "overlap" => {
                        note(state, &npub, &r.name, format!("waiting: {reason}"));
                        continue;
                    }
                    _ => {
                        skip(&dir, state, &npub, &r.name, slot, &reason);
                        let e = st.routines.entry(r.name.clone()).or_default();
                        e.last_scheduled = Some(slot);
                        e.last_outcome = Some(format!("skipped: {reason}"));
                        let _ = file.save(&st);
                        continue;
                    }
                }
            }
            // Claim the slot BEFORE firing: a crash mid-run must not refire it.
            {
                let e = st.routines.entry(r.name.clone()).or_default();
                e.last_scheduled = Some(slot);
                e.last_fired = Some(now);
                e.fires += 1;
                if matches!(sched, Schedule::At(_)) {
                    e.spent = true;
                }
                let _ = file.save(&st);
            }
            running().lock().unwrap().insert(key.clone());
            let st_state = state.clone();
            let r2 = r.clone();
            let m2 = manifest.clone();
            let dir2 = dir.clone();
            let npub2 = npub.clone();
            tokio::task::spawn_blocking(move || {
                let outcome = fire(&st_state, &npub2, &m2, &r2, &dir2, slot);
                // Record outcome + delivery.
                let f = RoutinesFile::open(&dir2);
                let mut s = f.load();
                let e = s.routines.entry(r2.name.clone()).or_default();
                e.last_outcome = Some(outcome.0);
                e.last_delivery = Some(outcome.1);
                let _ = f.save(&s);
                running().lock().unwrap().remove(&key);
            });
        }
    }
}

pub(crate) fn note(state: &App, npub: &str, name: &str, msg: String) {
    state
        .supervisor_notes
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(format!("{npub}:routine:{name}"), msg);
}

/// None = clear to fire. Some(reason) = don't. Shared with watches:
/// an event-triggered run passes exactly the gates a scheduled one does.
pub(crate) fn gate(
    state: &App,
    npub: &str,
    raw: &str,
    manifest: &Manifest,
    dir: &std::path::Path,
    key: &str,
) -> Option<String> {
    if running().lock().unwrap().contains(key) {
        return Some("overlap".into());
    }
    if state.passphrase_clone().is_none() {
        return Some("locked".into());
    }
    // Lease: presence keeper (if any) must not be lost; an agent that
    // declares log_relays but whose keeper isn't up yet waits.
    {
        let map = state.listeners.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(npub).and_then(|p| p.keeper.as_ref()) {
            Some(k) if k.lost.load(Ordering::Relaxed) => return Some("lease-not-held".into()),
            Some(_) => {}
            None => {
                if !manifest.memory.log_relays.is_empty() {
                    return Some("lease-not-held".into());
                }
                // No relays: uncoordinated, like presence — allowed, noted.
            }
        }
    }
    if !agent_decision(state, dir, npub, raw, manifest).ratified {
        return Some("not ratified".into());
    }
    None
}

fn skip(
    dir: &std::path::Path,
    state: &App,
    npub: &str,
    name: &str,
    slot: DateTime<Utc>,
    reason: &str,
) {
    note(
        state,
        npub,
        name,
        format!("skipped {}: {reason}", slot.to_rfc3339()),
    );
    // The signed record sees skips too — but only if we can sign.
    if let Ok(ks) = Keystore::open(&state.home) {
        if let Ok((custody, handle)) = admit_agent(state, &ks, npub) {
            let _ = EpisodicLog::open(dir).append(
                &custody,
                &handle,
                Tier::Self_,
                &EntryBody {
                    action: "routine.skipped".into(),
                    model: None,
                    cost: None,
                    harness: None,
                    outcome: reason.into(),
                    detail: Some(json!({"routine": name, "scheduled_for": slot.to_rfc3339()})),
                },
            );
        }
    }
}

/// Run + deliver + record. Returns (outcome, delivery report).
fn fire(
    state: &App,
    npub: &str,
    manifest: &Manifest,
    r: &Routine,
    dir: &std::path::Path,
    slot: DateTime<Utc>,
) -> (String, serde_json::Value) {
    let fired_at = Utc::now();
    let Ok(ks) = Keystore::open(&state.home) else {
        return ("error: keystore".into(), json!(null));
    };
    let (custody, handle) = match admit_agent(state, &ks, npub) {
        Ok(v) => v,
        Err(e) => return (format!("error: {e}"), json!(null)),
    };
    let log = EpisodicLog::open(dir);
    let ctx = apiary_runtime::routing::TaskContext {
        task_class: Some(r.class.clone()),
        tokens_per_run: r.budget.tokens_per_run,
        ..Default::default()
    };
    // The task is a ratified STANDING INSTRUCTION; frame the occasion. When
    // the routine declares delivery, the run PRODUCES the text and the host
    // delivers it — otherwise a model holding telegram_send sends the
    // greeting itself and the delivery sends it again.
    let delivery_note = if r.deliver.is_empty() {
        String::new()
    } else {
        let targets: Vec<String> = r
            .deliver
            .iter()
            .map(|d| {
                if let Some(c) = &d.telegram {
                    format!("Telegram chat {c}")
                } else if let Some(c) = &d.buzz {
                    format!("Buzz #{c}")
                } else if d.nostr.is_some() {
                    "a public nostr note".into()
                } else if d.companion {
                    "the human's voice companion".into()
                } else {
                    "?".into()
                }
            })
            .collect();
        format!(
            " Your reply text is delivered by the host to {} — write the message itself as your \
             reply; do NOT send it with a tool.",
            targets.join(", ")
        )
    };
    let task = format!(
        "{}\n\n(This is your routine \"{}\", running on schedule at {} — nobody is watching in \
         real time. Do the task, be concise, and if there is nothing to report say so in one \
         line.{delivery_note})",
        r.task.trim(),
        r.name,
        slot.to_rfc3339()
    );
    let result = apiary_runtime::runner::run_task(manifest, dir, &custody, &handle, &task, &ctx);
    if result.is_ok() {
        apiary_runtime::index::schedule_refresh(manifest.clone(), dir.to_path_buf());
    }
    let (outcome, text, run_event) = match &result {
        Ok(out) => (
            out.completion.outcome.clone(),
            out.completion.text.trim().to_string(),
            Some(out.log_event_id.clone()),
        ),
        Err(e) => (format!("error: {e}"), String::new(), None),
    };
    // Deliver (only on success with text).
    let mut delivered = Vec::new();
    if result.is_ok() && !text.is_empty() {
        for d in &r.deliver {
            delivered.push(deliver(
                state, manifest, &custody, &handle, npub, &r.name, d, &text,
            ));
        }
    }
    let report = json!(delivered);
    let _ = log.append(
        &custody,
        &handle,
        Tier::Self_,
        &EntryBody {
            action: "routine.run".into(),
            model: result.as_ref().ok().map(|o| o.completion.model.clone()),
            cost: None,
            harness: Some("native".into()),
            outcome: outcome.clone(),
            detail: Some(json!({
                "routine": r.name,
                "scheduled_for": slot.to_rfc3339(),
                "fired_at": fired_at.to_rfc3339(),
                "run_event": run_event,
                "delivered": report,
                "response_chars": text.len(),
            })),
        },
    );
    note(
        state,
        npub,
        &r.name,
        format!("fired {} → {outcome}", slot.to_rfc3339()),
    );
    (outcome, report)
}

/// One delivery target. Uses the same paths as presence replies and
/// telegram_send — same allowlists, same voice behavior.
#[allow(clippy::too_many_arguments)]
pub(crate) fn deliver(
    state: &App,
    manifest: &Manifest,
    custody: &apiary_core::custody::Custody,
    handle: &apiary_core::custody::AgentHandle,
    npub: &str,
    routine: &str,
    d: &Delivery,
    text: &str,
) -> serde_json::Value {
    // Voice for the targets that support it.
    let audio = if d.as_voice {
        apiary_runtime::speak::speak_slot(manifest).and_then(|slot| {
            let cred = slot
                .credential
                .as_ref()
                .and_then(|b| custody.open(handle, b).ok());
            apiary_runtime::speak::bind_speaker(manifest, cred).and_then(|sp| {
                sp.speak(text)
                    .and_then(|s| apiary_runtime::speak::to_ogg_opus(&s))
                    .ok()
                    .map(|s| {
                        use base64::Engine;
                        apiary_runtime::presence::Attachment::Audio {
                            media_type: s.media_type,
                            base64: base64::engine::general_purpose::STANDARD.encode(&s.bytes),
                            duration_secs: s.duration_secs,
                        }
                    })
            })
        })
    } else {
        None
    };
    let reply = apiary_runtime::presence::Reply {
        text: text.to_string(),
        audio,
    };

    if let Some(chat) = &d.telegram {
        let Some(tg) = manifest.presence.channel("telegram") else {
            return json!({"telegram": chat, "error": "no telegram presence"});
        };
        let allowed = tg.list_config("allowed_chats");
        if !allowed.iter().any(|c| c == "*" || c == chat) {
            return json!({"telegram": chat, "error": "chat not in allowed_chats"});
        }
        let Some(blob) = &tg.credential else {
            return json!({"telegram": chat, "error": "no sealed token"});
        };
        let token = match custody.open(handle, blob) {
            Ok(t) => t,
            Err(e) => return json!({"telegram": chat, "error": e.to_string()}),
        };
        let Ok(chat_id) = chat.parse::<i64>() else {
            return json!({"telegram": chat, "error": "chat id not numeric"});
        };
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("client");
        return match apiary_runtime::telegram::send_reply(
            &client,
            token.as_str(),
            chat_id,
            None,
            &reply,
        ) {
            Ok(id) => json!({"telegram": chat, "message_id": id, "voice": reply.audio.is_some()}),
            Err(e) => json!({"telegram": chat, "error": e.to_string()}),
        };
    }
    if let Some(channel) = &d.buzz {
        let Some(bz) = manifest.presence.channel("buzz") else {
            return json!({"buzz": channel, "error": "no buzz presence"});
        };
        let Some(relay) = bz.str_config("relay") else {
            return json!({"buzz": channel, "error": "presence.buzz.relay missing"});
        };
        return match apiary_runtime::buzz::BuzzSession::connect(relay, custody, handle) {
            Ok(mut s) => match resolve_buzz_channel(&mut s, channel) {
                Some(uuid) => match s.post(&uuid, text, &[]) {
                    Ok(ev) => json!({"buzz": channel, "event": ev.id.to_hex()}),
                    Err(e) => json!({"buzz": channel, "error": e.to_string()}),
                },
                None => json!({"buzz": channel, "error": "channel not found on relay"}),
            },
            Err(e) => json!({"buzz": channel, "error": e.to_string()}),
        };
    }
    if d.nostr.as_deref() == Some("publish") {
        let relays: Vec<String> = manifest
            .connectors
            .iter()
            .filter(|c| c.kind == "nostr-publish")
            .filter_map(|c| c.caps.get("relays").and_then(|v| v.as_array()).cloned())
            .flatten()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        if relays.is_empty() {
            return json!({"nostr": "publish", "error": "no nostr-publish relays"});
        }
        let event = match custody.sign(
            handle,
            nostr::prelude::EventBuilder::new(nostr::prelude::Kind::TextNote, text),
        ) {
            Ok(e) => e,
            Err(e) => return json!({"nostr": "publish", "error": e.to_string()}),
        };
        let mut acks = Vec::new();
        for r in &relays {
            acks.push(match apiary_runtime::relay::publish(r, &event) {
                Ok(m) => json!({"relay": r, "ok": m}),
                Err(e) => json!({"relay": r, "error": e.to_string()}),
            });
        }
        return json!({"nostr": "publish", "event": event.id.to_hex(), "relays": acks});
    }
    if d.companion {
        // The live bus: spoken by whichever apiary-voice is subscribed.
        // Nobody listening → recorded as undelivered (the log still has
        // the text; a chat target on the same routine still gets its copy).
        let _ = state;
        let n = crate::events::publish(json!({
            "type": "routine.delivered",
            "npub": npub,
            "routine": routine,
            "text": text,
            "as_voice": d.as_voice,
        }));
        return if n > 0 {
            json!({"companion": true, "subscribers": n})
        } else {
            json!({"companion": true, "undelivered": "no companion connected"})
        };
    }
    json!({"error": "no target"})
}

/// Buzz channels are addressed by uuid on the wire; routines name them.
/// Accept a uuid directly, else match the kind-39000 metadata name.
fn resolve_buzz_channel(s: &mut apiary_runtime::buzz::BuzzSession, name: &str) -> Option<String> {
    if name.len() == 36 && name.matches('-').count() == 4 {
        return Some(name.to_string());
    }
    let events = s.channels().ok()?;
    for ev in events {
        let matches_name = ev.tags.iter().any(|t| {
            let v = t.clone().to_vec();
            v.len() >= 2 && (v[0] == "name" || v[0] == "d") && v[1].eq_ignore_ascii_case(name)
        }) || serde_json::from_str::<serde_json::Value>(&ev.content)
            .ok()
            .and_then(|c| c["name"].as_str().map(|n| n.eq_ignore_ascii_case(name)))
            .unwrap_or(false);
        if matches_name {
            // The channel id is the d-tag.
            if let Some(d) = ev.tags.iter().find_map(|t| {
                let v = t.clone().to_vec();
                (v.len() >= 2 && v[0] == "d").then(|| v[1].clone())
            }) {
                return Some(d);
            }
        }
    }
    None
}

// ------------------------------------------------------------- endpoints

use axum::extract::{OriginalUri, Path as AxPath, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

/// GET /api/agents/{npub}/routines — schedule (constitutional) + host
/// state (routines.json) + next fires in the routine's zone.
pub async fn list_routines(
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
    let st = RoutinesFile::open(&dir).load();
    let now = Utc::now();
    let notes = state
        .supervisor_notes
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let running_now = running().lock().unwrap().clone();
    let items: Vec<serde_json::Value> = manifest
        .routines
        .iter()
        .map(|r| {
            let rec = st.routines.get(&r.name).cloned().unwrap_or_default();
            let (next, preview, sched_err) = match parse_schedule(r) {
                Ok(s) => {
                    let after = rec.last_scheduled.unwrap_or(now);
                    let anchor = rec.last_fired.or(st.since);
                    let next = if r.enabled && !rec.paused && !rec.spent {
                        s.next_after(after.max(now - chrono::Duration::seconds(1)), anchor)
                    } else {
                        None
                    };
                    (next, s.preview(now, 3), None)
                }
                Err(e) => (None, vec![], Some(e.to_string())),
            };
            json!({
                "name": r.name,
                "when": r.when, "every": r.every, "at": r.at, "tz": r.tz,
                "task": r.task,
                "class": r.class,
                "deliver": r.deliver,
                "budget": r.budget,
                "catch_up": r.catch_up,
                "enabled": r.enabled,
                "paused": rec.paused,
                "spent": rec.spent,
                "fires": rec.fires,
                "running": running_now.contains(&format!("{npub}/{}", r.name)),
                "last_scheduled": rec.last_scheduled,
                "last_fired": rec.last_fired,
                "last_outcome": rec.last_outcome,
                "last_delivery": rec.last_delivery,
                "next_fire": next,
                "preview": preview,
                "schedule_error": sched_err,
                "note": notes.get(&format!("{npub}:routine:{}", r.name)),
            })
        })
        .collect();
    Json(json!({
        "ok": true,
        "npub": npub,
        "since": st.since,
        "coordinated": !manifest.memory.log_relays.is_empty(),
        "routines": items,
    }))
    .into_response()
}

/// POST /api/agents/{npub}/routines/{name}/run — fire now (operator door:
/// a governor at a keyboard). Same gates as a scheduled fire except the
/// clock; recorded as a routine.run with "manual": true.
pub async fn run_routine_now(
    State(state): State<App>,
    AxPath((npub, name)): AxPath<(String, String)>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (_ks, npub, dir, raw, manifest) =
        match crate::ops::gate_pub(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    if let Err(e) = manifest.validate() {
        return crate::err(
            StatusCode::CONFLICT,
            format!("manifest is invalid — fix and re-ratify before firing routines: {e}"),
        )
        .into_response();
    }
    let Some(r) = manifest.routines.iter().find(|r| r.name == name).cloned() else {
        return crate::err(StatusCode::NOT_FOUND, format!("no routine '{name}'")).into_response();
    };
    let key = format!("{npub}/{name}");
    if let Some(reason) = gate(&state, &npub, &raw, &manifest, &dir, &key) {
        return crate::err(StatusCode::CONFLICT, format!("cannot fire now: {reason}"))
            .into_response();
    }
    running().lock().unwrap().insert(key.clone());
    let st2 = state.clone();
    let out = tokio::task::spawn_blocking(move || {
        let res = fire(&st2, &npub, &manifest, &r, &dir, Utc::now());
        let f = RoutinesFile::open(&dir);
        let mut s = f.load();
        let e = s.routines.entry(r.name.clone()).or_default();
        e.last_fired = Some(Utc::now());
        e.fires += 1;
        e.last_outcome = Some(res.0.clone());
        e.last_delivery = Some(res.1.clone());
        let _ = f.save(&s);
        running().lock().unwrap().remove(&key);
        res
    })
    .await
    .unwrap_or_else(|e| (format!("error: {e}"), json!(null)));
    Json(json!({"ok": true, "outcome": out.0, "delivered": out.1})).into_response()
}

/// POST /api/agents/{npub}/routines/{name}/pause | resume — host-local,
/// no amendment (like `active`).
pub async fn pause_routine(
    State(state): State<App>,
    AxPath((npub, name, action)): AxPath<(String, String, String)>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (_ks, _npub, dir, _raw, manifest) =
        match crate::ops::gate_pub(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    if !manifest.routines.iter().any(|r| r.name == name) {
        return crate::err(StatusCode::NOT_FOUND, format!("no routine '{name}'")).into_response();
    }
    let paused = match action.as_str() {
        "pause" => true,
        "resume" => false,
        other => {
            return crate::err(StatusCode::BAD_REQUEST, format!("unknown action '{other}'"))
                .into_response()
        }
    };
    let f = RoutinesFile::open(&dir);
    let mut s = f.load();
    s.routines.entry(name.clone()).or_default().paused = paused;
    if let Err(e) = f.save(&s) {
        return crate::err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
    }
    Json(json!({"ok": true, "routine": name, "paused": paused})).into_response()
}

// ------------------------------------------------------------- proposals

/// GET /api/agents/{npub}/proposal — the pending agent-drafted amendment,
/// if any, with the current YAML for a diff.
pub async fn get_proposal(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (_ks, _npub, dir, raw, _manifest) =
        match crate::ops::gate_pub(&state, &headers, "GET", &uri, None, &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    match apiary_runtime::proposal::read_proposal(&dir) {
        Some((yaml, meta)) => Json(json!({
            "ok": true, "pending": true, "proposed_yaml": yaml, "current_yaml": raw,
            "reason": meta.reason, "summary": meta.summary, "at": meta.at, "kind": meta.kind,
        }))
        .into_response(),
        None => Json(json!({"ok": true, "pending": false})).into_response(),
    }
}

/// GET /api/agents/{npub}/founding-proposal — the pending request to found
/// a NEW agent, if any (SCOPE_hal-project-management).
pub async fn get_founding_proposal(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (_ks, _npub, dir, _raw, _manifest) =
        match crate::ops::gate_pub(&state, &headers, "GET", &uri, None, &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    match apiary_runtime::proposal::read_founding_request(&dir) {
        Some(request) => Json(json!({"ok": true, "pending": true, "request": request})).into_response(),
        None => Json(json!({"ok": true, "pending": false})).into_response(),
    }
}

/// POST /api/agents/{npub}/founding-proposal/{decision} — approve (the
/// cockpit prefills the founding flow from the returned request; the
/// ceremony itself stays the ordinary human path) or reject (optional body
/// {"reason": …}). Both land in the requesting agent's signed log, so the
/// agent can read the outcome.
pub async fn decide_founding_proposal(
    State(state): State<App>,
    AxPath((npub, decision)): AxPath<(String, String)>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (ks, npub, dir, _raw, manifest) =
        match crate::ops::gate_pub(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let Some(request) = apiary_runtime::proposal::read_founding_request(&dir) else {
        return crate::err(StatusCode::NOT_FOUND, "no pending founding request").into_response();
    };
    let accepted = match decision.as_str() {
        "accept" => true,
        "reject" => false,
        other => {
            return crate::err(
                StatusCode::BAD_REQUEST,
                format!("unknown decision '{other}'"),
            )
            .into_response()
        }
    };
    let governor_reason = serde_json::from_slice::<serde_json::Value>(&raw_body)
        .ok()
        .and_then(|v| v.get("reason").and_then(|r| r.as_str()).map(String::from))
        .unwrap_or_default();

    // APPROVAL IS THE DOOR. Building exactly what the governor approved is
    // executing their decision, not a new authority — so approving founds
    // the agent rather than handing back a form to retype.
    //
    // The invariants that make that safe:
    //   * The new agent is governed by the HUMANS who govern the requester.
    //     An agent can never end up governing a colleague it asked for.
    //   * It arrives unratified and inactive. Founding creates; ratification
    //     animates. Nothing of it runs until a human signs.
    //   * Capabilities are NOT auto-granted. Credentials are sealed per
    //     agent and grants are their own ratified act; the request's list is
    //     reported back so the governor knows what remains to hand over.
    let mut founded = serde_json::Value::Null;
    if accepted {
        let governors: Vec<String> = manifest.governance.suspend_keys.clone();
        if governors.iter().any(|g| g == &npub) {
            return crate::err(
                StatusCode::CONFLICT,
                "the requesting agent governs itself — refusing to found a colleague under it",
            )
            .into_response();
        }
        if governors.is_empty() {
            return crate::err(
                StatusCode::CONFLICT,
                "the requesting agent has no human governors to inherit — refusing to found",
            )
            .into_response();
        }
        match crate::create_agent(
            &state,
            &request.name,
            &request.purpose,
            &governors,
            None,
            Some(&request),
        )
        .await
        {
            Ok((new_npub, _yaml, built_from)) => {
                founded = json!({
                    "npub": new_npub,
                    "name": request.name,
                    "built_from": built_from,
                    "governors": governors,
                    "ratified": false,
                    "still_to_grant": request.connectors,
                    "skills_requested": request.skills,
                });
            }
            Err((code, message)) => return crate::err(code, message).into_response(),
        }
    }
    apiary_runtime::proposal::clear_founding_request(&dir);
    if let Ok((custody, handle)) = admit_agent(&state, &ks, &npub) {
        let _ = EpisodicLog::open(&dir).append(
            &custody,
            &handle,
            Tier::Self_,
            &EntryBody {
                action: if accepted {
                    "founding.approved"
                } else {
                    "founding.rejected"
                }
                .into(),
                model: None,
                cost: None,
                harness: None,
                outcome: format!("founding request '{}'", request.name),
                detail: Some(json!({
                    "request": request,
                    "governor_reason": governor_reason,
                    "founded": founded,
                })),
            },
        );
    }
    Json(json!({
        "ok": true, "accepted": accepted, "request": request, "founded": founded,
        "note": if accepted {
            "founded from the approved request, unratified and inactive — review its \
             configuration and ratify; capabilities it asked for still need granting"
        } else {
            "rejected and recorded where the agent can read it"
        },
    }))
    .into_response()
}

/// POST /api/agents/{npub}/proposal/{decision} — accept (write the manifest;
/// ratify next) or reject. Governor. Both are signed log entries.
pub async fn decide_proposal(
    State(state): State<App>,
    AxPath((npub, decision)): AxPath<(String, String)>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (ks, npub, dir, raw, current) =
        match crate::ops::gate_pub(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let Some((yaml, meta)) = apiary_runtime::proposal::read_proposal(&dir) else {
        return crate::err(StatusCode::NOT_FOUND, "no pending proposal").into_response();
    };
    let accepted = match decision.as_str() {
        "accept" => true,
        "reject" => false,
        other => {
            return crate::err(
                StatusCode::BAD_REQUEST,
                format!("unknown decision '{other}'"),
            )
            .into_response()
        }
    };
    if accepted {
        // Re-check at decision time: the rules the agent could not break.
        let candidate = match Manifest::from_yaml(&yaml) {
            Ok(m) => m,
            Err(e) => {
                return crate::err(
                    StatusCode::CONFLICT,
                    format!("proposal no longer valid: {e}"),
                )
                .into_response()
            }
        };
        if candidate.identity.npub != current.identity.npub
            || candidate.governance.suspend_keys != current.governance.suspend_keys
        {
            return crate::err(
                StatusCode::CONFLICT,
                "proposal touches identity or governors — refused",
            )
            .into_response();
        }
        if let Err(error) = crate::agent_store::replace_manifest(&dir, &raw, &yaml) {
            return match error {
                crate::agent_store::StoreError::Conflict { current_revision } => (
                    StatusCode::CONFLICT,
                    Json(json!({
                        "ok": false,
                        "error": "the agent changed while this proposal was being reviewed; reload it before deciding",
                        "code": "manifest_revision_conflict",
                        "current_revision": current_revision,
                    })),
                )
                    .into_response(),
                crate::agent_store::StoreError::Io(error) => {
                    crate::err(StatusCode::INTERNAL_SERVER_ERROR, error).into_response()
                }
            };
        }
    }
    apiary_runtime::proposal::clear_proposal(&dir);
    if let Ok((custody, handle)) = admit_agent(&state, &ks, &npub) {
        let _ = EpisodicLog::open(&dir).append(
            &custody,
            &handle,
            Tier::Self_,
            &EntryBody {
                action: if accepted {
                    "amendment.accepted"
                } else {
                    "amendment.rejected"
                }
                .into(),
                model: None,
                cost: None,
                harness: None,
                outcome: meta.summary.clone(),
                detail: Some(
                    json!({"reason": meta.reason, "kind": meta.kind, "proposed_at": meta.at}),
                ),
            },
        );
    }
    Json(json!({
        "ok": true, "accepted": accepted,
        "manifest_sha256": if accepted { Some(ceremony::manifest_hash(&yaml)) } else { None },
        "note": if accepted { "written — ratify in the Manifest tab; nothing runs until then" } else { "rejected and removed" },
    }))
    .into_response()
}
