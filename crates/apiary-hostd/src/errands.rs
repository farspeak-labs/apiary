//! Errand pickup — the supervisor's promise-keeping side (SCOPE_errands).
//!
//! A mention is one bounded run, so an agent asked for a draft could only
//! ever promise one. `follow_up` files the request instead; this is the
//! half that keeps it. Every 10s tick, beside `reconcile_routines` and
//! `reconcile_watches`: run what is due, deliver it back where it was
//! asked, and — the part that matters most — say so out loud when it
//! failed or went stale. Somebody is waiting on every row in this file.
//!
//! An errand run is an ordinary governed run: same gates, same lease, same
//! signed log. Two things are deliberately different. It spends the
//! RESPONSIVE lane, because a person asked for it and starving a requested
//! draft because a watch had a busy morning is the wrong failure; and it
//! carries `ask_requester` instead of `follow_up`, so an errand can ask a
//! question but can never file more work for itself.

use crate::{admit_agent, routines::gate, routines::note, App};
use apiary_core::keystore::Keystore;
use apiary_core::log::{EntryBody, EpisodicLog, Tier};
use apiary_core::manifest::{Delivery, Manifest};
use apiary_runtime::errands::{Errand, ErrandsFile, State};
use chrono::Utc;
use serde_json::json;
use std::sync::{Mutex, OnceLock};

/// Errand runs in flight, keyed "npub/id" — the overlap guard.
fn running() -> &'static Mutex<std::collections::HashSet<String>> {
    static R: OnceLock<Mutex<std::collections::HashSet<String>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(Default::default()))
}

/// Where an errand's result goes: back where it was asked, never anywhere
/// else. `None` means this host cannot deliver to that platform, which is
/// worth saying rather than silently dropping the work.
fn delivery_to(errand: &Errand) -> Option<Delivery> {
    let mut target = Delivery {
        telegram: None,
        buzz: None,
        nostr: None,
        companion: false,
        as_voice: false,
    };
    match errand.channel_kind.as_str() {
        "buzz" => target.buzz = Some(errand.channel.clone()),
        "telegram" => target.telegram = Some(errand.channel.clone()),
        _ => return None,
    }
    Some(target)
}

/// One supervisor tick over every agent's outstanding work.
pub fn reconcile_errands(state: &App) {
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
        let file = ErrandsFile::open(&dir);
        let mut errands = file.load();
        if errands.errands.is_empty() {
            continue;
        }
        let raw = std::fs::read_to_string(dir.join("manifest.yaml")).unwrap_or_default();
        let Ok(manifest) = Manifest::from_yaml(&raw) else {
            continue; // presence reconcile already noted the load failure
        };

        // 1. Anything gone stale is dropped — and SAID. Work quietly
        //    abandoned is the failure this whole primitive exists to
        //    prevent; a person is still waiting on every one of these.
        let mut stale: Vec<Errand> = Vec::new();
        for errand in errands.errands.iter_mut() {
            if errand.is_expired(now) {
                errand.state = State::Expired;
                errand.outcome = Some("not run in time".into());
                stale.push(errand.clone());
            }
        }
        errands.prune(now);
        let _ = file.save(&errands);
        for errand in stale {
            speak(
                state,
                &npub,
                &manifest,
                &dir,
                &errand,
                &format!(
                    "I did not get to this in time and have dropped it: {}. \
                     Ask me again if you still want it.",
                    errand.summary
                ),
                "errand.expired",
            );
        }

        // 2. One at a time per agent. Someone waiting on two things would
        //    rather have the first than half of both.
        let key_of = |errand: &Errand| format!("{npub}/{}", errand.id);
        let busy = running().lock().unwrap().clone();
        let Some(errand) = errands
            .errands
            .iter()
            .find(|errand| errand.is_runnable(now) && !busy.contains(&key_of(errand)))
            .cloned()
        else {
            continue;
        };
        if busy.iter().any(|k| k.starts_with(&format!("{npub}/"))) {
            continue;
        }
        let key = key_of(&errand);
        if let Some(reason) = gate(state, &npub, &raw, &manifest, &dir, &key) {
            note(state, &npub, &errand.id, format!("waiting: {reason}"));
            continue;
        }
        // Claim it before the run so a host that dies mid-errand leaves a
        // Running row that expires honestly rather than one that reruns
        // forever.
        if let Some(claim) = errands
            .errands
            .iter_mut()
            .find(|candidate| candidate.id == errand.id)
        {
            claim.state = State::Running;
        }
        let _ = file.save(&errands);
        running().lock().unwrap().insert(key.clone());

        let st = state.clone();
        let npub2 = npub.clone();
        let manifest2 = manifest.clone();
        let dir2 = dir.clone();
        tokio::task::spawn_blocking(move || {
            run_errand(&st, &npub2, &manifest2, &dir2, &errand);
            running().lock().unwrap().remove(&key);
        });
    }
}

/// Run one errand and settle it. Every exit from here either delivers
/// something or says why it could not — there is no silent path out.
fn run_errand(state: &App, npub: &str, manifest: &Manifest, dir: &std::path::Path, errand: &Errand) {
    let started = Utc::now();
    let Ok(ks) = Keystore::open(&state.home) else {
        return settle(state, npub, manifest, dir, errand, State::Failed, "keystore");
    };
    let (custody, handle) = match admit_agent(state, &ks, npub) {
        Ok(pair) => pair,
        Err(error) => {
            return settle(
                state,
                npub,
                manifest,
                dir,
                errand,
                State::Failed,
                &error.to_string(),
            )
        }
    };
    let ctx = apiary_runtime::routing::TaskContext {
        task_class: Some("errand".into()),
        tokens_per_run: Some(errand.tokens),
        // Responsive: a person asked for this. The bound comes from the
        // per-errand ceiling and the pending cap, not from the lane.
        lane: apiary_runtime::spend::Lane::Responsive,
        // An agent whose manifest names a work harness does its errands
        // there. This is what lets "ask in the channel, get a branch back"
        // work: the mention is answered by the native loop, and the work
        // it took on runs in a real coding loop afterwards.
        harness: manifest.routing.harness.clone(),
        errand_door: Some(apiary_runtime::errands::Door {
            agent_dir: dir.to_path_buf(),
            channel_kind: errand.channel_kind.clone(),
            channel: errand.channel.clone(),
            requested_by: errand.requested_by.clone(),
            reply_ref: errand.reply_ref.clone(),
            errand_id: Some(errand.id.clone()),
        }),
        ..Default::default()
    };
    let task = apiary_runtime::errands::task_text(errand);
    let result =
        apiary_runtime::runner::run_task(manifest, dir, &custody, &handle, &task, &ctx);
    if result.is_ok() {
        apiary_runtime::index::schedule_refresh(manifest.clone(), dir.to_path_buf());
    }

    // The run may have parked itself by asking. Re-read rather than trust
    // the copy we started with: `ask_requester` wrote to the same file.
    let file = ErrandsFile::open(dir);
    let reloaded = file.load();
    let current = reloaded
        .errands
        .iter()
        .find(|candidate| candidate.id == errand.id)
        .cloned();
    if let Some(asked) = current
        .as_ref()
        .filter(|candidate| candidate.state == State::Asked)
    {
        let question = asked.question.clone().unwrap_or_default();
        speak(
            state,
            npub,
            manifest,
            dir,
            asked,
            &format!("About {} — {question}", asked.summary),
            "errand.asked",
        );
        note(
            state,
            npub,
            &errand.id,
            format!("asked a question · {}", asked.summary),
        );
        return;
    }

    match result {
        Ok(out) if !out.completion.text.trim().is_empty() => {
            let text: String = out.completion.text.trim().chars().take(8000).collect();
            speak(state, npub, manifest, dir, errand, &text, "errand.run");
            mark(dir, &errand.id, State::Delivered, Some(out.completion.outcome));
            note(
                state,
                npub,
                &errand.id,
                format!(
                    "delivered · {} · {}s",
                    errand.summary,
                    (Utc::now() - started).num_seconds()
                ),
            );
        }
        // A run that produced nothing is a failure here, not a quiet
        // success: this one was promised to somebody.
        Ok(_) => {
            settle(
                state,
                npub,
                manifest,
                dir,
                errand,
                State::Failed,
                "the run finished without producing anything",
            );
        }
        Err(error) => {
            settle(
                state,
                npub,
                manifest,
                dir,
                errand,
                State::Failed,
                &error.to_string(),
            );
        }
    }
}

/// Record a settled outcome on disk.
fn mark(dir: &std::path::Path, id: &str, state: State, outcome: Option<String>) {
    let file = ErrandsFile::open(dir);
    let mut errands = file.load();
    if let Some(errand) = errands.errands.iter_mut().find(|errand| errand.id == id) {
        errand.state = state;
        if let Some(outcome) = outcome {
            errand.outcome = Some(outcome);
        }
    }
    let _ = file.save(&errands);
}

/// Failure, said out loud in the room where the promise was made.
fn settle(
    state: &App,
    npub: &str,
    manifest: &Manifest,
    dir: &std::path::Path,
    errand: &Errand,
    outcome: State,
    reason: &str,
) {
    speak(
        state,
        npub,
        manifest,
        dir,
        errand,
        &format!(
            "I could not finish this after all: {}. What went wrong: {reason}.",
            errand.summary
        ),
        "errand.failed",
    );
    mark(dir, &errand.id, outcome, Some(reason.to_string()));
    note(
        state,
        npub,
        &errand.id,
        format!("failed · {} · {reason}", errand.summary),
    );
}

/// Deliver text back to the conversation the errand came from, and record
/// the attempt. Delivery failing is itself worth a log line — that is the
/// case where a person is left waiting and nobody knows.
fn speak(
    state: &App,
    npub: &str,
    manifest: &Manifest,
    dir: &std::path::Path,
    errand: &Errand,
    text: &str,
    action: &str,
) {
    let log = EpisodicLog::open(dir);
    let Ok(ks) = Keystore::open(&state.home) else {
        return;
    };
    let Ok((custody, handle)) = admit_agent(state, &ks, npub) else {
        return;
    };
    let delivered = match delivery_to(errand) {
        Some(target) => crate::routines::deliver(
            state, manifest, &custody, &handle, npub, &errand.id, &target, text,
        ),
        None => json!({
            "error": format!(
                "this host cannot deliver to {} — the work has nowhere to land",
                errand.channel_kind
            )
        }),
    };
    let _ = log.append(
        &custody,
        &handle,
        Tier::Self_,
        &EntryBody {
            action: action.into(),
            model: None,
            cost: None,
            harness: Some("native".into()),
            outcome: if delivered.get("error").is_some() {
                "undelivered".into()
            } else {
                "delivered".into()
            },
            detail: Some(json!({
                "errand": errand.id,
                "summary": errand.summary,
                "channel_kind": errand.channel_kind,
                "channel": errand.channel,
                "requested_by": errand.requested_by,
                "delivered": delivered,
                "response_chars": text.len(),
            })),
        },
    );
}

// ------------------------------------------------------------- endpoints

use axum::{
    extract::{OriginalUri, Path as AxPath, State as AxState},
    response::IntoResponse,
    Json,
};

/// GET /api/agents/{npub}/errands — what this agent owes, and to whom.
pub async fn list_errands(
    AxState(state): AxState<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (_ks, npub, dir, _raw, _manifest) =
        match crate::ops::gate_pub(&state, &headers, "GET", &uri, None, &npub) {
            Ok(value) => value,
            Err(error) => return error.into_response(),
        };
    let errands = ErrandsFile::open(&dir).load();
    let notes = state
        .supervisor_notes
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let busy = running().lock().unwrap().clone();
    let items: Vec<serde_json::Value> = errands
        .errands
        .iter()
        .map(|errand| {
            json!({
                "id": errand.id,
                "summary": errand.summary,
                "task": errand.task,
                "state": errand.state,
                "channel_kind": errand.channel_kind,
                "channel": errand.channel,
                "requested_by": errand.requested_by,
                "filed_at": errand.filed_at,
                "start_after": errand.start_after,
                "deadline": errand.deadline(),
                "question": errand.question,
                "answer": errand.answer,
                "outcome": errand.outcome,
                "running": busy.contains(&format!("{npub}/{}", errand.id)),
                "note": notes.get(&format!("{npub}:routine:{}", errand.id)),
            })
        })
        .collect();
    Json(json!({
        "ok": true,
        "errands": items,
        "outstanding": errands.outstanding().count(),
        "max_pending": apiary_runtime::errands::MAX_PENDING,
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
pub struct CancelBody {
    pub id: String,
}

/// POST /api/agents/{npub}/errands/cancel — call it off, and tell the
/// person who asked. Cancelling silently would reproduce exactly the
/// failure this primitive exists to remove.
pub async fn cancel_errand(
    AxState(state): AxState<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    Json(body): Json<CancelBody>,
) -> impl IntoResponse {
    let raw_body = serde_json::to_vec(&json!({ "id": body.id })).unwrap_or_default();
    let (_ks, npub, dir, _raw, manifest) = match crate::ops::gate_pub(
        &state,
        &headers,
        "POST",
        &uri,
        Some(&raw_body),
        &npub,
    ) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let file = ErrandsFile::open(&dir);
    let mut errands = file.load();
    let Some(errand) = errands
        .errands
        .iter_mut()
        .find(|errand| errand.id == body.id && errand.state.is_outstanding())
    else {
        return crate::err(
            axum::http::StatusCode::NOT_FOUND,
            "no outstanding work with that id",
        )
        .into_response();
    };
    errand.state = State::Cancelled;
    errand.outcome = Some("cancelled by the governor".into());
    let cancelled = errand.clone();
    if let Err(error) = file.save(&errands) {
        return crate::err(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            error.to_string(),
        )
        .into_response();
    }
    speak(
        &state,
        &npub,
        &manifest,
        &dir,
        &cancelled,
        &format!(
            "This has been called off and I will not be delivering it: {}.",
            cancelled.summary
        ),
        "errand.cancelled",
    );
    Json(json!({ "ok": true, "id": cancelled.id })).into_response()
}
