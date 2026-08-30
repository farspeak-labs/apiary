//! Foreign harness under the governance shell, end to end against the mock
//! ACP agent binary (a real subprocess speaking real newline JSON-RPC).

use apiary_core::custody::Custody;
use apiary_core::log::EpisodicLog;
use apiary_core::manifest::{
    HarnessAccess, HarnessGrant, HarnessMetering, HarnessProfile, HarnessSandbox, Manifest,
};
use nostr::prelude::*;

fn setup(
    tag: &str,
) -> (
    Manifest,
    std::path::PathBuf,
    Custody,
    apiary_core::custody::AgentHandle,
) {
    let mut custody = Custody::new();
    let keys = Keys::generate();
    let npub = apiary_core::identity::to_npub(&keys.public_key()).unwrap();
    let handle = custody.admit(keys);
    let human = apiary_core::identity::to_npub(&Keys::generate().public_key()).unwrap();
    let manifest = Manifest::from_yaml(&format!(
        "manifest_version: 1\nidentity:\n  npub: {npub}\ninference: []\nconnectors: []\nmemory:\n  log: local\ngovernance:\n  suspend_keys:\n    - {human}\n"
    ))
    .unwrap();
    let dir = std::env::temp_dir().join(format!("apiary-acp-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    (manifest, dir, custody, handle)
}

fn grant(command: &str, access: HarnessAccess) -> HarnessGrant {
    HarnessGrant {
        name: "mock-acp".into(),
        kind: "acp".into(),
        command: command.into(),
        args: Vec::new(),
        access,
        profile: HarnessProfile::Isolated,
        sandbox: HarnessSandbox::None,
        allowed_tools: Vec::new(),
        inherit_env: Vec::new(),
        metering: HarnessMetering::Unmetered,
        estimated_tokens_per_run: None,
        workdir: None,
    }
}

#[test]
fn acp_deny_mode_blocks_tool_and_logs_harness() {
    let (mut manifest, dir, custody, handle) = setup("deny");
    let mock = env!("CARGO_BIN_EXE_mock-acp-agent");
    let grant = grant(mock, HarnessAccess::InferenceOnly);
    #[cfg(target_os = "macos")]
    let grant = {
        let mut grant = grant;
        grant.sandbox = HarnessSandbox::ReadOnly;
        grant
    };
    manifest.harnesses.push(grant.clone());
    let out = apiary_runtime::runner::run_acp_task(
        &manifest,
        &dir,
        &custody,
        &handle,
        "do something",
        &grant,
    )
    .unwrap();

    assert!(
        out.text.contains("mock harness reply: do something"),
        "{}",
        out.text
    );
    assert_eq!(out.stop_reason, "end_turn");
    // Host policy denied the write_file permission…
    assert_eq!(
        out.permissions,
        vec![("write_file".to_string(), "reject_once".to_string())]
    );
    // …and the harness reported the tool as failed, not completed.
    assert!(out
        .tool_calls
        .iter()
        .any(|(t, s)| t == "write_file" && s == "failed"));

    // The signed record attributes the run to the foreign harness.
    let log = EpisodicLog::open(&dir);
    let entries = log.tail(5).unwrap();
    let body = EpisodicLog::parse_body(entries.last().unwrap()).unwrap();
    assert_eq!(body.action, "run.task");
    assert!(body.harness.as_deref().unwrap_or("").starts_with("acp:"));
    #[cfg(target_os = "macos")]
    assert_eq!(body.detail.as_ref().unwrap()["sandbox"], "read-only");
    assert_eq!(log.verify().unwrap(), 1);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn acp_allow_mode_grants_tool() {
    let (mut manifest, dir, custody, handle) = setup("allow");
    let mock = env!("CARGO_BIN_EXE_mock-acp-agent");
    let grant = grant(mock, HarnessAccess::Full);
    manifest.harnesses.push(grant.clone());
    let out = apiary_runtime::runner::run_acp_task(
        &manifest, &dir, &custody, &handle, "write it", &grant,
    )
    .unwrap();
    assert_eq!(
        out.permissions,
        vec![("write_file".to_string(), "allow_once".to_string())]
    );
    assert!(out
        .tool_calls
        .iter()
        .any(|(t, s)| t == "write_file" && s == "completed"));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn curated_acp_access_matches_exact_permission_titles() {
    let (mut manifest, dir, custody, handle) = setup("curated");
    let mock = env!("CARGO_BIN_EXE_mock-acp-agent");
    let mut allowed = grant(mock, HarnessAccess::Curated);
    allowed.allowed_tools = vec!["write_file".into()];
    manifest.harnesses.push(allowed.clone());
    let out = apiary_runtime::runner::run_acp_task(
        &manifest, &dir, &custody, &handle, "write it", &allowed,
    )
    .unwrap();
    assert_eq!(out.permissions[0].1, "allow_once");

    let mut denied = allowed;
    denied.allowed_tools = vec!["read_file".into()];
    manifest.harnesses.clear();
    manifest.harnesses.push(denied.clone());
    let out = apiary_runtime::runner::run_acp_task(
        &manifest, &dir, &custody, &handle, "write it", &denied,
    )
    .unwrap();
    assert_eq!(out.permissions[0].1, "reject_once");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn strict_unknown_usage_refuses_before_spawning() {
    let (mut manifest, dir, custody, handle) = setup("strict");
    let mut strict = grant("definitely-not-a-command", HarnessAccess::Full);
    strict.metering = HarnessMetering::Strict;
    manifest.harnesses.push(strict.clone());
    let error =
        apiary_runtime::runner::run_acp_task(&manifest, &dir, &custody, &handle, "do it", &strict)
            .err()
            .unwrap();
    assert!(error
        .to_string()
        .contains("does not report authoritative token usage"));
    assert_eq!(EpisodicLog::open(&dir).verify().unwrap(), 1);
    std::fs::remove_dir_all(&dir).ok();
}

/// The wiring that makes a builder reachable by talking to it: an ordinary
/// governed run, told which harness to use, goes there instead of the
/// native inference loop. Everything else about the run is unchanged.
#[test]
fn a_governed_run_can_be_routed_to_a_granted_harness() {
    let (mut manifest, dir, custody, handle) = setup("routed");
    let mock = env!("CARGO_BIN_EXE_mock-acp-agent");
    let grant = grant(mock, HarnessAccess::Full);
    manifest.harnesses.push(grant.clone());
    manifest.routing.harness = Some(grant.name.clone());

    let ctx = apiary_runtime::routing::TaskContext {
        harness: manifest.routing.harness.clone(),
        ..Default::default()
    };
    let out = apiary_runtime::runner::run_task(
        &manifest,
        &dir,
        &custody,
        &handle,
        "build the thing",
        &ctx,
    )
    .expect("a routed run reaches the harness");

    assert!(
        out.completion
            .text
            .contains("mock harness reply: build the thing"),
        "{}",
        out.completion.text
    );
    // Attribution is honest: the harness picks its own model, so the record
    // names the harness rather than inventing a model.
    assert_eq!(out.completion.model, "harness:mock-acp");
    assert_eq!(out.slot, "mock-acp");
    // This manifest has NO inference slots at all, so reaching the harness
    // proves the delegation happens before the native path is consulted.
    assert!(manifest.inference.is_empty());
}

/// Routing is not a grant. A run pointed at a harness the agent does not
/// hold is refused rather than quietly falling back to the native loop —
/// falling back would silently answer a coding request with prose.
#[test]
fn a_run_routed_to_an_ungranted_harness_is_refused() {
    let (manifest, dir, custody, handle) = setup("ungranted");
    let ctx = apiary_runtime::routing::TaskContext {
        harness: Some("not-granted".into()),
        ..Default::default()
    };
    let result =
        apiary_runtime::runner::run_task(&manifest, &dir, &custody, &handle, "build it", &ctx);
    let error = match result {
        Ok(_) => panic!("an ungranted harness must refuse"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("has not been granted"),
        "{error}"
    );
}
