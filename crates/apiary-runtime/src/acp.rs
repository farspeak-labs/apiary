//! ACP client — drive a foreign harness (Goose, Claude Code, Codex) as this
//! agent's loop, under Apiary's governance shell (SPEC §2 sidecars).
//!
//! The runtime brings the loop; Apiary supplies everything that isn't the
//! loop: identity (results signed into the log), floors (permission requests
//! route back HERE and are decided by host policy, never by the model), and
//! the record (every tool call and permission decision logged).
//!
//! Wire: newline-delimited JSON-RPC 2.0 over the child's stdio, per the
//! Agent Client Protocol. This is a deliberately minimal sync client for the
//! one-shot runner; when the host daemon goes async, graduate to the
//! official `agent-client-protocol` crate.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// Host policy for the harness's permission requests. Default deny: a
/// hijacked or overeager loop is bounded by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionMode {
    /// Reject every ACP permission request. Harnesses that perform native
    /// actions without requesting permission need their own mode or sandbox.
    Deny,
    /// Approve every request (the human explicitly opted in for this run).
    Allow,
    /// Approve only matching ACP tool titles; reject every other request.
    AllowList(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileMode {
    /// Scrubbed environment and a fresh per-agent HOME.
    Isolated,
    /// Isolated profile plus explicitly named environment variables.
    Curated(Vec<String>),
    /// The harness receives the host user's complete environment and HOME.
    Inherit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxMode {
    None,
    ReadOnly,
    NoNetwork,
    ReadOnlyNoNetwork,
}

pub struct AcpOutcome {
    /// Accumulated agent text (message chunks joined).
    pub text: String,
    pub stop_reason: String,
    /// (tool title, status) pairs observed via session/update.
    pub tool_calls: Vec<(String, String)>,
    /// (tool title, decision) pairs for permission requests we answered.
    pub permissions: Vec<(String, String)>,
}

fn goose_mode(command: &str, mode: &PermissionMode) -> Option<&'static str> {
    let name = std::path::Path::new(command)
        .file_name()
        .and_then(|name| name.to_str())?;
    // Goose's upstream CLI is normally named `goose`; Berd bundles the same
    // ACP server as `goosed`. Both expose native execution modes that must be
    // pinned from the ratified Apiary access policy rather than inherited
    // from the host environment.
    if name != "goose"
        && name != "goosed"
        && !name.starts_with("goose-")
        && !name.starts_with("goosed-")
    {
        return None;
    }
    Some(match mode {
        PermissionMode::Deny => "chat",
        PermissionMode::AllowList(_) => "approve",
        PermissionMode::Allow => "auto",
    })
}

#[cfg(target_os = "macos")]
fn sandbox_profile(mode: SandboxMode) -> Option<&'static str> {
    match mode {
        SandboxMode::None => None,
        SandboxMode::ReadOnly => Some("(version 1)(allow default)(deny file-write*)"),
        SandboxMode::NoNetwork => Some("(version 1)(allow default)(deny network*)"),
        SandboxMode::ReadOnlyNoNetwork => {
            Some("(version 1)(allow default)(deny file-write*)(deny network*)")
        }
    }
}

fn sandboxed_command(
    command: &str,
    args: &[String],
    sandbox: SandboxMode,
) -> Result<Command, crate::Error> {
    if sandbox == SandboxMode::None {
        let mut process = Command::new(command);
        process.args(args);
        return Ok(process);
    }
    #[cfg(target_os = "macos")]
    {
        let profile = sandbox_profile(sandbox).expect("non-none sandbox has a profile");
        let mut process = Command::new("/usr/bin/sandbox-exec");
        process.args(["-p", profile, command]).args(args);
        Ok(process)
    }
    #[cfg(target_os = "linux")]
    {
        let executable = std::env::var_os("PATH")
            .and_then(|path| {
                std::env::split_paths(&path)
                    .map(|directory| directory.join("bwrap"))
                    .find(|candidate| candidate.is_file())
            })
            .ok_or_else(|| {
                crate::Error::Provider(
                    "OS sandbox requested, but Bubblewrap (bwrap) is not installed".into(),
                )
            })?;
        let mut process = Command::new(executable);
        process.args(["--die-with-parent", "--new-session"]);
        match sandbox {
            SandboxMode::ReadOnly | SandboxMode::ReadOnlyNoNetwork => {
                process.args(["--ro-bind", "/", "/"]);
            }
            SandboxMode::NoNetwork => {
                process.args(["--bind", "/", "/"]);
            }
            SandboxMode::None => unreachable!("handled above"),
        }
        if matches!(
            sandbox,
            SandboxMode::NoNetwork | SandboxMode::ReadOnlyNoNetwork
        ) {
            process.arg("--unshare-net");
        }
        process.arg("--").arg(command).args(args);
        Ok(process)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (command, args);
        Err(crate::Error::Provider(format!(
            "OS sandbox {sandbox:?} was requested, but this host has no supported sandbox backend"
        )))
    }
}

/// Run one prompt through an ACP agent subprocess.
#[allow(clippy::too_many_arguments)]
pub fn run_acp_prompt(
    command: &str,
    args: &[String],
    workdir: &std::path::Path,
    profile_root: &std::path::Path,
    task: &str,
    mode: PermissionMode,
    profile: ProfileMode,
    sandbox: SandboxMode,
    profile_name: &str,
    turn_timeout: Duration,
) -> Result<AcpOutcome, crate::Error> {
    // Isolated and curated profiles get a per-agent HOME, so global agents,
    // skills, extensions, and credentials do not leak in accidentally. Full
    // inheritance is a separate ratified choice. This is profile isolation,
    // not a filesystem/network sandbox; the manifest and UI say so plainly.
    const ENV_ALLOWLIST: &[&str] = &["PATH", "HOME", "USER", "SHELL", "LANG", "TMPDIR", "TERM"];
    // Remembered so a failure can name the exact HOME a login has to happen
    // in — an isolated harness holds none of the host user's credentials,
    // and "Authentication required" alone does not say where to fix it.
    let mut profile_home: Option<std::path::PathBuf> = None;
    let mut cmd = sandboxed_command(command, args, sandbox)?;
    cmd.current_dir(workdir);
    if profile != ProfileMode::Inherit {
        cmd.env_clear();
        for key in ENV_ALLOWLIST {
            if *key != "HOME" {
                if let Ok(value) = std::env::var(key) {
                    cmd.env(key, value);
                }
            }
        }
        if let ProfileMode::Curated(names) = &profile {
            for name in names {
                if let Ok(value) = std::env::var(name) {
                    cmd.env(name, value);
                }
            }
        }
        let home = profile_root
            .join(".apiary-harnesses")
            .join(profile_name)
            .join("home");
        std::fs::create_dir_all(&home)?;
        profile_home = Some(home.clone());
        let profile_home = home;
        cmd.env("HOME", &profile_home)
            .env("XDG_CONFIG_HOME", profile_home.join(".config"))
            .env("XDG_DATA_HOME", profile_home.join(".local/share"))
            .env("XDG_CACHE_HOME", profile_home.join(".cache"));
    }
    // Goose has an explicit native execution mode in addition to ACP
    // permission requests. Pin it from the ratified access policy so an
    // inherited global GOOSE_MODE cannot silently widen this agent.
    if let Some(goose_mode) = goose_mode(command, &mode) {
        cmd.env("GOOSE_MODE", goose_mode);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| crate::Error::Provider(format!("spawn {command}: {e}")))?;
    let result = drive(
        &mut child,
        workdir,
        task,
        mode,
        turn_timeout,
        profile_home.as_deref(),
    );
    let _ = child.kill();
    let _ = child.wait();
    result
}

#[allow(clippy::too_many_arguments)]
fn drive(
    child: &mut Child,
    workdir: &std::path::Path,
    task: &str,
    mode: PermissionMode,
    turn_timeout: Duration,
    profile_home: Option<&std::path::Path>,
) -> Result<AcpOutcome, crate::Error> {
    let mut stdin = child.stdin.take().expect("piped stdin");
    let stdout = child.stdout.take().expect("piped stdout");

    // Reader thread → channel, so every wait has a real timeout.
    let (tx, rx) = mpsc::channel::<Value>();
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<Value>(&line) {
                if tx.send(v).is_err() {
                    break;
                }
            }
        }
    });

    let mut next_id = 0i64;
    let mut send_request = |stdin: &mut std::process::ChildStdin,
                            method: &str,
                            params: Value|
     -> Result<i64, crate::Error> {
        next_id += 1;
        let frame = json!({"jsonrpc": "2.0", "id": next_id, "method": method, "params": params});
        writeln!(stdin, "{frame}")
            .map_err(|e| crate::Error::Provider(format!("acp write: {e}")))?;
        Ok(next_id)
    };

    let mut out = AcpOutcome {
        text: String::new(),
        stop_reason: "unknown".into(),
        tool_calls: Vec::new(),
        permissions: Vec::new(),
    };

    // 1. initialize — we advertise no fs/terminal capabilities: the harness
    //    gets capability through permission-gated tools, not through us.
    let init_id = send_request(
        &mut stdin,
        "initialize",
        json!({"protocolVersion": 1, "clientCapabilities": {"fs": {"readTextFile": false, "writeTextFile": false}}}),
    )?;
    let mut session_id: Option<String> = None;
    let mut auth_hint: Option<String> = None;
    let mut new_id: Option<i64> = None;
    let mut prompt_id: Option<i64> = None;

    loop {
        let msg = rx
            .recv_timeout(turn_timeout)
            .map_err(|_| crate::Error::Provider("acp: agent timed out or exited".into()))?;

        // Agent → client REQUEST (has id + method): permission requests get
        // host policy; anything else is politely unsupported.
        if let (Some(id), Some(method)) =
            (msg.get("id"), msg.get("method").and_then(|m| m.as_str()))
        {
            match method {
                "session/request_permission" => {
                    let title = msg["params"]["toolCall"]["title"]
                        .as_str()
                        .unwrap_or("unnamed tool")
                        .to_string();
                    let options = msg["params"]["options"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default();
                    // Strict selection: an option is only acceptable if its
                    // kind matches the mode's intent. Deny mode NEVER falls
                    // back to an allow option — a malformed option list gets
                    // a JSON-RPC error, which the harness must treat as
                    // not-granted.
                    let tool_allowed = match &mode {
                        PermissionMode::Allow => true,
                        PermissionMode::AllowList(allowed) => {
                            allowed.iter().any(|item| item == &title)
                        }
                        PermissionMode::Deny => false,
                    };
                    let acceptable = |kind: &str| {
                        if tool_allowed {
                            kind.starts_with("allow")
                        } else {
                            kind.starts_with("reject") || kind.starts_with("deny")
                        }
                    };
                    let choice = options.iter().find_map(|o| {
                        let kind = o["kind"].as_str()?;
                        if !acceptable(kind) {
                            return None;
                        }
                        Some((o["optionId"].as_str()?.to_string(), kind.to_string()))
                    });
                    let resp = match choice {
                        Some((option_id, kind)) => {
                            out.permissions.push((title, kind));
                            json!({"jsonrpc": "2.0", "id": id, "result": {"outcome": {"outcome": "selected", "optionId": option_id}}})
                        }
                        None => {
                            out.permissions
                                .push((title, "refused (no acceptable option)".into()));
                            json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32600, "message": "no permission option acceptable to host policy"}})
                        }
                    };
                    writeln!(stdin, "{resp}")
                        .map_err(|e| crate::Error::Provider(format!("acp write: {e}")))?;
                }
                other => {
                    let resp = json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": format!("client does not support {other}")}});
                    writeln!(stdin, "{resp}")
                        .map_err(|e| crate::Error::Provider(format!("acp write: {e}")))?;
                }
            }
            continue;
        }

        // NOTIFICATION: session/update carries the stream.
        if msg.get("method").and_then(|m| m.as_str()) == Some("session/update") {
            let update = &msg["params"]["update"];
            match update["sessionUpdate"].as_str().unwrap_or("") {
                "agent_message_chunk" => {
                    if let Some(t) = update["content"]["text"].as_str() {
                        out.text.push_str(t);
                    }
                }
                "tool_call" | "tool_call_update" => {
                    let title = update["title"].as_str().unwrap_or("").to_string();
                    let status = update["status"].as_str().unwrap_or("pending").to_string();
                    if !title.is_empty() {
                        out.tool_calls.push((title, status));
                    }
                }
                _ => {}
            }
            continue;
        }

        // RESPONSE to one of our requests.
        if let Some(id) = msg.get("id").and_then(|i| i.as_i64()) {
            if let Some(err) = msg.get("error") {
                let message = err["message"].as_str().unwrap_or("unknown");
                // An unauthenticated harness is the most common first
                // failure and the least self-explanatory: the loop is
                // installed, the handshake succeeded, and it stops because
                // it has no login — in a HOME the operator has never seen.
                let remedy = if message.to_ascii_lowercase().contains("auth") {
                    match profile_home {
                        // Quote the harness's own instruction rather than
                        // guessing a command: the binary Apiary spawns is
                        // often an adapter, not the thing you log in to.
                        Some(home) => format!(
                            " — this harness runs in its own profile and has no login yet. \
                             Log it in as a person, with HOME={} set{}",
                            home.display(),
                            auth_hint
                                .as_deref()
                                .map(|hint| format!(" ({hint})"))
                                .unwrap_or_default()
                        ),
                        None => String::new(),
                    }
                } else {
                    String::new()
                };
                return Err(crate::Error::Provider(format!(
                    "acp error on request {id}: {message}{remedy}"
                )));
            }
            if id == init_id {
                auth_hint = msg["result"]["authMethods"]
                    .as_array()
                    .and_then(|methods| methods.first())
                    .and_then(|method| {
                        method["description"]
                            .as_str()
                            .or_else(|| method["name"].as_str())
                    })
                    .map(str::to_string);
                // The session's working directory is the AGENT's dir — the
                // harness works in the agent's world, not the invoking
                // shell's. (v1 shipped env::current_dir() here; a live run
                // promptly listed the user's home directory. Evidence-cited
                // fix.) Absolute path per the ACP spec.
                let cwd = workdir
                    .canonicalize()
                    .unwrap_or_else(|_| workdir.to_path_buf());
                new_id = Some(send_request(
                    &mut stdin,
                    "session/new",
                    json!({"cwd": cwd, "mcpServers": []}),
                )?);
            } else if Some(id) == new_id {
                let sid = msg["result"]["sessionId"]
                    .as_str()
                    .ok_or_else(|| crate::Error::Provider("acp: no sessionId".into()))?
                    .to_string();
                prompt_id = Some(send_request(
                    &mut stdin,
                    "session/prompt",
                    json!({"sessionId": sid, "prompt": [{"type": "text", "text": task}]}),
                )?);
                session_id = Some(sid);
            } else if Some(id) == prompt_id {
                out.stop_reason = msg["result"]["stopReason"]
                    .as_str()
                    .unwrap_or("end_turn")
                    .to_string();
                let _ = session_id; // session ends with the one-shot run
                return Ok(out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{goose_mode, PermissionMode};

    #[test]
    fn goose_native_mode_is_pinned_from_ratified_access() {
        assert_eq!(goose_mode("goose", &PermissionMode::Deny), Some("chat"));
        assert_eq!(
            goose_mode(
                "/usr/local/bin/goose-acp",
                &PermissionMode::AllowList(vec!["shell".into()])
            ),
            Some("approve")
        );
        assert_eq!(
            goose_mode("/opt/bin/goose", &PermissionMode::Allow),
            Some("auto")
        );
        assert_eq!(goose_mode("claude", &PermissionMode::Allow), None);
        assert_eq!(
            goose_mode(
                "/Applications/Berd.app/Contents/MacOS/goosed",
                &PermissionMode::Deny
            ),
            Some("chat")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_read_only_sandbox_denies_child_writes() {
        use super::{sandboxed_command, SandboxMode};
        use std::process::Stdio;

        let path =
            std::env::temp_dir().join(format!("apiary-sandbox-write-probe-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut command = sandboxed_command(
            "/usr/bin/touch",
            &[path.to_string_lossy().into_owned()],
            SandboxMode::ReadOnly,
        )
        .unwrap();
        let status = command
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(!status.success());
        assert!(!path.exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_no_network_sandbox_denies_loopback_connections() {
        use super::{sandboxed_command, SandboxMode};
        use std::process::Stdio;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port().to_string();
        let mut command = sandboxed_command(
            "/usr/bin/nc",
            &["-z".into(), "127.0.0.1".into(), port],
            SandboxMode::NoNetwork,
        )
        .unwrap();
        let status = command
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(!status.success());
    }
}
