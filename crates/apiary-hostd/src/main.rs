//! The `apiary-hostd` binary: parse args, build the shared router, serve.
//! All behavior lives in the library — the Tauri desktop app embeds the
//! same router in-process.

use apiary_hostd::{build_router, AppState, AuthMode};
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "apiary-hostd", version, about = "Apiary host daemon")]
struct Args {
    /// State directory (keys, manifests).
    #[arg(long, env = "APIARY_HOME", default_value_os_t = default_home())]
    home: PathBuf,
    /// Dev-keystore passphrase; the cockpit can also unlock at runtime.
    #[arg(long, env = "APIARY_PASSPHRASE", hide_env_values = true)]
    passphrase: Option<String>,
    /// Bind address.
    #[arg(long, default_value = "127.0.0.1:7777")]
    bind: String,
    /// Auth mode: "open" (localhost dev) or "nip98" (signed requests).
    #[arg(long, default_value = "open")]
    auth: String,
    /// Canonical external origin clients sign NIP-98 URLs against
    /// (default: http://<bind>). Must match what clients see exactly.
    #[arg(long)]
    origin: Option<String>,
    /// Bootstrap host-manager npubs (nip98 mode). Repeatable. Managers added
    /// later in People & access persist, so this flag is only required for
    /// first setup or recovery.
    #[arg(long = "admin")]
    admins: Vec<String>,
}

fn default_home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".apiary")
}

/// Headless unlock: the opt-in passphrase file behind the cockpit's
/// "remember on this host" checkbox. A host that must run agents through
/// reboots and deploys holds its own key — like an SSH host key — so the
/// keystore's at-rest protection here reduces to OS account permissions
/// (0600) and disk encryption. Forgetting it in the cockpit deletes it.
fn headless_unlock_path(home: &std::path::Path) -> PathBuf {
    home.join("headless-unlock")
}

fn write_headless_unlock(path: &std::path::Path, passphrase: &str) -> Result<(), String> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| e.to_string())?;
    f.write_all(passphrase.as_bytes()).map_err(|e| e.to_string())
}

/// Read + verify the stored passphrase; None (with a loud note) if the
/// file is absent, unreadable, or no longer matches the keystore.
fn read_headless_unlock(home: &std::path::Path) -> Option<String> {
    let path = headless_unlock_path(home);
    let pass = std::fs::read_to_string(&path)
        .ok()?
        .trim_end_matches('\n')
        .to_string();
    if pass.is_empty() {
        return None;
    }
    let verified = apiary_core::keystore::Keystore::open(home)
        .map_err(|e| e.to_string())
        .and_then(|ks| {
            ks.verify_or_initialize_workspace(&pass)
                .map_err(|e| e.to_string())
        });
    match verified {
        Ok(_) => {
            eprintln!("headless unlock: workspace unlocked from {}", path.display());
            Some(pass)
        }
        Err(e) => {
            eprintln!(
                "headless unlock: {} no longer opens the keystore ({e}) — staying locked; \
                 unlock in the cockpit and re-tick \"remember on this host\"",
                path.display()
            );
            None
        }
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    // Fail closed: an unrecognized auth mode must never silently mean open.
    let auth = match args.auth.as_str() {
        "nip98" => AuthMode::Nip98,
        "open" => {
            eprintln!("auth=open: every local process can drive this daemon; use --auth nip98 beyond localhost dev");
            AuthMode::Open
        }
        other => {
            eprintln!("error: unknown --auth '{other}' (expected: open | nip98)");
            std::process::exit(2);
        }
    };
    let admins = args
        .admins
        .iter()
        .map(|a| apiary_core::identity::parse_npub(a))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|e| {
            eprintln!("error: --admin: {e}");
            std::process::exit(2);
        });
    let managers =
        apiary_hostd::access::ManagerRegistry::load(&args.home, admins).unwrap_or_else(|error| {
            eprintln!("error: host manager registry: {error}");
            std::process::exit(2);
        });
    let desktop_token = apiary_core::identity::generate()
        .secret_key()
        .to_secret_hex();
    // Explicit --passphrase / APIARY_PASSPHRASE wins; otherwise the opt-in
    // headless-unlock file lets agents come back up unattended.
    let stored = read_headless_unlock(&args.home);
    let auto = stored.is_some();
    let initial_pass = args.passphrase.clone().or(stored);
    let remember_home = args.home.clone();
    let forget_home = args.home.clone();
    let state = Arc::new(AppState {
        home: args.home.clone(),
        passphrase: std::sync::RwLock::new(initial_pass),
        remember_passphrase: Some(Arc::new(move |pass: &str| {
            write_headless_unlock(&headless_unlock_path(&remember_home), pass)
        })),
        forget_passphrase: Some(Arc::new(move || {
            match std::fs::remove_file(headless_unlock_path(&forget_home)) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        })),
        automatic_unlock: std::sync::atomic::AtomicBool::new(auto),
        auth,
        origin: args
            .origin
            .clone()
            .unwrap_or_else(|| format!("http://{}", args.bind)),
        token: None,
        browser_sessions: std::sync::Mutex::new(std::collections::HashMap::new()),
        pending_nip46: std::sync::Mutex::new(std::collections::HashMap::new()),
        remote_signers: std::sync::Mutex::new(std::collections::HashMap::new()),
        desktop_token: Some(desktop_token),
        internal_token: apiary_core::identity::generate()
            .secret_key()
            .to_secret_hex(),
        control_audit: std::sync::Mutex::new(()),
        control_tokens: std::sync::Mutex::new(()),
        listeners: std::sync::Mutex::new(std::collections::HashMap::new()),
        pending_oauth: std::sync::Mutex::new(std::collections::HashMap::new()),
        supervisor_notes: std::sync::Mutex::new(std::collections::HashMap::new()),
        admitted: std::sync::Mutex::new(std::collections::HashMap::new()),
        decisions: Default::default(),
        managers: std::sync::RwLock::new(managers),
    });
    apiary_hostd::write_control_discovery(&state).unwrap_or_else(|error| {
        eprintln!("error: control-plane discovery: {error}");
        std::process::exit(2);
    });
    apiary_hostd::write_desktop_access(&state).unwrap_or_else(|error| {
        eprintln!("error: desktop access discovery: {error}");
        std::process::exit(2);
    });
    apiary_hostd::ops::spawn_supervisor(state.clone());
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(&args.bind)
        .await
        .expect("bind");
    println!("apiary-hostd listening on http://{}", args.bind);
    axum::serve(listener, app).await.expect("serve");
}
