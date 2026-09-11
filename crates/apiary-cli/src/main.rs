//! `apiary` — the host's front door. JSON in/out, `buzz-cli`-style, so the
//! host is scriptable by humans and drivable by agents (SPEC §2). This is the
//! HOST surface; agents' own shell access is an opt-in connector (SPEC §6) and
//! has nothing to do with this binary.

use apiary_core::{
    ceremony, custody::Custody, keystore::Keystore, log::EpisodicLog, manifest::Manifest,
};
use clap::{Parser, Subcommand};
use nostr::prelude::*;
use serde_json::json;
use std::io::Read;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "apiary", version, about = "Apiary portable-agent host")]
struct Cli {
    /// State directory (keys, manifests). Never commit this.
    #[arg(long, env = "APIARY_HOME", default_value_os_t = default_home())]
    home: PathBuf,
    /// Dev-keystore passphrase (NIP-49). Prefer the env var over the flag.
    #[arg(long, env = "APIARY_PASSPHRASE", hide_env_values = true, global = true)]
    passphrase: Option<String>,
    #[command(subcommand)]
    command: Command,
}

fn default_home() -> PathBuf {
    dirs_home().join(".apiary")
}

fn dirs_home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

#[derive(Subcommand)]
enum Command {
    /// Agent lifecycle.
    Agent {
        #[command(subcommand)]
        cmd: AgentCmd,
    },
    /// Manifest operations.
    Manifest {
        #[command(subcommand)]
        cmd: ManifestCmd,
    },
    /// Credential custody (NIP-44 seal/open against an agent's key).
    Credential {
        #[command(subcommand)]
        cmd: CredentialCmd,
    },
    /// The signed episodic log.
    Log {
        #[command(subcommand)]
        cmd: LogCmd,
    },
    /// Normalize a public key: accepts npub or hex, prints both forms.
    Key { key: String },
    /// Routines: scheduled, governed runs (SCOPE_routines). `list` reads
    /// the agent's manifest + host state locally; `run`/`pause`/`resume`
    /// go through the running host (the desktop's daemon, found via
    /// ~/.apiary/desktop.json) — firing needs its gates and delivery.
    Routine {
        #[command(subcommand)]
        cmd: RoutineCmd,
    },
    /// Buzz workspace membership: the agent authenticates to a Buzz relay
    /// with its own key (NIP-42) and participates as a first-class member.
    Buzz {
        #[command(subcommand)]
        cmd: BuzzCmd,
    },
    /// Run a one-shot task as an agent.
    Run {
        /// The agent's npub.
        npub: String,
        /// The task text.
        #[arg(long)]
        task: String,
        /// Task class for routing (e.g. "reasoning").
        #[arg(long)]
        class: Option<String>,
        /// Data class for routing floors (e.g. "sensitive").
        #[arg(long)]
        data_class: Option<String>,
        /// Which loop runs the task: "native" or a harness name declared in
        /// this agent's ratified manifest.
        #[arg(long, default_value = "native")]
        harness: String,
        /// Legacy selector: match a declared ACP harness by exact command.
        #[arg(long)]
        acp_cmd: Option<String>,
        /// Legacy assertion: must exactly match the declared harness args.
        #[arg(long = "acp-arg")]
        acp_args: Vec<String>,
        /// Legacy assertion that the declared harness has full access. This
        /// flag can never widen the ratified policy.
        #[arg(long)]
        acp_allow: bool,
    },
}

#[derive(Subcommand)]
enum RoutineCmd {
    /// Schedule + host state + next fires for an agent.
    List { npub: String },
    /// Fire a routine now through the running host (operator door).
    Run { npub: String, name: String },
    /// Pause a routine on this host (no amendment).
    Pause { npub: String, name: String },
    /// Resume a paused routine.
    Resume { npub: String, name: String },
}

#[derive(Subcommand)]
enum LogCmd {
    /// Show the last N log entries.
    Show {
        npub: String,
        #[arg(long, default_value_t = 20)]
        tail: usize,
    },
    /// Verify every entry's signature and the prev-chain.
    Verify { npub: String },
    /// Publish the log to the manifest's relays (tier-enforced: public
    /// plain, self NIP-44-wrapped, local never leaves).
    Publish { npub: String },
    /// Fetch this agent's published log from its relays, verify signatures,
    /// and decrypt its own wrapped entries.
    Remote { npub: String },
}

#[derive(Subcommand)]
enum AgentCmd {
    /// Found a new agent: generate identity, store key (NIP-49), write a
    /// provisional manifest. Founding is the moment of maximum ignorance —
    /// the manifest starts minimal and conservative (SPEC §7).
    New {
        /// Human-readable label (stored in the manifest directory only).
        #[arg(long)]
        name: Option<String>,
        /// Independent governor identity (npub), belonging to a person or a
        /// separate manager agent. It can never be the new agent's own key.
        #[arg(long, required = true)]
        suspend_key: Vec<String>,
    },
    /// Export the agent as ONE portable JSON bundle: manifest + NIP-49-locked
    /// key + full signed log. The passphrase travels out of band.
    Export {
        npub: String,
        /// Write to a file (default: stdout).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Re-encrypt the traveling key under THIS dedicated passphrase —
        /// the handoff secret for giving the agent to someone else. Your
        /// keystore passphrase never travels. Requires the keystore
        /// passphrase to unlock the key first.
        #[arg(long, conflicts_with = "to")]
        export_passphrase: Option<String>,
        /// Seal the whole bundle to a recipient's key (npub or hex): one
        /// kind-4602 event signed by the agent, NIP-44-encrypted to the
        /// recipient — no secret in flight, tamper-evident end to end.
        #[arg(long)]
        to: Option<String>,
    },
    /// Import a bundle on this host. Verifies key↔npub↔manifest agreement,
    /// every log signature, the chain, and ratification before anything
    /// lands. Imported agents arrive INACTIVE; the lease governs who runs.
    Import {
        file: PathBuf,
        /// Passphrase that opens the bundle's key, when it differs from
        /// your keystore passphrase (i.e. the sender's export passphrase).
        /// The key is re-encrypted under YOUR keystore passphrase on
        /// arrival either way.
        #[arg(long)]
        bundle_passphrase: Option<String>,
        /// For sealed envelopes: which keystore-held key is the recipient
        /// (default: the key the envelope's p tag names, if held here).
        #[arg(long = "as", value_name = "NPUB")]
        as_key: Option<String>,
    },
    /// Rebuild an agent from its relays: the addressable manifest event
    /// (kind 34600) plus the published log, with the key supplied as an
    /// ncryptsec file. Local-tier entries never left the origin host, so
    /// the recovered chain may have gaps (reported, not fatal).
    Recover {
        npub: String,
        #[arg(long, required = true)]
        relay: Vec<String>,
        #[arg(long)]
        key_file: PathBuf,
    },
    /// List agents in this host's keystore.
    List,
    /// Ratify an agent's manifest as a human suspend-key holder. The agent
    /// signs its manifest hash, then the human countersigns — both land as
    /// public log entries (the founding ceremony, SPEC §7).
    Ratify {
        /// The agent's npub.
        npub: String,
        /// The ratifying human's npub. Without --export/--import the key must
        /// be held in this keystore and listed in governance.suspend_keys.
        #[arg(long = "as", value_name = "NPUB")]
        as_key: Option<String>,
        /// Emit the UNSIGNED ratification event for external signing (your
        /// master key never enters Apiary). Requires --as for the signer.
        #[arg(long)]
        export: bool,
        /// Import an externally-signed ratification event (JSON on stdin).
        #[arg(long)]
        import: bool,
    },
}

#[derive(Subcommand)]
enum BuzzCmd {
    /// List the workspace's channels.
    Channels {
        npub: String,
        #[arg(long)]
        relay: String,
    },
    /// Post a stream message to a channel as the agent.
    Post {
        npub: String,
        #[arg(long)]
        relay: String,
        #[arg(long)]
        channel: String,
        #[arg(long)]
        message: String,
    },
    /// Read a channel's recent messages.
    Read {
        npub: String,
        #[arg(long)]
        relay: String,
        #[arg(long)]
        channel: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Publish the agent's profile (kind-0: name, about, picture) so it
    /// appears as a named member instead of a hex pubkey.
    Profile {
        npub: String,
        #[arg(long)]
        relay: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        about: Option<String>,
        #[arg(long)]
        picture: Option<String>,
        /// A local image to upload to the relay and use as the picture.
        /// An avatar is a URL, not an upload, so this does the upload part
        /// first and then points both profiles at what came back.
        #[arg(long)]
        image: Option<std::path::PathBuf>,
    },
    /// Request to join a channel (NIP-29) so mentions and member lists work.
    Join {
        npub: String,
        #[arg(long)]
        relay: String,
        #[arg(long)]
        channel: String,
    },
    /// Listen for mentions and answer them through the governed run loop.
    /// Runs until Ctrl-C. Mentions match a p-tag or the "@<name>" text.
    Listen {
        npub: String,
        #[arg(long)]
        relay: String,
        /// Trigger text (default: "@" + the agent's stored name).
        #[arg(long)]
        trigger: Option<String>,
    },
}

#[derive(Subcommand)]
enum ManifestCmd {
    /// Validate a manifest file (schema + substrate invariants).
    Validate { path: PathBuf },
    /// Print an agent's manifest as JSON.
    Show { npub: String },
}

#[derive(Subcommand)]
enum CredentialCmd {
    /// Seal a secret to an agent's key. Reads plaintext from stdin; emits the
    /// NIP-44 blob for pasting into a manifest connector entry.
    Seal { npub: String },
    /// Open a sealed blob (stdin) with an agent's key. Dev/debug only —
    /// prints plaintext to stdout, so pipe it, don't paste it.
    Open { npub: String },
}

fn main() {
    let cli = Cli::parse();
    let result = run(&cli);
    match result {
        Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
        Err(e) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({"ok": false, "error": e.to_string()}))
                    .unwrap()
            );
            std::process::exit(1);
        }
    }
}

fn run(cli: &Cli) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let ks = Keystore::open(&cli.home)?;
    match &cli.command {
        Command::Agent { cmd } => match cmd {
            AgentCmd::New { name, suspend_key } => {
                // Validate suspend keys before generating anything.
                for k in suspend_key {
                    apiary_core::identity::parse_npub(k)?;
                }
                let passphrase = require_passphrase(cli)?;
                // Check the passphrase against the WORKSPACE before minting a
                // key with it. Storing first happily produced an agent whose
                // key no other part of this host could open: it founded, it
                // took a manifest, it appeared in the cockpit, and it could
                // never be ratified — the failure surfaced only at the
                // approval button, in the one place it reads as the ratify
                // being broken rather than the founding.
                ks.verify_or_initialize_workspace(passphrase).map_err(|e| {
                    let detail = e.to_string();
                    let detail = detail.strip_prefix("keystore: ").unwrap_or(&detail).to_string();
                    apiary_core::Error::Keystore(format!(
                        "{detail} — founding with it would create an agent this host cannot open, unlock, or ratify"
                    ))
                })?;
                let keys = apiary_core::identity::generate();
                let npub = apiary_core::identity::to_npub(&keys.public_key())?;
                let key_path = ks.store(&keys, passphrase)?;

                let manifest = Manifest::from_yaml(&founding_manifest_yaml(&npub, suspend_key))?;
                let dir = ks.agent_dir(&npub);
                let manifest_path = dir.join("manifest.yaml");
                std::fs::write(&manifest_path, manifest.to_yaml()?)?;
                if let Some(n) = name {
                    std::fs::write(dir.join("name"), n)?;
                }
                Ok(json!({
                    "ok": true,
                    "npub": npub,
                    "name": name,
                    "key": key_path.display().to_string(),
                    "manifest": manifest_path.display().to_string(),
                    "note": "provisional manifest — founding is the moment of maximum ignorance; ratify and amend"
                }))
            }
            AgentCmd::Ratify {
                npub,
                as_key,
                export,
                import,
            } => {
                let npub = &normalize_key(npub)?;
                let raw = std::fs::read_to_string(ks.agent_dir(npub).join("manifest.yaml"))?;
                let manifest = Manifest::from_yaml(&raw)?;
                let listed = manifest
                    .governance
                    .suspend_keys
                    .iter()
                    .map(|k| apiary_core::identity::parse_npub(k))
                    .collect::<Result<Vec<_>, _>>()?;
                let log = EpisodicLog::open(&ks.agent_dir(npub));

                if *import {
                    // Externally-signed human event on stdin. A complete
                    // founding needs BOTH signatures, so the agent signs its
                    // manifest here too (keystore key, passphrase required).
                    let event = Event::from_json(read_stdin()?.trim())
                        .map_err(|e| format!("could not parse event JSON: {e}"))?;
                    let passphrase = require_passphrase(cli)?;
                    let mut custody = Custody::new();
                    let agent_handle = custody.admit(ks.load(npub, passphrase)?);
                    let signed = ceremony::sign_manifest(&custody, &agent_handle, &log, &raw)?;
                    ceremony::import_ratification(&log, &event, &raw, &listed)?;
                    return Ok(json!({
                        "ok": true,
                        "agent": npub,
                        "agent_signed": signed.id.to_hex(),
                        "imported": event.id.to_hex(),
                        "ratified_by": event.pubkey.to_hex(),
                        "manifest_sha256": ceremony::manifest_hash(&raw),
                    }));
                }

                let as_key_raw = as_key
                    .as_deref()
                    .ok_or("--as <npub> is required (the ratifying human)")?;
                let as_key = &normalize_key(as_key_raw)?;
                let ratifier_pk = apiary_core::identity::parse_npub(as_key)?;
                if !listed.contains(&ratifier_pk) {
                    return Err(format!(
                        "{as_key} is not in this agent's governance.suspend_keys — \
                         only a named human can ratify"
                    )
                    .into());
                }

                if *export {
                    // Emit the unsigned event; the human signs it elsewhere.
                    let unsigned = ceremony::ratification_unsigned(ratifier_pk, npub, &raw)?;
                    return Ok(json!({
                        "ok": true,
                        "agent": npub,
                        "sign_as": as_key,
                        "unsigned_event": serde_json::from_str::<serde_json::Value>(&unsigned.as_json())?,
                        "note": "sign this with your own nostr tooling, then: apiary agent ratify <npub> --import < signed.json"
                    }));
                }

                let passphrase = require_passphrase(cli)?;
                let mut custody = Custody::new();
                let agent_handle = custody.admit(ks.load(npub, passphrase)?);
                let human_handle = custody.admit(ks.load(as_key, passphrase)?);
                let signed = ceremony::sign_manifest(&custody, &agent_handle, &log, &raw)?;
                let ratified = ceremony::ratify(&custody, &human_handle, &log, npub, &raw)?;
                Ok(json!({
                    "ok": true,
                    "agent": npub,
                    "ratified_by": as_key,
                    "manifest_sha256": ceremony::manifest_hash(&raw),
                    "events": { "signed": signed.id.to_hex(), "ratified": ratified.id.to_hex() },
                }))
            }
            AgentCmd::Export {
                npub,
                out,
                export_passphrase,
                to,
            } => {
                let npub = &normalize_key(npub)?;
                let bundle = if let Some(recipient) = to {
                    let keystore_pass = require_passphrase(cli)?;
                    let recipient_pk = apiary_core::identity::parse_npub(recipient)?;
                    apiary_core::portability::seal(
                        &ks.agent_dir(npub),
                        npub,
                        keystore_pass,
                        &recipient_pk,
                    )?
                } else if let Some(export_pass) = export_passphrase {
                    let keystore_pass = require_passphrase(cli)?;
                    apiary_core::portability::export_with_passphrase(
                        &ks.agent_dir(npub),
                        npub,
                        Some((keystore_pass, export_pass)),
                    )?
                } else {
                    apiary_core::portability::export(&ks.agent_dir(npub), npub)?
                };
                match out {
                    Some(path) => {
                        std::fs::write(path, serde_json::to_string_pretty(&bundle)?)?;
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let _ = std::fs::set_permissions(
                                path,
                                std::fs::Permissions::from_mode(0o600),
                            );
                        }
                        Ok(json!({
                            "ok": true,
                            "npub": npub,
                            "out": path.display().to_string(),
                            "note": "the key inside is still NIP-49-locked — the passphrase travels out of band",
                        }))
                    }
                    None => Ok(bundle),
                }
            }
            AgentCmd::Import {
                file,
                bundle_passphrase,
                as_key,
            } => {
                let passphrase = require_passphrase(cli)?;
                let value: serde_json::Value =
                    serde_json::from_str(&std::fs::read_to_string(file)?)?;
                let report = apiary_core::portability::import_any(
                    &ks,
                    &value,
                    bundle_passphrase.as_deref(),
                    passphrase,
                    as_key.as_deref(),
                )?;
                Ok(json!({
                    "ok": true,
                    "npub": report.npub,
                    "name": report.name,
                    "log_entries": report.log_entries,
                    "ratified": report.ratified,
                    "index_rows": report.index_rows,
                    "index_dropped": report.index_dropped,
                    "note": "imported INACTIVE — activate to run standing presence; the lease referees any host overlap",
                }))
            }
            AgentCmd::Recover {
                npub,
                relay,
                key_file,
            } => {
                let npub = &normalize_key(npub)?;
                let passphrase = require_passphrase(cli)?;
                let pk = apiary_core::identity::parse_npub(npub)?;
                let hex = pk.to_hex();
                let ncryptsec = std::fs::read_to_string(key_file)?.trim().to_string();
                // The key unlocks self-tier entries during recovery.
                let enc = EncryptedSecretKey::from_bech32(&ncryptsec)
                    .map_err(|e| format!("key file is not valid ncryptsec: {e}"))?;
                let keys = Keys::new(
                    enc.decrypt(passphrase)
                        .map_err(|e| format!("passphrase does not open the key: {e}"))?,
                );
                let mut custody = Custody::new();
                let handle = custody.admit(keys);
                // 1. The constitution, from its addressable event.
                let mut manifest_yaml: Option<(u64, String)> = None;
                for r in relay {
                    let filter = json!({
                        "kinds": [apiary_runtime::publish::MANIFEST_KIND],
                        "authors": [hex],
                        "#d": ["apiary-manifest"],
                        "limit": 3,
                    });
                    for e in apiary_runtime::relay::fetch(r, filter).unwrap_or_default() {
                        if e.verify().is_ok()
                            && manifest_yaml
                                .as_ref()
                                .is_none_or(|(t, _)| e.created_at.as_secs() > *t)
                        {
                            manifest_yaml = Some((e.created_at.as_secs(), e.content.clone()));
                        }
                    }
                }
                let Some((_, manifest_yaml)) = manifest_yaml else {
                    return Err("no published manifest found on those relays — \
                                run `apiary log publish` on the origin host first, \
                                or move the agent with export/import"
                        .into());
                };
                // 2. The memory: published log events, self-tier unwrapped.
                let mut events: Vec<Event> = Vec::new();
                for r in relay {
                    let own = json!({
                        "authors": [hex],
                        "kinds": [
                            apiary_core::log::LOG_ENTRY_KIND,
                            apiary_runtime::publish::WRAPPED_KIND,
                        ],
                    });
                    let about = json!({
                        "kinds": [apiary_core::log::LOG_ENTRY_KIND],
                        "#p": [hex],
                    });
                    for fetched in [
                        apiary_runtime::relay::fetch(r, own),
                        apiary_runtime::relay::fetch(r, about),
                    ]
                    .into_iter()
                    .flatten()
                    {
                        for e in fetched {
                            if e.verify().is_err() {
                                continue;
                            }
                            let inner = if e.kind.as_u16() == apiary_runtime::publish::WRAPPED_KIND
                            {
                                match apiary_runtime::publish::unwrap_self_entry(
                                    &custody, &handle, &e,
                                ) {
                                    Ok(inner) => inner,
                                    Err(_) => continue,
                                }
                            } else {
                                e
                            };
                            if !events.iter().any(|x| x.id == inner.id) {
                                events.push(inner);
                            }
                        }
                    }
                }
                events.sort_by_key(|e| e.created_at.as_secs());
                let bundle = json!({
                    "apiary_export": apiary_core::portability::EXPORT_VERSION,
                    "exported_at": 0,
                    "npub": npub,
                    "name": "",
                    "manifest_yaml": manifest_yaml,
                    "key_ncryptsec": ncryptsec,
                    "log": events
                        .iter()
                        .map(|e| serde_json::from_str::<serde_json::Value>(&e.as_json())
                            .unwrap_or_default())
                        .collect::<Vec<_>>(),
                    "published": null,
                });
                let report = apiary_core::portability::import_with_options(
                    &ks, &bundle, passphrase, passphrase, false,
                )?;
                Ok(json!({
                    "ok": true,
                    "npub": report.npub,
                    "log_entries": report.log_entries,
                    "ratified": report.ratified,
                    "chain_intact": report.chain_intact,
                    "note": if report.chain_intact {
                        "fully recovered from relays"
                    } else {
                        "recovered with chain gaps — local-tier entries never left the origin host (expected)"
                    },
                }))
            }
            AgentCmd::List => {
                let agents: Vec<serde_json::Value> = ks
                    .list()?
                    .into_iter()
                    .map(|npub| {
                        let name = std::fs::read_to_string(ks.agent_dir(&npub).join("name")).ok();
                        json!({"npub": npub, "name": name})
                    })
                    .collect();
                Ok(json!({"ok": true, "agents": agents}))
            }
        },
        Command::Manifest { cmd } => match cmd {
            ManifestCmd::Validate { path } => {
                let raw = std::fs::read_to_string(path)?;
                let m = Manifest::from_yaml(&raw)?;
                Ok(json!({"ok": true, "npub": m.identity.npub, "valid": true}))
            }
            ManifestCmd::Show { npub } => {
                let npub = &normalize_key(npub)?;
                let raw = std::fs::read_to_string(ks.agent_dir(npub).join("manifest.yaml"))?;
                let m = Manifest::from_yaml(&raw)?;
                Ok(json!({"ok": true, "manifest": serde_json::to_value(&m)?}))
            }
        },
        Command::Log { cmd } => match cmd {
            LogCmd::Show { npub, tail } => {
                let npub = &normalize_key(npub)?;
                let log = EpisodicLog::open(&ks.agent_dir(npub));
                let entries: Vec<serde_json::Value> = log
                    .tail(*tail)?
                    .iter()
                    .map(|e| {
                        let body = EpisodicLog::parse_body(e).ok();
                        json!({
                            "id": e.id.to_hex(),
                            "at": e.created_at.as_secs(),
                            "signer": e.pubkey.to_hex(),
                            "body": body,
                        })
                    })
                    .collect();
                Ok(json!({"ok": true, "npub": npub, "entries": entries}))
            }
            LogCmd::Verify { npub } => {
                let npub = &normalize_key(npub)?;
                let count = EpisodicLog::open(&ks.agent_dir(npub)).verify()?;
                Ok(json!({"ok": true, "npub": npub, "entries": count, "chain": "valid"}))
            }
            LogCmd::Publish { npub } => {
                let npub = &normalize_key(npub)?;
                let passphrase = require_passphrase(cli)?;
                let agent_dir = ks.agent_dir(npub);
                let raw = std::fs::read_to_string(agent_dir.join("manifest.yaml"))?;
                let manifest = Manifest::from_yaml(&raw)?;
                let mut custody = Custody::new();
                let handle = custody.admit(ks.load(npub, passphrase)?);
                let report = apiary_runtime::publish::publish_log(
                    &agent_dir,
                    &custody,
                    &handle,
                    &manifest.memory.log_relays,
                )?;
                Ok(json!({
                    "ok": true,
                    "npub": npub,
                    "published_public": report.published_public,
                    "published_wrapped": report.published_wrapped,
                    "skipped_local": report.skipped_local,
                    "already_published": report.already_published,
                    "relays": report.relay_results,
                }))
            }
            LogCmd::Remote { npub } => {
                let npub = &normalize_key(npub)?;
                let passphrase = require_passphrase(cli)?;
                let agent_dir = ks.agent_dir(npub);
                let raw = std::fs::read_to_string(agent_dir.join("manifest.yaml"))?;
                let manifest = Manifest::from_yaml(&raw)?;
                let pk = apiary_core::identity::parse_npub(npub)?;
                let mut custody = Custody::new();
                let handle = custody.admit(ks.load(npub, passphrase)?);
                let mut summary = Vec::new();
                for relay in &manifest.memory.log_relays {
                    let own = json!({
                        "authors": [pk.to_hex()],
                        "kinds": [
                            apiary_core::log::LOG_ENTRY_KIND,
                            apiary_runtime::publish::WRAPPED_KIND,
                        ],
                    });
                    // Governance events about this agent (ratifications) are
                    // authored by humans — discovered via the p tag.
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
                            let mut public = 0usize;
                            let mut unwrapped = 0usize;
                            let mut opaque = 0usize;
                            let mut entries = Vec::new();
                            for e in &events {
                                if e.kind == Kind::Custom(apiary_runtime::publish::WRAPPED_KIND) {
                                    match apiary_runtime::publish::unwrap_self_entry(
                                        &custody, &handle, e,
                                    ) {
                                        Ok(inner) => {
                                            unwrapped += 1;
                                            if let Ok(body) = EpisodicLog::parse_body(&inner) {
                                                entries.push(json!({
                                                    "tier": "self (decrypted)",
                                                    "action": body.action,
                                                    "outcome": body.outcome,
                                                }));
                                            }
                                        }
                                        Err(_) => opaque += 1,
                                    }
                                } else {
                                    public += 1;
                                    if let Ok(body) = EpisodicLog::parse_body(e) {
                                        entries.push(json!({
                                            "tier": "public",
                                            "action": body.action,
                                            "outcome": body.outcome,
                                        }));
                                    }
                                }
                            }
                            summary.push(json!({
                                "relay": relay,
                                "events": events.len(),
                                "public": public,
                                "self_decrypted": unwrapped,
                                "undecryptable": opaque,
                                "entries": entries,
                            }));
                        }
                        Err(e) => summary.push(json!({"relay": relay, "error": e.to_string()})),
                    }
                }
                Ok(json!({"ok": true, "npub": npub, "relays": summary}))
            }
        },
        Command::Buzz { cmd } => {
            let (npub, relay) = match cmd {
                BuzzCmd::Channels { npub, relay }
                | BuzzCmd::Post { npub, relay, .. }
                | BuzzCmd::Read { npub, relay, .. }
                | BuzzCmd::Profile { npub, relay, .. }
                | BuzzCmd::Join { npub, relay, .. }
                | BuzzCmd::Listen { npub, relay, .. } => (npub, relay),
            };
            let npub = &normalize_key(npub)?;
            let passphrase = require_passphrase(cli)?;
            let agent_dir = ks.agent_dir(npub);
            let mut custody = Custody::new();
            let handle = custody.admit(ks.load(npub, passphrase)?);
            let mut session = apiary_runtime::buzz::BuzzSession::connect(relay, &custody, &handle)?;
            match cmd {
                BuzzCmd::Channels { .. } => {
                    let channels: Vec<serde_json::Value> = session
                        .channels()?
                        .iter()
                        .map(|e| {
                            let get = |name: &str| {
                                e.tags.iter().find_map(|t| {
                                    let s = t.as_slice();
                                    (s.first().map(String::as_str) == Some(name))
                                        .then(|| s.get(1).cloned())?
                                })
                            };
                            json!({
                                "id": get("d"),
                                "name": get("name"),
                                "visibility": get("visibility"),
                            })
                        })
                        .collect();
                    Ok(json!({"ok": true, "relay": relay, "channels": channels}))
                }
                BuzzCmd::Post {
                    channel, message, ..
                } => {
                    let event = session.post(channel, message, &[])?;
                    // Membership acts are part of the record.
                    let log = EpisodicLog::open(&agent_dir);
                    log.append(
                        &custody,
                        &handle,
                        apiary_core::log::Tier::Self_,
                        &apiary_core::log::EntryBody {
                            action: "buzz.post".into(),
                            model: None,
                            cost: None,
                            harness: None,
                            outcome: "ok".into(),
                            detail: Some(json!({
                                "relay": relay,
                                "channel": channel,
                                "event": event.id.to_hex(),
                                "chars": message.len(),
                            })),
                        },
                    )?;
                    Ok(json!({
                        "ok": true,
                        "relay": relay,
                        "channel": channel,
                        "event": event.id.to_hex(),
                    }))
                }
                BuzzCmd::Read { channel, limit, .. } => {
                    let msgs: Vec<serde_json::Value> = session
                        .read_channel(channel, *limit)?
                        .iter()
                        .map(|e| {
                            json!({
                                "at": e.created_at.as_secs(),
                                "author": e.pubkey.to_hex(),
                                "content": e.content,
                            })
                        })
                        .collect();
                    Ok(json!({"ok": true, "relay": relay, "channel": channel, "messages": msgs}))
                }
                BuzzCmd::Join { channel, .. } => {
                    let event = session.join_channel(channel)?;
                    Ok(json!({
                        "ok": true,
                        "relay": relay,
                        "channel": channel,
                        "event": event.id.to_hex(),
                        "note": "join requested — open channels admit immediately, private ones await an admin",
                    }))
                }
                BuzzCmd::Listen { trigger, .. } => {
                    // The full teammate loop: ratified constitution required,
                    // every mention answered through the GOVERNED run path
                    // (budget floors, provenance framing, signed log).
                    let raw = std::fs::read_to_string(agent_dir.join("manifest.yaml"))?;
                    let manifest = Manifest::from_yaml(&raw)?;
                    let suspend_keys = manifest
                        .governance
                        .suspend_keys
                        .iter()
                        .map(|k| apiary_core::identity::parse_npub(k))
                        .collect::<Result<Vec<_>, _>>()?;
                    let agent_pk = apiary_core::identity::parse_npub(npub)?;
                    let log = EpisodicLog::open(&agent_dir);
                    if !ceremony::is_ratified(&log, &raw, &agent_pk, &suspend_keys)? {
                        return Err("manifest is not ratified — nothing runs unratified".into());
                    }
                    let name = std::fs::read_to_string(agent_dir.join("name"))
                        .unwrap_or_default()
                        .trim()
                        .to_string();
                    let trigger = trigger.clone().unwrap_or_else(|| format!("@{name}"));
                    eprintln!(
                        "listening as {} (trigger: {trigger:?} or p-tag) — Ctrl-C to stop",
                        if name.is_empty() {
                            npub.as_str()
                        } else {
                            name.as_str()
                        }
                    );
                    // Never stops from inside: Ctrl-C is the terminal's stop.
                    let stop = std::sync::atomic::AtomicBool::new(false);
                    apiary_runtime::buzz::run_mention_service(
                        &manifest,
                        &agent_dir,
                        &custody,
                        &handle,
                        relay,
                        &trigger,
                        &stop,
                        |line| eprintln!("{line}"),
                    )?;
                    Ok(json!({"ok": true, "stopped": true}))
                }
                BuzzCmd::Profile {
                    name,
                    about,
                    picture,
                    image,
                    ..
                } => {
                    let uploaded = match image {
                        Some(path) => {
                            let bytes = std::fs::read(path)?;
                            let mime = match path
                                .extension()
                                .and_then(|e| e.to_str())
                                .map(str::to_ascii_lowercase)
                                .as_deref()
                            {
                                Some("png") => "image/png",
                                Some("jpg") | Some("jpeg") => "image/jpeg",
                                Some("webp") => "image/webp",
                                Some("gif") => "image/gif",
                                other => {
                                    return Err(apiary_core::Error::Manifest(format!(
                                        "unsupported image type {other:?} — png, jpeg, webp or gif"
                                    ))
                                    .into())
                                }
                            };
                            Some(apiary_runtime::buzz::upload_blob(
                                relay, &bytes, mime, &custody, &handle,
                            )?)
                        }
                        None => None,
                    };
                    let picture = uploaded.as_deref().or(picture.as_deref());
                    let event = session.set_profile(name, about.as_deref(), picture)?;
                    // The agent profile carries the picture too: kind-0 is
                    // how a user is shown, kind-10100 is how an AGENT is
                    // shown, and an avatar on only one of them is half done.
                    let skills = std::fs::read_to_string(agent_dir.join("manifest.yaml"))
                        .ok()
                        .and_then(|raw| apiary_core::manifest::Manifest::from_yaml(&raw).ok())
                        .map(|m| m.skills.iter().map(|s| s.name.clone()).collect::<Vec<_>>())
                        .unwrap_or_default();
                    session.set_agent_profile(name, &skills, picture)?;
                    let log = EpisodicLog::open(&agent_dir);
                    log.append(
                        &custody,
                        &handle,
                        apiary_core::log::Tier::Public,
                        &apiary_core::log::EntryBody {
                            action: "buzz.profile".into(),
                            model: None,
                            cost: None,
                            harness: None,
                            outcome: "ok".into(),
                            detail: Some(json!({
                                "relay": relay,
                                "name": name,
                                "event": event.id.to_hex(),
                            })),
                        },
                    )?;
                    Ok(json!({
                        "ok": true,
                        "relay": relay,
                        "name": name,
                        "event": event.id.to_hex(),
                        "picture": picture,
                    }))
                }
            }
        }
        Command::Routine { cmd } => match cmd {
            RoutineCmd::List { npub } => {
                let dir = ks.agent_dir(npub);
                let raw = std::fs::read_to_string(dir.join("manifest.yaml"))?;
                let m = apiary_core::manifest::Manifest::from_yaml(&raw)?;
                let st = apiary_runtime::routines::RoutinesFile::open(&dir).load();
                let now = chrono::Utc::now();
                let items: Vec<serde_json::Value> = m
                    .routines
                    .iter()
                    .map(|r| {
                        let rec = st.routines.get(&r.name).cloned().unwrap_or_default();
                        let (next, preview) = match apiary_runtime::routines::parse_schedule(r) {
                            Ok(s) => (
                                if r.enabled && !rec.paused && !rec.spent {
                                    s.next_after(rec.last_scheduled.unwrap_or(now).max(now), rec.last_fired.or(st.since))
                                } else {
                                    None
                                },
                                s.preview(now, 3),
                            ),
                            Err(_) => (None, vec![]),
                        };
                        json!({
                            "name": r.name, "when": r.when, "every": r.every, "at": r.at, "tz": r.tz,
                            "enabled": r.enabled, "paused": rec.paused, "spent": rec.spent,
                            "fires": rec.fires, "last_fired": rec.last_fired,
                            "last_outcome": rec.last_outcome, "next_fire": next, "preview": preview,
                            "deliver": r.deliver,
                        })
                    })
                    .collect();
                Ok(json!({"ok": true, "npub": npub, "since": st.since, "routines": items}))
            }
            RoutineCmd::Run { npub, name } => host_post(
                &cli.home,
                &format!("/api/agents/{npub}/routines/{name}/run"),
            ),
            RoutineCmd::Pause { npub, name } => host_post(
                &cli.home,
                &format!("/api/agents/{npub}/routines/{name}/pause"),
            ),
            RoutineCmd::Resume { npub, name } => host_post(
                &cli.home,
                &format!("/api/agents/{npub}/routines/{name}/resume"),
            ),
        },
        Command::Key { key } => {
            let pk = apiary_core::identity::parse_npub(key)?;
            let npub = apiary_core::identity::to_npub(&pk)?;
            let in_keystore = ks.agent_dir(&npub).join("key.ncryptsec").exists();
            Ok(json!({
                "ok": true,
                "npub": npub,
                "hex": pk.to_hex(),
                "in_keystore": in_keystore,
            }))
        }
        Command::Run {
            npub,
            task,
            class,
            data_class,
            harness,
            acp_cmd,
            acp_args,
            acp_allow,
        } => {
            let npub = &normalize_key(npub)?;
            let passphrase = require_passphrase(cli)?;
            let agent_dir = ks.agent_dir(npub);
            let raw = std::fs::read_to_string(agent_dir.join("manifest.yaml"))?;
            let manifest = Manifest::from_yaml(&raw)?;
            // Ratification gate: an unratified constitution doesn't run.
            let suspend_keys = manifest
                .governance
                .suspend_keys
                .iter()
                .map(|k| apiary_core::identity::parse_npub(k))
                .collect::<Result<Vec<_>, _>>()?;
            let log = EpisodicLog::open(&agent_dir);
            let agent_pk = apiary_core::identity::parse_npub(npub)?;
            if !ceremony::is_ratified(&log, &raw, &agent_pk, &suspend_keys)? {
                return Err(
                    "manifest is not ratified — run `apiary agent ratify` first \
                     (founding is constitution-then-amendments; nothing runs unratified)"
                        .into(),
                );
            }
            let mut custody = Custody::new();
            let handle = custody.admit(ks.load(npub, passphrase)?);

            if harness != "native" {
                let grant = if harness == "acp" {
                    let cmd = acp_cmd
                        .as_deref()
                        .ok_or("--acp-cmd is required with legacy --harness acp")?;
                    manifest
                        .harnesses
                        .iter()
                        .find(|grant| grant.command == cmd)
                        .ok_or_else(|| format!("no ratified harness grants command '{cmd}'"))?
                } else {
                    manifest
                        .harnesses
                        .iter()
                        .find(|grant| grant.name == *harness)
                        .ok_or_else(|| {
                            format!("harness '{harness}' is not granted to this agent")
                        })?
                };
                if !acp_args.is_empty() && acp_args != &grant.args {
                    return Err("--acp-arg cannot override the ratified harness arguments".into());
                }
                if *acp_allow && grant.access != apiary_core::manifest::HarnessAccess::Full {
                    return Err("--acp-allow cannot widen the ratified harness access".into());
                }
                let out = apiary_runtime::runner::run_acp_task(
                    &manifest, &agent_dir, &custody, &handle, task, grant,
                )?;
                return Ok(json!({
                    "ok": true,
                    "npub": npub,
                    "harness": grant.name,
                    "outcome": out.stop_reason,
                    "tool_calls": out.tool_calls,
                    "permission_decisions": out.permissions,
                    "log_event": out.log_event_id,
                    "response": out.text,
                }));
            }

            let ctx = apiary_runtime::routing::TaskContext {
                attachments: Vec::new(),
                task_class: class.clone(),
                data_class: data_class.clone(),
                tokens_per_run: None,
                disable_tools: false,
                ..Default::default()
            };
            let out = apiary_runtime::runner::run_task(
                &manifest, &agent_dir, &custody, &handle, task, &ctx,
            )?;
            Ok(json!({
                "ok": true,
                "npub": npub,
                "slot": out.slot,
                "model": out.completion.model,
                "outcome": out.completion.outcome,
                "tokens": {
                    "input": out.completion.input_tokens,
                    "output": out.completion.output_tokens,
                },
                "log_event": out.log_event_id,
                "response": out.completion.text,
            }))
        }
        Command::Credential { cmd } => match cmd {
            CredentialCmd::Seal { npub } => {
                let npub = &normalize_key(npub)?;
                let passphrase = require_passphrase(cli)?;
                let keys = ks.load(npub, passphrase)?;
                let mut custody = Custody::new();
                let handle = custody.admit(keys);
                let plaintext = read_stdin()?;
                let blob = custody.seal(&handle, plaintext.trim_end())?;
                Ok(json!({"ok": true, "npub": npub, "nip44": blob.nip44}))
            }
            CredentialCmd::Open { npub } => {
                let npub = &normalize_key(npub)?;
                let passphrase = require_passphrase(cli)?;
                let keys = ks.load(npub, passphrase)?;
                let mut custody = Custody::new();
                let handle = custody.admit(keys);
                let blob = apiary_core::manifest::EncryptedBlob {
                    nip44: read_stdin()?.trim().to_string(),
                };
                let plaintext = custody.open(&handle, &blob)?;
                Ok(json!({"ok": true, "npub": npub, "plaintext": plaintext.as_str()}))
            }
        },
    }
}

/// Accept a public key in any form (npub or hex) and normalize to the
/// canonical npub, which is how keystore directories are named.
fn normalize_key(s: &str) -> Result<String, Box<dyn std::error::Error>> {
    let pk = apiary_core::identity::parse_npub(s)?;
    Ok(apiary_core::identity::to_npub(&pk)?)
}

fn require_passphrase(cli: &Cli) -> Result<&str, Box<dyn std::error::Error>> {
    cli.passphrase
        .as_deref()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| "passphrase required: set APIARY_PASSPHRASE or --passphrase".into())
}

fn read_stdin() -> Result<String, std::io::Error> {
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    Ok(buf)
}

/// The minimal founding manifest: identity, memory, inference — and nothing
/// else until declared and ratified (SPEC §6: the capability floor for a
/// freshly founded agent is genuinely minimal).
fn founding_manifest_yaml(npub: &str, suspend_keys: &[String]) -> String {
    let keys_yaml: String = suspend_keys
        .iter()
        .map(|k| format!("    - {k}\n"))
        .collect();
    format!(
        "manifest_version: 1\n\
         identity:\n\
         \x20 npub: {npub}\n\
         inference: []\n\
         connectors: []\n\
         memory:\n\
         \x20 log: local\n\
         \x20 index: local\n\
         governance:\n\
         \x20 suspend_keys:\n{keys_yaml}"
    )
}

/// POST to the running desktop's daemon (found via <home>/desktop.json:
/// {url, token, pid} — written per launch, 0600). The operator door.
fn host_post(
    home: &std::path::Path,
    path: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let disc = home.join("desktop.json");
    let d: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&disc).map_err(|_| {
            format!(
                "no running host found ({} missing) — launch the Apiary desktop first",
                disc.display()
            )
        })?)?;
    let url = d["url"].as_str().ok_or("desktop.json has no url")?;
    let token = d["token"].as_str().unwrap_or("");
    let resp = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()?
        .post(format!("{url}{path}"))
        .header("x-apiary-token", token)
        .header("content-type", "application/json")
        .body("{}")
        .send()?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().unwrap_or(json!({"error": "non-JSON reply"}));
    if !status.is_success() {
        return Err(format!("host {status}: {}", body["error"].as_str().unwrap_or("?")).into());
    }
    Ok(body)
}
