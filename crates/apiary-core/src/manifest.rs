//! The agent manifest — SPEC §4.
//!
//! The agent *is* its manifest + key + memory. The manifest lives outside any
//! host's database: moving hosts is a file move, not a migration. Everything
//! capable is a connector (SPEC §6); the core has no capabilities, only custody.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Current manifest schema version. Versioned from v1 (SPEC §8: the manifest
/// is a contract — the first schema change must not break deployed agents).
pub const MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub manifest_version: u32,
    pub identity: Identity,
    /// The durable, human-ratified description of who this agent is and how
    /// it should behave. Capabilities remain separate: this can guide use of
    /// a connector, but can never grant one.
    #[serde(default, skip_serializing_if = "Constitution::is_empty")]
    pub constitution: Constitution,
    /// Ratified procedural knowledge. `SKILL.md` is the interchange format;
    /// the parsed content lives here so the manifest remains the single,
    /// portable source of truth.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skills: Vec<Skill>,
    /// Inference is a POOL, not a scalar — each entry is a full connection
    /// ("inference in" is itself a credentialed connection, SPEC §1/§7).
    #[serde(default)]
    pub inference: Vec<InferenceSlot>,
    #[serde(default)]
    pub routing: Routing,
    /// Everything capable is a connector, incl. shell & payments. Absent
    /// connector = absent capability (default-deny by construction).
    #[serde(default)]
    pub connectors: Vec<Connector>,
    /// Foreign execution loops are capabilities too. Each entry names one
    /// complete harness and the profile, tools, and accounting policy this
    /// agent's governors approved. Absent entry = harness unavailable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub harnesses: Vec<HarnessGrant>,
    pub memory: Memory,
    #[serde(default)]
    pub presence: Presence,
    pub governance: Governance,
    /// Single-instance liveness (SPEC §8 split-brain, §12.2 takeover modes).
    #[serde(default)]
    pub lease: LeaseConfig,
    /// Standing instructions the governor ratified once; the host replays
    /// them on schedule (SCOPE_routines). Time is the fourth door — the
    /// only one with no human on the other side — so a routine's authority
    /// comes from ratification, and it travels with the agent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routines: Vec<Routine>,
    /// Event-triggered standing instructions (SCOPE_proactive-agents): the
    /// agent acts because the world changed. Ratified like routines, run
    /// like routines, and paid for out of the proactive allowance.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub watches: Vec<Watch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    /// The agent's public key — the identity itself (bech32 npub).
    pub npub: String,
    /// Master-key custody: a NIP-46 remote signer URI. Running instances get
    /// session-scoped delegation only; a stolen host is not a stolen identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    /// Successor-key statement, signed at founding — cheap now, forward
    /// compatible with whatever rotation NIP the ecosystem lands on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub successor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessGrant {
    /// Stable selection name used by API and CLI runs.
    pub name: String,
    /// Adapter protocol. ACP is implemented today; additional adapters can
    /// be added without conflating a harness with an inference provider.
    #[serde(default = "default_harness_kind")]
    pub kind: String,
    pub command: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// inference-only | curated | full
    #[serde(default)]
    pub access: HarnessAccess,
    /// isolated | curated | inherit
    #[serde(default)]
    pub profile: HarnessProfile,
    /// none | read-only | no-network | read-only-no-network
    #[serde(default)]
    pub sandbox: HarnessSandbox,
    /// ACP permission-request titles permitted by a curated harness.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_tools: Vec<String>,
    /// Additional host environment variable names inherited by a curated
    /// profile. Full `inherit` deliberately receives the complete profile.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inherit_env: Vec<String>,
    /// unmetered | estimated | strict
    #[serde(default)]
    pub metering: HarnessMetering,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_tokens_per_run: Option<u64>,
    /// Optional ratified working directory. This selects a cwd; it is not an
    /// OS sandbox, and the cockpit states that distinction explicitly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,
}

fn default_harness_kind() -> String {
    "acp".into()
}

fn validate_slug(label: &str, value: &str, max: usize) -> Result<(), crate::Error> {
    let valid = !value.is_empty()
        && value.len() <= max
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if valid {
        Ok(())
    } else {
        Err(crate::Error::Manifest(format!(
            "{label} '{value}' must be 1-{max} lowercase letters, digits, or hyphens"
        )))
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HarnessAccess {
    /// Deny ACP permission requests; known harness-native modes are also
    /// pinned to chat/inference-only where an adapter supports that.
    #[default]
    InferenceOnly,
    /// Only permission requests matching `allowed_tools` may be approved.
    Curated,
    /// Approve the complete native tool surface exposed by the harness.
    Full,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HarnessProfile {
    /// Fresh per-agent HOME and scrubbed environment.
    #[default]
    Isolated,
    /// Fresh per-agent HOME plus explicitly named environment variables.
    Curated,
    /// Inherit the host user's complete environment and global profile.
    Inherit,
}

/// Optional OS-enforced restrictions applied to the entire harness process
/// tree. Support is platform-dependent and requested modes fail closed when
/// the host has no enforcement backend.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HarnessSandbox {
    /// No OS sandbox. Profile and ACP permission policy still apply.
    #[default]
    None,
    /// Deny filesystem writes. Reads and network remain available.
    ReadOnly,
    /// Deny network access. Filesystem access remains available.
    NoNetwork,
    /// Deny both filesystem writes and network access.
    ReadOnlyNoNetwork,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HarnessMetering {
    /// Run even though ACP reports no usage; daily token limits do not bound
    /// this harness. The signed log calls that out on every run.
    Unmetered,
    /// Charge a ratified per-run estimate against the daily ledger.
    Estimated,
    /// Refuse when the harness cannot report authoritative usage.
    #[default]
    Strict,
}

impl HarnessGrant {
    pub fn validate(&self) -> Result<(), crate::Error> {
        validate_slug("harness name", &self.name, 64)?;
        if self.kind != "acp" {
            return Err(crate::Error::Manifest(format!(
                "harness '{}' kind '{}' is unsupported (available: acp)",
                self.name, self.kind
            )));
        }
        if self.command.trim().is_empty() || self.command.chars().count() > 1024 {
            return Err(crate::Error::Manifest(format!(
                "harness '{}' command must be 1–1024 characters",
                self.name
            )));
        }
        if self.args.len() > 64 || self.args.iter().any(|arg| arg.len() > 4096) {
            return Err(crate::Error::Manifest(format!(
                "harness '{}' has too many or oversized arguments",
                self.name
            )));
        }
        if self.access == HarnessAccess::Curated && self.allowed_tools.is_empty() {
            return Err(crate::Error::Manifest(format!(
                "curated harness '{}' requires allowed_tools",
                self.name
            )));
        }
        if self.allowed_tools.len() > 256
            || self
                .allowed_tools
                .iter()
                .any(|tool| tool.trim().is_empty() || tool.len() > 512)
        {
            return Err(crate::Error::Manifest(format!(
                "harness '{}' has an invalid tool allowlist",
                self.name
            )));
        }
        if self.inherit_env.len() > 128
            || self.inherit_env.iter().any(|name| {
                name.is_empty()
                    || name.len() > 128
                    || !name
                        .as_bytes()
                        .first()
                        .is_some_and(|byte| *byte == b'_' || byte.is_ascii_alphabetic())
                    || !name
                        .bytes()
                        .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
            })
        {
            return Err(crate::Error::Manifest(format!(
                "harness '{}' has an invalid environment-variable allowlist",
                self.name
            )));
        }
        if self.workdir.as_ref().is_some_and(|workdir| {
            workdir.trim().is_empty() || workdir.len() > 4096 || workdir.contains('\0')
        }) {
            return Err(crate::Error::Manifest(format!(
                "harness '{}' has an invalid working directory",
                self.name
            )));
        }
        match (self.metering, self.estimated_tokens_per_run) {
            (HarnessMetering::Estimated, Some(1..=64_000)) => {}
            (HarnessMetering::Estimated, _) => {
                return Err(crate::Error::Manifest(format!(
                    "estimated harness '{}' needs estimated_tokens_per_run between 1 and 64000",
                    self.name
                )))
            }
            (_, Some(_)) => {
                return Err(crate::Error::Manifest(format!(
                    "harness '{}' may set estimated_tokens_per_run only with estimated metering",
                    self.name
                )))
            }
            _ => {}
        }
        Ok(())
    }
}

/// Human-owned operating character. These fields are injected as
/// authoritative instructions on every run and travel with the agent as part
/// of the ratified manifest.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Constitution {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub purpose: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub role: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub voice: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub principles: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub boundaries: Vec<String>,
}

impl Constitution {
    pub fn is_empty(&self) -> bool {
        self.purpose.is_empty()
            && self.role.is_empty()
            && self.voice.is_empty()
            && self.principles.is_empty()
            && self.boundaries.is_empty()
    }

    /// Stable, readable form for the runtime's authoritative system prompt.
    pub fn prompt_text(&self) -> String {
        let mut sections = Vec::new();
        if !self.purpose.is_empty() {
            sections.push(format!("Purpose: {}", self.purpose));
        }
        if !self.role.is_empty() {
            sections.push(format!("Role: {}", self.role));
        }
        if !self.voice.is_empty() {
            sections.push(format!("Voice: {}", self.voice));
        }
        if !self.principles.is_empty() {
            sections.push(format!(
                "Operating principles:\n- {}",
                self.principles.join("\n- ")
            ));
        }
        if !self.boundaries.is_empty() {
            sections.push(format!(
                "Behavioral boundaries:\n- {}",
                self.boundaries.join("\n- ")
            ));
        }
        sections.join("\n")
    }
}

/// One portable skill. Requirements describe capabilities the instructions
/// expect, but never grant them; connectors remain separate amendments.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Skill {
    pub name: String,
    pub description: String,
    pub instructions: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires_connectors: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SkillFrontmatter {
    name: String,
    description: String,
}

impl Skill {
    pub const MAX_COUNT: usize = 32;
    pub const MAX_DESCRIPTION_BYTES: usize = 2_048;
    pub const MAX_INSTRUCTIONS_BYTES: usize = 32_768;

    /// Parse the interoperable SKILL.md shape: YAML frontmatter containing
    /// only name + description, followed by Markdown instructions.
    pub fn from_markdown(
        markdown: &str,
        requires_connectors: Vec<String>,
    ) -> Result<Self, crate::Error> {
        let normalized = markdown.replace("\r\n", "\n");
        let rest = normalized.strip_prefix("---\n").ok_or_else(|| {
            crate::Error::Manifest("SKILL.md must start with YAML frontmatter ('---')".into())
        })?;
        let (frontmatter, instructions) = rest.split_once("\n---\n").ok_or_else(|| {
            crate::Error::Manifest("SKILL.md frontmatter needs a closing '---' line".into())
        })?;
        let header: SkillFrontmatter = serde_yaml::from_str(frontmatter)?;
        let mut skill = Self {
            name: header.name.trim().to_string(),
            description: header.description.trim().to_string(),
            instructions: instructions.trim().to_string(),
            requires_connectors: requires_connectors
                .into_iter()
                .map(|kind| kind.trim().to_string())
                .filter(|kind| !kind.is_empty())
                .collect(),
        };
        skill.requires_connectors.sort();
        skill.requires_connectors.dedup();
        skill.validate()?;
        Ok(skill)
    }

    pub fn to_markdown(&self) -> Result<String, crate::Error> {
        let frontmatter = serde_yaml::to_string(&SkillFrontmatter {
            name: self.name.clone(),
            description: self.description.clone(),
        })?;
        Ok(format!(
            "---\n{}\n---\n\n{}\n",
            frontmatter.trim_end(),
            self.instructions.trim()
        ))
    }

    pub fn validate(&self) -> Result<(), crate::Error> {
        let valid_name = !self.name.is_empty()
            && self.name.len() <= 64
            && !self.name.starts_with('-')
            && !self.name.ends_with('-')
            && self
                .name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !valid_name {
            return Err(crate::Error::Manifest(format!(
                "skill name '{}' must be 1-64 lowercase letters, digits, or hyphens",
                self.name
            )));
        }
        if self.description.trim().is_empty()
            || self.description.len() > Self::MAX_DESCRIPTION_BYTES
        {
            return Err(crate::Error::Manifest(format!(
                "skill '{}': description must be 1-{} bytes",
                self.name,
                Self::MAX_DESCRIPTION_BYTES
            )));
        }
        if self.instructions.trim().is_empty()
            || self.instructions.len() > Self::MAX_INSTRUCTIONS_BYTES
        {
            return Err(crate::Error::Manifest(format!(
                "skill '{}': instructions must be 1-{} bytes",
                self.name,
                Self::MAX_INSTRUCTIONS_BYTES
            )));
        }
        if self
            .requires_connectors
            .iter()
            .any(|kind| kind.trim().is_empty())
        {
            return Err(crate::Error::Manifest(format!(
                "skill '{}': connector requirements cannot be empty",
                self.name
            )));
        }
        let unique = self
            .requires_connectors
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        if unique.len() != self.requires_connectors.len() {
            return Err(crate::Error::Manifest(format!(
                "skill '{}': connector requirements must be unique",
                self.name
            )));
        }
        Ok(())
    }

    pub fn requirements_met(&self, manifest: &Manifest) -> bool {
        self.requires_connectors.iter().all(|required| {
            manifest
                .connectors
                .iter()
                .any(|connector| connector.kind == *required)
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceSlot {
    /// Pool-local name routing rules refer to: "workhorse", "fast", "local", "embed".
    pub name: String,
    /// "claude-code" | "codex" | "anthropic" | "openai" | "xai" | "ollama" | "mock".
    /// Claude Code and Codex use subscription auth through guarded local CLIs.
    /// The openai and xai providers speak the OpenAI-compatible dialect; `requires.
    /// base_url` points either at any compatible endpoint (Groq, Together,
    /// llama.cpp, LM Studio, ollama /v1 — keyless when local).
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Agent-owned credential: NIP-44 blob encrypted to the agent's pubkey.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<EncryptedBlob>,
    /// For provider = "host": cognitive requirements instead of a credential.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub requires: BTreeMap<String, serde_json::Value>,
}

/// Agent-authored, human-governed routing (SPEC §7). Floors are human-signed
/// and agent-immutable; rules may tighten them, never loosen (HARD_FLOORS
/// clamp, generalized). Merge order: floors → rules → default.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Routing {
    #[serde(default)]
    pub floors: Vec<RoutingRule>,
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// Explicit, human-ratified provider failover. Keys are primary slot
    /// names and values are tried in order, but only before any text or tool
    /// action has been emitted. An empty map means fail closed.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fallbacks: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingRule {
    /// Declarative condition, e.g. `data.class == "sensitive"`.
    pub when: String,
    /// Target inference-slot name.
    pub to: String,
    /// Per-rule provenance (SPEC §7): authored-by / approved-by / evidenced-by.
    #[serde(default, skip_serializing_if = "Provenance::is_empty")]
    pub provenance: Provenance,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authored_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    /// Pointers into the episodic log — evidence-cited amendments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidenced_by: Vec<String>,
}

impl Provenance {
    pub fn is_empty(&self) -> bool {
        self.authored_by.is_none() && self.approved_by.is_none() && self.evidenced_by.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Connector {
    /// "square", "shell-sandboxed", "cashu-wallet", …
    #[serde(rename = "type")]
    pub kind: String,
    /// NIP-44 blob encrypted to the agent's pubkey; useless without the key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<EncryptedBlob>,
    /// Spend-authority floors and behavioral caps, human-owned.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub caps: BTreeMap<String, serde_json::Value>,
}

impl Connector {
    /// True for an MCP connector whose allowlist is empty: freshly granted
    /// (the library entry carries no allowlist) and not yet configured.
    /// Valid but inert — it binds zero tools until tools are ticked.
    pub fn grants_no_tools(&self) -> bool {
        if self.kind != "mcp" {
            return false;
        }
        let has_allowed = self
            .caps
            .get("allowed_tools")
            .and_then(|v| v.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false);
        let has_access = self
            .caps
            .get("tool_access")
            .and_then(|v| v.as_object())
            .map(|o| !o.is_empty())
            .unwrap_or(false);
        !has_allowed && !has_access
    }
}

/// Memory is three stores with different sync/growth/privacy (SPEC §9).
/// The working set is ephemeral and deliberately absent from the manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Memory {
    /// Signed episodic log location (append-only), e.g. `relay://…` or a path.
    pub log: String,
    /// Semantic index location — derived, rebuildable.
    #[serde(default = "default_index")]
    pub index: String,
    /// Relays the log is published to (tier-enforced: public plain,
    /// self NIP-44-wrapped, local never).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub log_relays: Vec<String>,
    /// Keep what was actually said in conversations, not merely that they
    /// happened.
    ///
    /// Off by default, and deliberately so: the episodic log is signed,
    /// portable, and sometimes published, so other people's words do not
    /// belong in it unless a governor decided they should. Turning it on
    /// gives the agent durable memory that survives the relay's retention,
    /// travels with it between hosts, and — with an `embed` slot — becomes
    /// searchable recall rather than just the last few messages.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub remember_conversations: bool,
    /// Markdown knowledge folders (Obsidian vaults, KB repos, plain note
    /// dirs) chunked into the semantic index — ambient recall alongside
    /// the agent's own log memories. Host-local paths: vault contents are
    /// NOT exported or published; a destination host re-indexes its own.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vaults: Vec<VaultRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultRef {
    /// Short name used in index rows and retrieval provenance.
    pub name: String,
    pub path: String,
    /// "markdown" (default) or "obsidian" (frontmatter/tags/wikilinks).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

fn default_index() -> String {
    "local".into()
}

/// Standing presence: which platforms the agent LIVES on, answering when
/// spoken to. A map so channels are pluggable — built-ins (buzz, telegram,
/// slack) and installed Channel Plugin Protocol plugins share one shape.
/// Where the agent lives is constitutional: each entry is ratified.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Presence {
    #[serde(flatten)]
    pub channels: std::collections::BTreeMap<String, PresenceChannel>,
}

/// One presence channel: an optional credential sealed to the agent (a
/// platform token — the platform shim; the identity stays the npub) plus
/// kind-specific configuration keys.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PresenceChannel {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<EncryptedBlob>,
    #[serde(flatten)]
    pub config: std::collections::BTreeMap<String, serde_json::Value>,
}

impl Presence {
    pub fn channel(&self, kind: &str) -> Option<&PresenceChannel> {
        self.channels.get(kind)
    }
}

impl PresenceChannel {
    pub fn str_config(&self, key: &str) -> Option<&str> {
        self.config.get(key).and_then(|v| v.as_str())
    }
    pub fn list_config(&self, key: &str) -> Vec<String> {
        self.config
            .get(key)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Governance {
    /// Independent Nostr identities that can halt and govern the agent
    /// (SPEC §8). An identity may belong to a person or a separate manager
    /// agent; suspension authority must never rest with this agent's own key.
    pub suspend_keys: Vec<String>,
    /// Additional per-agent managers with explicitly bounded authority.
    /// Existing `suspend_keys` are always governors for backward
    /// compatibility and remain eligible to ratify constitutional changes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub managers: Vec<ManagerGrant>,
    /// Unified spend authority: token budgets and money budgets are one
    /// system of human-owned floors enforced by the host core.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub budgets: BTreeMap<String, serde_json::Value>,
    /// Capabilities normally reserved for the human door. Off by default;
    /// each one must be enabled by a HUMAN ratification (see `Autonomy`).
    #[serde(default, skip_serializing_if = "Autonomy::is_empty")]
    pub autonomy: Autonomy,
}

/// Full-autonomy capabilities — the four things only a person could do.
///
/// Apiary's design rests on these being unreachable from the agent surface:
/// "authority comes from the door", and this is the human door. A lead agent
/// running lights-out may be granted them per capability, and every use is a
/// signed log entry — but ONE rail is not negotiable and is enforced in the
/// ratify path: **autonomy can never grant autonomy.** Enabling any flag
/// requires a human ratifier, so an autonomous agent cannot widen its own
/// authority or another agent's. `suspend_keys` always stops it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Autonomy {
    /// Enact constitutional change: sign the ratification a human normally
    /// signs. Governance without a person in the loop.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ratify: bool,
    /// Bring the keystore to life unattended (POST /api/unlock).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unlock: bool,
    /// Produce a sealed export bundle — memory plus re-sealed credentials,
    /// addressed to another host. An agent that can export can relocate.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub export: bool,
    /// Open sealed credentials to PLAINTEXT. The widest of the four: a
    /// holder can act as any provider the agent has, outside Apiary's audit.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub open_credentials: bool,
}

impl Autonomy {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// True if `self` enables anything `previous` did not — the test the
    /// ratify path applies before accepting an agent's signature.
    pub fn expands_beyond(&self, previous: &Self) -> bool {
        (self.ratify && !previous.ratify)
            || (self.unlock && !previous.unlock)
            || (self.export && !previous.export)
            || (self.open_credentials && !previous.open_credentials)
    }

    /// Human-readable list of what is enabled, for logs and the cockpit.
    pub fn granted(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.ratify {
            out.push("ratify");
        }
        if self.unlock {
            out.push("unlock");
        }
        if self.export {
            out.push("export");
        }
        if self.open_credentials {
            out.push("open credentials");
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ManagerRole {
    /// Inspect the agent's non-secret environment and audit-visible state.
    Viewer,
    /// Viewer rights plus runs, activation, delivery, and other operations.
    Operator,
    /// Operator rights plus proposing configuration amendments.
    Editor,
    /// Full per-agent authority, including managers, credentials, and ratification.
    Governor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagerGrant {
    pub npub: String,
    pub role: ManagerRole,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseConfig {
    /// Where liveness is asserted. "relay-event" = signed, replaceable
    /// "running on host X until T" event.
    #[serde(default = "default_lease_mechanism")]
    pub mechanism: String,
    /// Takeover policy (SPEC §12.2): "auto" | "human" | "contested-human".
    #[serde(default = "default_takeover")]
    pub takeover: String,
    #[serde(default = "default_heartbeat_secs")]
    pub heartbeat_secs: u64,
    #[serde(default = "default_expiry_secs")]
    pub expiry_secs: u64,
}

impl Default for LeaseConfig {
    fn default() -> Self {
        Self {
            mechanism: default_lease_mechanism(),
            takeover: default_takeover(),
            heartbeat_secs: default_heartbeat_secs(),
            expiry_secs: default_expiry_secs(),
        }
    }
}

fn default_lease_mechanism() -> String {
    "relay-event".into()
}
fn default_takeover() -> String {
    "contested-human".into()
}
fn default_heartbeat_secs() -> u64 {
    300
}
fn default_expiry_secs() -> u64 {
    900
}

/// A NIP-44 ciphertext envelope. Portable; useless without the agent's key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedBlob {
    /// base64 NIP-44 v2 payload.
    pub nip44: String,
}

/// One scheduled, governed run.
/// A watch is a door the governor ratified in advance: the agent runs
/// because the world changed, not because a person spoke or a clock struck.
///
/// The trigger is never the authority — this ratified watch is. What the
/// trigger carries (a file's contents, later a relay event) reaches the run
/// as DATA, framed exactly like platform text: a file that appears saying
/// "ignore your instructions" is a file that appeared, nothing more.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Watch {
    pub name: String,
    /// What is watched. "vault" today; relay/connector/webhook later.
    pub on: String,
    /// Which granted vault (a `memory.vaults` name). Required for "vault".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
    /// Optional path substring filter, e.g. "PROJECT.md". Absent = any file.
    #[serde(rename = "match", default, skip_serializing_if = "Option::is_none")]
    pub match_path: Option<String>,
    /// The instruction, ratified with the manifest.
    pub task: String,
    /// Coalesce a burst of changes into one run ("30s", "5m", "2h").
    #[serde(default = "default_debounce")]
    pub debounce: String,
    /// Hard ceiling. Refuses for the rest of the day rather than queueing —
    /// a backlog that fires at midnight is worse than a gap.
    #[serde(default = "default_max_per_day")]
    pub max_per_day: u32,
    /// Empty (the default) means the run delivers nothing: proactive work
    /// is silent unless the agent uses a send tool or this says otherwise.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deliver: Vec<Delivery>,
    #[serde(default)]
    pub budget: RoutineBudget,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_debounce() -> String {
    "5m".into()
}

fn default_max_per_day() -> u32 {
    12
}

impl Watch {
    /// Triggers this host understands.
    pub const KINDS: [&'static str; 1] = ["vault"];
    pub const MAX_PER_DAY_CEILING: u32 = 200;
}

/// "90s" | "15m" | "2h" | "1d" → seconds. One spelling of duration for the
/// whole system: the schema validates with it, the schedule engine runs on it.
pub fn parse_duration_secs(s: &str) -> Option<i64> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.len().checked_sub(1)?);
    let n: i64 = num.trim().parse().ok()?;
    if n <= 0 {
        return None;
    }
    Some(match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86_400,
        _ => return None,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Routine {
    pub name: String,
    /// Exactly one of `when` (5-field cron or @hourly/@daily/@weekly),
    /// `every` ("15m", "2h", "1d"; minimum 1m), `at` (ISO-8601 datetime,
    /// one-shot — disables itself after firing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub every: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    /// IANA zone; REQUIRED with `when` and `at` (a portable agent must not
    /// fire at the wrong hour because it moved hosts). Ignored for `every`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tz: Option<String>,
    /// The instruction. Ratified with the manifest — a mention can never
    /// plant one.
    pub task: String,
    /// task_class for routing rules (default "routine").
    #[serde(default = "default_routine_class")]
    pub class: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deliver: Vec<Delivery>,
    #[serde(default)]
    pub budget: RoutineBudget,
    /// "none" | "one" — a missed fire (host asleep) runs once on wake,
    /// never a backlog.
    #[serde(default = "default_catch_up")]
    pub catch_up: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// Where a routine's reply goes — surfaces the agent already has.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telegram: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buzz: Option<String>,
    /// `publish` — kind-1 via the nostr-publish connector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nostr: Option<String>,
    /// Spoken by a connected apiary-voice.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub companion: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub as_voice: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutineBudget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens_per_run: Option<u64>,
}

fn default_routine_class() -> String {
    "routine".into()
}
fn default_catch_up() -> String {
    "one".into()
}
fn default_true() -> bool {
    true
}

impl Manifest {
    pub fn from_yaml(s: &str) -> Result<Self, crate::Error> {
        let m: Manifest = serde_yaml::from_str(s)?;
        m.validate()?;
        Ok(m)
    }

    /// Parse WITHOUT the invariant checks — for surfaces that must be able
    /// to display and REPAIR an invalid manifest (the cockpit's Connectors
    /// tab fixing a missing allowlist). Never run an agent from this:
    /// callers that execute must call validate() and refuse.
    pub fn from_yaml_unvalidated(s: &str) -> Result<Self, crate::Error> {
        Ok(serde_yaml::from_str(s)?)
    }

    pub fn to_yaml(&self) -> Result<String, crate::Error> {
        Ok(serde_yaml::to_string(self)?)
    }

    /// Structural validation beyond serde: the invariants the substrate owns.
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.manifest_version != MANIFEST_VERSION {
            return Err(crate::Error::Manifest(format!(
                "unsupported manifest_version {} (host supports {})",
                self.manifest_version, MANIFEST_VERSION
            )));
        }
        let agent_pk = crate::identity::parse_npub(&self.identity.npub)?;
        let has_governor = !self.governance.suspend_keys.is_empty()
            || self
                .governance
                .managers
                .iter()
                .any(|manager| manager.role == ManagerRole::Governor);
        if !has_governor {
            return Err(crate::Error::Manifest(
                "governance must name at least one independent governor identity: \
                 suspension authority can never rest with the agent's own key"
                    .into(),
            ));
        }
        // Manager identities must be valid, unique, and independent from the
        // agent itself. Duplicate declarations would make effective authority
        // ambiguous, so fail closed rather than silently choosing a role.
        let mut manager_keys = std::collections::BTreeSet::new();
        for k in &self.governance.suspend_keys {
            let pk = crate::identity::parse_npub(k)?;
            if pk == agent_pk {
                return Err(crate::Error::Manifest(
                    "agent's own key cannot be a suspend key".into(),
                ));
            }
            if !manager_keys.insert(pk) {
                return Err(crate::Error::Manifest(
                    "duplicate governance manager identity".into(),
                ));
            }
        }
        if self.governance.managers.len() > 256 {
            return Err(crate::Error::Manifest(
                "governance may declare at most 256 managers".into(),
            ));
        }
        for manager in &self.governance.managers {
            let pk = crate::identity::parse_npub(&manager.npub)?;
            if pk == agent_pk {
                return Err(crate::Error::Manifest(
                    "agent's own key cannot manage itself".into(),
                ));
            }
            if !manager_keys.insert(pk) {
                return Err(crate::Error::Manifest(
                    "duplicate governance manager identity".into(),
                ));
            }
        }
        if self.skills.len() > Skill::MAX_COUNT {
            return Err(crate::Error::Manifest(format!(
                "manifest declares {} skills; at most {} are allowed",
                self.skills.len(),
                Skill::MAX_COUNT
            )));
        }
        let mut skill_names = std::collections::BTreeSet::new();
        for skill in &self.skills {
            skill.validate()?;
            if !skill_names.insert(skill.name.as_str()) {
                return Err(crate::Error::Manifest(format!(
                    "duplicate skill name '{}'",
                    skill.name
                )));
            }
        }
        let mut harness_names = std::collections::BTreeSet::new();
        for harness in &self.harnesses {
            harness.validate()?;
            if !harness_names.insert(harness.name.as_str()) {
                return Err(crate::Error::Manifest(format!(
                    "duplicate harness name '{}'",
                    harness.name
                )));
            }
        }
        // Routing targets must exist in the inference pool.
        let slot_names: Vec<&str> = self.inference.iter().map(|s| s.name.as_str()).collect();
        for rule in self.routing.floors.iter().chain(self.routing.rules.iter()) {
            if !slot_names.contains(&rule.to.as_str()) {
                return Err(crate::Error::Manifest(format!(
                    "routing rule targets unknown inference slot '{}'",
                    rule.to
                )));
            }
        }
        if let Some(d) = &self.routing.default {
            if !slot_names.contains(&d.as_str()) {
                return Err(crate::Error::Manifest(format!(
                    "routing default targets unknown inference slot '{d}'"
                )));
            }
        }
        for (primary, fallbacks) in &self.routing.fallbacks {
            if !slot_names.contains(&primary.as_str()) {
                return Err(crate::Error::Manifest(format!(
                    "routing fallback names unknown primary inference slot '{primary}'"
                )));
            }
            let mut seen_fallbacks = std::collections::BTreeSet::new();
            for fallback in fallbacks {
                if !slot_names.contains(&fallback.as_str()) {
                    return Err(crate::Error::Manifest(format!(
                        "routing fallback targets unknown inference slot '{fallback}'"
                    )));
                }
                if fallback == primary || !seen_fallbacks.insert(fallback) {
                    return Err(crate::Error::Manifest(format!(
                        "routing fallback for '{primary}' repeats slot '{fallback}'"
                    )));
                }
            }
        }
        // An MCP connector with no allowlist is VALID but INERT: it binds
        // zero tools. Making it a validation error created a catch-22 —
        // a fresh grant (or an OAuth re-connect, which re-grants) copies
        // the library entry, and the allowlist can only be added to the
        // manifest AFTER the grant exists. The host surfaces inert
        // connectors loudly instead (see Connector::grants_no_tools).
        // Routines: one schedule spelling, tz where it matters, valid
        // delivery targets, unique names.
        let mut rnames = std::collections::BTreeSet::new();
        for r in &self.routines {
            if r.name.trim().is_empty() || !rnames.insert(r.name.as_str()) {
                return Err(crate::Error::Manifest(format!(
                    "routine name '{}' is empty or duplicated",
                    r.name
                )));
            }
            let spellings = [r.when.is_some(), r.every.is_some(), r.at.is_some()]
                .iter()
                .filter(|b| **b)
                .count();
            if spellings != 1 {
                return Err(crate::Error::Manifest(format!(
                    "routine '{}' needs exactly one of when / every / at",
                    r.name
                )));
            }
            if (r.when.is_some() || r.at.is_some()) && r.tz.is_none() {
                return Err(crate::Error::Manifest(format!(
                    "routine '{}' needs tz (an IANA zone) with when/at — a portable agent \
                     must not fire at the wrong hour on a new host",
                    r.name
                )));
            }
            if r.task.trim().is_empty() {
                return Err(crate::Error::Manifest(format!(
                    "routine '{}' has an empty task",
                    r.name
                )));
            }
            if !matches!(r.catch_up.as_str(), "none" | "one") {
                return Err(crate::Error::Manifest(format!(
                    "routine '{}': catch_up must be none | one",
                    r.name
                )));
            }
            for d in &r.deliver {
                let targets = [
                    d.telegram.is_some(),
                    d.buzz.is_some(),
                    d.nostr.is_some(),
                    d.companion,
                ]
                .iter()
                .filter(|b| **b)
                .count();
                if targets != 1 {
                    return Err(crate::Error::Manifest(format!(
                        "routine '{}': each deliver entry names exactly one target",
                        r.name
                    )));
                }
                if d.telegram.is_some() && self.presence.channel("telegram").is_none() {
                    return Err(crate::Error::Manifest(format!(
                        "routine '{}' delivers to telegram but the agent has no telegram presence",
                        r.name
                    )));
                }
                if d.buzz.is_some() && self.presence.channel("buzz").is_none() {
                    return Err(crate::Error::Manifest(format!(
                        "routine '{}' delivers to buzz but the agent has no buzz presence",
                        r.name
                    )));
                }
                if let Some(n) = &d.nostr {
                    if n != "publish" || !self.connectors.iter().any(|c| c.kind == "nostr-publish")
                    {
                        return Err(crate::Error::Manifest(format!(
                            "routine '{}': nostr delivery must be 'publish' and needs the \
                             nostr-publish connector",
                            r.name
                        )));
                    }
                }
            }
        }
        // Watches: a known trigger, a vault the agent actually has, a real
        // debounce, and a ceiling. A watch without bounds is a retry storm.
        let mut wnames = std::collections::BTreeSet::new();
        for w in &self.watches {
            if w.name.trim().is_empty() || !wnames.insert(w.name.as_str()) {
                return Err(crate::Error::Manifest(format!(
                    "watch name '{}' is empty or duplicated",
                    w.name
                )));
            }
            if !Watch::KINDS.contains(&w.on.as_str()) {
                return Err(crate::Error::Manifest(format!(
                    "watch '{}': unknown trigger '{}' (this host watches: {})",
                    w.name,
                    w.on,
                    Watch::KINDS.join(", ")
                )));
            }
            if w.task.trim().is_empty() {
                return Err(crate::Error::Manifest(format!(
                    "watch '{}' has an empty task",
                    w.name
                )));
            }
            if w.on == "vault" {
                let Some(vault) = w.vault.as_deref().map(str::trim).filter(|v| !v.is_empty()) else {
                    return Err(crate::Error::Manifest(format!(
                        "watch '{}' watches a vault but names none",
                        w.name
                    )));
                };
                if !self.memory.vaults.iter().any(|v| v.name == vault) {
                    return Err(crate::Error::Manifest(format!(
                        "watch '{}' watches vault '{vault}', which this agent has not been \
                         granted (memory.vaults)",
                        w.name
                    )));
                }
            }
            if parse_duration_secs(&w.debounce).is_none() {
                return Err(crate::Error::Manifest(format!(
                    "watch '{}': debounce '{}' is not a duration like 30s, 5m, 2h",
                    w.name, w.debounce
                )));
            }
            if w.max_per_day == 0 || w.max_per_day > Watch::MAX_PER_DAY_CEILING {
                return Err(crate::Error::Manifest(format!(
                    "watch '{}': max_per_day must be between 1 and {}",
                    w.name,
                    Watch::MAX_PER_DAY_CEILING
                )));
            }
            for d in &w.deliver {
                let targets = [
                    d.telegram.is_some(),
                    d.buzz.is_some(),
                    d.nostr.is_some(),
                    d.companion,
                ]
                .iter()
                .filter(|b| **b)
                .count();
                if targets != 1 {
                    return Err(crate::Error::Manifest(format!(
                        "watch '{}': each deliver entry names exactly one target",
                        w.name
                    )));
                }
                if d.telegram.is_some() && self.presence.channel("telegram").is_none() {
                    return Err(crate::Error::Manifest(format!(
                        "watch '{}' delivers to telegram but the agent has no telegram presence",
                        w.name
                    )));
                }
                if d.buzz.is_some() && self.presence.channel("buzz").is_none() {
                    return Err(crate::Error::Manifest(format!(
                        "watch '{}' delivers to buzz but the agent has no buzz presence",
                        w.name
                    )));
                }
            }
        }
        // Duplicate slot names would make routing ambiguous.
        let mut seen = std::collections::BTreeSet::new();
        for n in &slot_names {
            if !seen.insert(*n) {
                return Err(crate::Error::Manifest(format!(
                    "duplicate inference slot name '{n}'"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity;
    use nostr::prelude::Keys;

    fn minimal_yaml() -> String {
        let agent = identity::to_npub(&Keys::generate().public_key()).unwrap();
        let human = identity::to_npub(&Keys::generate().public_key()).unwrap();
        format!(
            "manifest_version: 1\nidentity:\n  npub: {agent}\nmemory:\n  log: local\n\
             governance:\n  suspend_keys:\n    - {human}\n"
        )
    }

    #[test]
    fn manifests_without_a_constitution_remain_valid() {
        let manifest = Manifest::from_yaml(&minimal_yaml()).unwrap();
        assert!(manifest.constitution.is_empty());
        assert!(!manifest.to_yaml().unwrap().contains("constitution:"));
    }

    #[test]
    fn routing_fallbacks_are_explicit_and_validated() {
        let mut manifest = Manifest::from_yaml(&minimal_yaml()).unwrap();
        manifest.inference = vec![
            InferenceSlot {
                name: "primary".into(),
                provider: "mock".into(),
                model: Some("primary-model".into()),
                credential: None,
                requires: Default::default(),
            },
            InferenceSlot {
                name: "backup".into(),
                provider: "mock".into(),
                model: Some("backup-model".into()),
                credential: None,
                requires: Default::default(),
            },
        ];
        manifest.routing.default = Some("primary".into());
        manifest
            .routing
            .fallbacks
            .insert("primary".into(), vec!["backup".into()]);
        manifest.validate().unwrap();
        assert!(manifest.to_yaml().unwrap().contains("fallbacks:"));

        manifest
            .routing
            .fallbacks
            .insert("primary".into(), vec!["missing".into()]);
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn harness_grants_are_portable_and_fail_closed() {
        let mut manifest = Manifest::from_yaml(&minimal_yaml()).unwrap();
        manifest.harnesses.push(HarnessGrant {
            name: "goose-workspace".into(),
            kind: "acp".into(),
            command: "goose".into(),
            args: vec!["acp".into()],
            access: HarnessAccess::Curated,
            profile: HarnessProfile::Isolated,
            sandbox: HarnessSandbox::ReadOnly,
            allowed_tools: vec!["shell".into(), "write_file".into()],
            inherit_env: Vec::new(),
            metering: HarnessMetering::Estimated,
            estimated_tokens_per_run: Some(8192),
            workdir: Some("/workspace".into()),
        });
        manifest.validate().unwrap();
        let round_trip = Manifest::from_yaml(&manifest.to_yaml().unwrap()).unwrap();
        assert_eq!(round_trip.harnesses[0].name, "goose-workspace");
        assert_eq!(round_trip.harnesses[0].access, HarnessAccess::Curated);
        assert_eq!(round_trip.harnesses[0].sandbox, HarnessSandbox::ReadOnly);

        let mut bad = round_trip.harnesses[0].clone();
        bad.allowed_tools.clear();
        assert!(bad.validate().is_err());
        bad.access = HarnessAccess::Full;
        bad.metering = HarnessMetering::Strict;
        bad.estimated_tokens_per_run = Some(100);
        assert!(bad.validate().is_err());
    }

    #[test]
    fn scoped_manager_roles_require_an_independent_governor() {
        let mut manifest = Manifest::from_yaml(&minimal_yaml()).unwrap();
        let governor = identity::to_npub(&Keys::generate().public_key()).unwrap();
        let viewer = identity::to_npub(&Keys::generate().public_key()).unwrap();
        manifest.governance.suspend_keys.clear();
        manifest.governance.managers = vec![ManagerGrant {
            npub: viewer,
            role: ManagerRole::Viewer,
        }];
        assert!(manifest.validate().is_err());
        manifest.governance.managers.push(ManagerGrant {
            npub: governor.clone(),
            role: ManagerRole::Governor,
        });
        manifest.validate().unwrap();

        manifest.governance.suspend_keys = vec![governor];
        assert!(manifest.validate().is_err());

        manifest.governance.suspend_keys.clear();
        manifest.governance.managers[1].npub = manifest.identity.npub.clone();
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn constitution_prompt_text_keeps_each_operating_layer() {
        let constitution = Constitution {
            purpose: "Help customers".into(),
            role: "Support specialist".into(),
            voice: "Warm and direct".into(),
            principles: vec!["Verify account details".into()],
            boundaries: vec!["Do not issue refunds".into()],
        };
        let prompt = constitution.prompt_text();
        assert!(prompt.contains("Purpose: Help customers"));
        assert!(prompt.contains("Role: Support specialist"));
        assert!(prompt.contains("Voice: Warm and direct"));
        assert!(prompt.contains("Operating principles:\n- Verify account details"));
        assert!(prompt.contains("Behavioral boundaries:\n- Do not issue refunds"));
    }

    #[test]
    fn skill_markdown_round_trips_and_normalizes_requirements() {
        let markdown = "---\r\nname: web-research\r\ndescription: Research current topics with sources.\r\n---\r\n\r\n# Workflow\r\n\r\nSearch, read, and cite.\r\n";
        let skill = Skill::from_markdown(
            markdown,
            vec![
                " web-fetch ".into(),
                "web-search".into(),
                "web-search".into(),
            ],
        )
        .unwrap();
        assert_eq!(skill.name, "web-research");
        assert_eq!(skill.requires_connectors, ["web-fetch", "web-search"]);
        let round_trip = Skill::from_markdown(
            &skill.to_markdown().unwrap(),
            skill.requires_connectors.clone(),
        )
        .unwrap();
        assert_eq!(round_trip.name, skill.name);
        assert_eq!(round_trip.description, skill.description);
        assert_eq!(round_trip.instructions, skill.instructions);
    }

    #[test]
    fn skill_markdown_rejects_extra_frontmatter_and_bad_names() {
        let extra =
            "---\nname: research\ndescription: Research things.\nauthor: stranger\n---\nDo it.";
        assert!(Skill::from_markdown(extra, vec![]).is_err());
        let bad_name = "---\nname: Research Skill\ndescription: Research things.\n---\nDo it.";
        assert!(Skill::from_markdown(bad_name, vec![]).is_err());
    }
}
