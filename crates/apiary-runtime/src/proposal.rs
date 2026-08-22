//! Agent-drafted amendments (SCOPE_routines, piece 5). An agent may
//! PROPOSE a change to its own constitution — "I could send you this
//! every morning, shall I?" — but never enact one: the proposal lands in
//! `manifest.proposed.yaml` beside the manifest, the cockpit shows it as
//! pending the governor's decision, and accepting it is the ordinary
//! amend-then-ratify path. Nothing new to trust: the same signature the
//! agent needs for everything else.
//!
//! Hard rule enforced here: a proposal cannot change identity or
//! governance.suspend_keys. The rest is the governor's call.

use apiary_core::manifest::{Manifest, Routine};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const PROPOSED_FILE: &str = "manifest.proposed.yaml";
pub const PROPOSAL_META: &str = "proposal.json";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProposalMeta {
    pub reason: String,
    pub summary: String,
    pub at: String,
    /// "routine" | "yaml"
    pub kind: String,
}

pub fn proposed_path(agent_dir: &Path) -> PathBuf {
    agent_dir.join(PROPOSED_FILE)
}

/// Validate a candidate manifest against the current one and write it as
/// the pending proposal (replacing any earlier one — one at a time).
pub fn write_proposal(
    agent_dir: &Path,
    current: &Manifest,
    candidate: &Manifest,
    meta: ProposalMeta,
) -> Result<(), crate::Error> {
    candidate.validate()?;
    if candidate.identity.npub != current.identity.npub {
        return Err(crate::Error::Provider(
            "a proposal cannot change the agent's identity".into(),
        ));
    }
    if candidate.governance.suspend_keys != current.governance.suspend_keys {
        return Err(crate::Error::Provider(
            "a proposal cannot change who governs the agent (suspend_keys)".into(),
        ));
    }
    let yaml = candidate.to_yaml()?;
    std::fs::write(proposed_path(agent_dir), yaml)?;
    std::fs::write(
        agent_dir.join(PROPOSAL_META),
        serde_json::to_string_pretty(&meta)?,
    )?;
    Ok(())
}

pub fn read_proposal(agent_dir: &Path) -> Option<(String, ProposalMeta)> {
    let yaml = std::fs::read_to_string(proposed_path(agent_dir)).ok()?;
    let meta = std::fs::read_to_string(agent_dir.join(PROPOSAL_META))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(ProposalMeta {
            reason: String::new(),
            summary: "amendment".into(),
            at: String::new(),
            kind: "yaml".into(),
        });
    Some((yaml, meta))
}

pub fn clear_proposal(agent_dir: &Path) {
    let _ = std::fs::remove_file(proposed_path(agent_dir));
    let _ = std::fs::remove_file(agent_dir.join(PROPOSAL_META));
}

// ------------------------------------------------------------- the tools

/// `propose_routine` — structured; the safe common case.
pub struct ProposeRoutine {
    pub agent_dir: PathBuf,
    pub manifest: Manifest,
}

impl crate::connector::Connector for ProposeRoutine {
    fn def(&self) -> crate::connector::ToolDef {
        crate::connector::ToolDef {
            name: "propose_routine".into(),
            description:
                "Propose a new scheduled routine for yourself (a standing instruction the \
                          host would run on a schedule). This does NOT create it — it lands as a \
                          proposal your governor must accept and ratify. Use when a human asks for \
                          something recurring, or when you see a genuinely useful recurring task; \
                          say in `reason` why. One proposal at a time."
                    .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "short kebab-case name"},
                    "when": {"type": "string", "description": "5-field cron (Sunday=0), e.g. '0 8 * * 1-5'"},
                    "every": {"type": "string", "description": "interval instead of cron: 15m, 2h, 1d"},
                    "at": {"type": "string", "description": "one-shot: YYYY-MM-DDTHH:MM (in tz)"},
                    "tz": {"type": "string", "description": "IANA zone, e.g. America/Chicago (required with when/at)"},
                    "task": {"type": "string", "description": "the instruction to run each time"},
                    "deliver_telegram": {"type": "string", "description": "chat id to deliver the reply to (must be in your allowed_chats)"},
                    "deliver_companion": {"type": "boolean", "description": "speak the reply through the human's companion app"},
                    "as_voice": {"type": "boolean"},
                    "tokens_per_run": {"type": "integer"},
                    "reason": {"type": "string", "description": "why this routine is worth having — shown to the governor"}
                },
                "required": ["name", "task", "reason"]
            }),
        }
    }

    fn execute(
        &self,
        _custody: &apiary_core::custody::Custody,
        _agent: &apiary_core::custody::AgentHandle,
        args: &Value,
    ) -> Result<String, crate::Error> {
        let s = |k: &str| {
            args[k]
                .as_str()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let name = s("name").ok_or_else(|| crate::Error::Provider("name required".into()))?;
        let name: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        let task = s("task").ok_or_else(|| crate::Error::Provider("task required".into()))?;
        let reason = s("reason").unwrap_or_else(|| "proposed by the agent".into());
        let mut deliver = Vec::new();
        if let Some(chat) = s("deliver_telegram") {
            deliver.push(apiary_core::manifest::Delivery {
                telegram: Some(chat),
                buzz: None,
                nostr: None,
                companion: false,
                as_voice: args["as_voice"].as_bool().unwrap_or(false),
            });
        }
        if args["deliver_companion"].as_bool().unwrap_or(false) {
            deliver.push(apiary_core::manifest::Delivery {
                telegram: None,
                buzz: None,
                nostr: None,
                companion: true,
                as_voice: args["as_voice"].as_bool().unwrap_or(false),
            });
        }
        let routine = Routine {
            name: name.clone(),
            when: s("when"),
            every: s("every"),
            at: s("at"),
            tz: s("tz"),
            task: task.clone(),
            class: "routine".into(),
            deliver,
            budget: apiary_core::manifest::RoutineBudget {
                tokens_per_run: args["tokens_per_run"].as_u64(),
            },
            catch_up: "one".into(),
            enabled: true,
        };
        // Schedule must parse (cron syntax, tz) — fail here, not at fire time.
        crate::routines::parse_schedule(&routine)?;
        let mut candidate = self.manifest.clone();
        candidate.routines.retain(|r| r.name != name);
        candidate.routines.push(routine);
        let summary = format!(
            "add routine '{name}' ({}) — {}",
            s("when")
                .or_else(|| s("every").map(|e| format!("every {e}")))
                .or_else(|| s("at").map(|a| format!("once at {a}")))
                .unwrap_or_default(),
            task.chars().take(80).collect::<String>()
        );
        write_proposal(
            &self.agent_dir,
            &self.manifest,
            &candidate,
            ProposalMeta {
                reason,
                summary: summary.clone(),
                at: chrono::Utc::now().to_rfc3339(),
                kind: "routine".into(),
            },
        )?;
        Ok(format!(
            "proposal written: {summary}. It is NOT active — your governor sees it in the cockpit and \
             decides. Tell the human it is waiting for their ratification."
        ))
    }
}

// ---------------------------------------------------- founding requests

pub const FOUNDING_FILE: &str = "founding.proposed.yaml";

/// A request to found a NEW agent (SCOPE_hal-project-management). The
/// requesting agent describes the colleague it thinks should exist; the
/// governor approves (prefilled founding flow) or rejects. Founding stays
/// a human ceremony — this file is only ever a request.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FoundingRequest {
    pub name: String,
    pub purpose: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub role: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub principles: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub boundaries: Vec<String>,
    /// Skill names / one-line descriptions the new agent would need.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skills: Vec<String>,
    /// Capabilities it would need, by library name or kind — described,
    /// never granted here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub connectors: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens_per_day: Option<u64>,
    /// Why this agent should exist — shown to the governor.
    pub reason: String,
    pub at: String,
    /// npub of the requesting agent.
    pub by: String,
}

pub fn founding_path(agent_dir: &Path) -> PathBuf {
    agent_dir.join(FOUNDING_FILE)
}

pub fn write_founding_request(
    agent_dir: &Path,
    request: &FoundingRequest,
) -> Result<(), crate::Error> {
    if request.name.trim().is_empty()
        || request.purpose.trim().is_empty()
        || request.reason.trim().is_empty()
    {
        return Err(crate::Error::Provider(
            "a founding request needs name, purpose, and reason".into(),
        ));
    }
    let yaml = serde_yaml::to_string(request)
        .map_err(|e| crate::Error::Provider(format!("founding request encode: {e}")))?;
    std::fs::write(founding_path(agent_dir), yaml)?;
    Ok(())
}

pub fn read_founding_request(agent_dir: &Path) -> Option<FoundingRequest> {
    let yaml = std::fs::read_to_string(founding_path(agent_dir)).ok()?;
    serde_yaml::from_str(&yaml).ok()
}

pub fn clear_founding_request(agent_dir: &Path) {
    let _ = std::fs::remove_file(founding_path(agent_dir));
}

/// `propose_agent` — request the founding of a new agent.
pub struct ProposeAgent {
    pub agent_dir: PathBuf,
    pub npub: String,
}

impl crate::connector::Connector for ProposeAgent {
    fn def(&self) -> crate::connector::ToolDef {
        crate::connector::ToolDef {
            name: "propose_agent".into(),
            description:
                "Request that a NEW agent be founded for a purpose you cannot or should not \
                 cover yourself. This does NOT create anything: it lands as a founding request \
                 the governor approves or rejects in the cockpit — founding is always a human \
                 ceremony. Describe the colleague: purpose, skillset, capabilities it would \
                 need, spend ceiling. Say in `reason` why it should exist. After filing, tell \
                 the human in the channel where the need arose. One request at a time; filing \
                 again replaces your pending one."
                    .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "short working name, e.g. 'Docs gardener'"},
                    "purpose": {"type": "string", "description": "what it should reliably do"},
                    "role": {"type": "string", "description": "one-sentence constitution role sketch"},
                    "principles": {"type": "array", "items": {"type": "string"}},
                    "boundaries": {"type": "array", "items": {"type": "string"}},
                    "skills": {"type": "array", "items": {"type": "string"}, "description": "skills it would need, one line each"},
                    "connectors": {"type": "array", "items": {"type": "string"}, "description": "capabilities it would need (library names or kinds)"},
                    "tokens_per_day": {"type": "integer", "description": "proposed daily spend ceiling"},
                    "reason": {"type": "string", "description": "why this agent should exist — shown to the governor"}
                },
                "required": ["name", "purpose", "reason"]
            }),
        }
    }

    fn execute(
        &self,
        _custody: &apiary_core::custody::Custody,
        _agent: &apiary_core::custody::AgentHandle,
        args: &Value,
    ) -> Result<String, crate::Error> {
        let s = |k: &str| {
            args[k]
                .as_str()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let list = |k: &str| -> Vec<String> {
            args[k]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(|v| v.trim().to_string()))
                        .filter(|v| !v.is_empty())
                        .collect()
                })
                .unwrap_or_default()
        };
        let request = FoundingRequest {
            name: s("name").ok_or_else(|| crate::Error::Provider("name required".into()))?,
            purpose: s("purpose")
                .ok_or_else(|| crate::Error::Provider("purpose required".into()))?,
            role: s("role").unwrap_or_default(),
            principles: list("principles"),
            boundaries: list("boundaries"),
            skills: list("skills"),
            connectors: list("connectors"),
            tokens_per_day: args["tokens_per_day"].as_u64(),
            reason: s("reason").ok_or_else(|| crate::Error::Provider("reason required".into()))?,
            at: chrono::Utc::now().to_rfc3339(),
            by: self.npub.clone(),
        };
        let name = request.name.clone();
        write_founding_request(&self.agent_dir, &request)?;
        Ok(format!(
            "founding request for '{name}' written. Nothing was created — the governor sees it \
             in the cockpit and decides. Tell the human it is waiting for their review."
        ))
    }
}

#[cfg(test)]
mod founding_tests {
    use super::*;

    #[test]
    fn founding_request_round_trips_and_validates() {
        let dir = std::env::temp_dir().join(format!("apiary-founding-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(read_founding_request(&dir).is_none());
        let request = FoundingRequest {
            name: "Docs gardener".into(),
            purpose: "keep the docs pruned".into(),
            role: "tends documentation".into(),
            principles: vec!["small commits".into()],
            boundaries: vec![],
            skills: vec!["markdown hygiene".into()],
            connectors: vec!["markdown-vault".into()],
            tokens_per_day: Some(50_000),
            reason: "the humans keep forgetting".into(),
            at: "2026-08-22T00:00:00Z".into(),
            by: "npub1example".into(),
        };
        write_founding_request(&dir, &request).unwrap();
        let back = read_founding_request(&dir).expect("pending request reads back");
        assert_eq!(back.name, "Docs gardener");
        assert_eq!(back.tokens_per_day, Some(50_000));
        assert_eq!(back.boundaries, Vec::<String>::new());
        // Missing essentials are refused at write time.
        let mut invalid = request.clone();
        invalid.reason = "  ".into();
        assert!(write_founding_request(&dir, &invalid).is_err());
        clear_founding_request(&dir);
        assert!(read_founding_request(&dir).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// `propose_amendment` — the whole manifest as YAML; advanced.
pub struct ProposeAmendment {
    pub agent_dir: PathBuf,
    pub manifest: Manifest,
}

impl crate::connector::Connector for ProposeAmendment {
    fn def(&self) -> crate::connector::ToolDef {
        crate::connector::ToolDef {
            name: "propose_amendment".into(),
            description: "Propose an amendment to your own manifest (constitution) as complete YAML. \
                          Never enacted by you: it lands as a proposal the governor accepts and \
                          ratifies. Identity and suspend_keys cannot change. Prefer propose_routine \
                          for schedules. Explain the change in `reason`."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "yaml": {"type": "string", "description": "the full proposed manifest YAML"},
                    "reason": {"type": "string"}
                },
                "required": ["yaml", "reason"]
            }),
        }
    }

    fn execute(
        &self,
        _custody: &apiary_core::custody::Custody,
        _agent: &apiary_core::custody::AgentHandle,
        args: &Value,
    ) -> Result<String, crate::Error> {
        let yaml = args["yaml"]
            .as_str()
            .ok_or_else(|| crate::Error::Provider("yaml required".into()))?;
        let candidate = Manifest::from_yaml(yaml)?;
        let reason = args["reason"].as_str().unwrap_or("").to_string();
        write_proposal(
            &self.agent_dir,
            &self.manifest,
            &candidate,
            ProposalMeta {
                reason: reason.clone(),
                summary: "manifest amendment (yaml)".into(),
                at: chrono::Utc::now().to_rfc3339(),
                kind: "yaml".into(),
            },
        )?;
        Ok("proposal written — waiting for the governor to accept and ratify.".into())
    }
}
