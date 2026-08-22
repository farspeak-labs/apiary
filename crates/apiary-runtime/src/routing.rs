//! Routing — SPEC §7. The host routes, not the models: declarative policy
//! decided before inference. Merge order: floors → rules → default, and
//! floors clamp — a floor match is final and no rule can loosen it.
//!
//! Phase 1 conditions are the simple equality form the founding manifest
//! uses: `task.class == "reasoning"` and `data.class == "sensitive"`.

use apiary_core::manifest::{Manifest, RoutingRule};

#[derive(Debug, Clone, Default)]
pub struct TaskContext {
    /// What the task carries besides text (platform photos, voice notes).
    /// The runner shows images to vision providers; audio is transcribed
    /// first (transcribe slot) and never reaches a text provider as audio.
    pub attachments: Vec<crate::presence::Attachment>,
    /// e.g. "reasoning", "chat", "classification"
    pub task_class: Option<String>,
    /// e.g. "sensitive"
    pub data_class: Option<String>,
    /// Per-run ceiling within the day's cap (routines set this); None =
    /// the ledger's default reservation.
    pub tokens_per_run: Option<u64>,
    /// A low-latency caller may explicitly request inference without the
    /// agent's connector catalog. Capabilities remain ratified; they are
    /// simply not offered to this run.
    pub disable_tools: bool,
    /// Host-selected slot for a connection diagnostic. Ordinary callers do
    /// not populate this; the target must still exist in the ratified pool.
    pub route_override: Option<String>,
    /// Skip memory, skill selection, transcription, and connector binding for
    /// a low-cost connection diagnostic.
    pub lightweight: bool,
    /// Test exactly one route rather than masking it with failover.
    pub disable_fallback: bool,
    /// Which allowance this run spends. Proactive runs (watches, standing
    /// intentions) draw on the proactive sub-lane; everything a person or
    /// a ratified schedule asked for stays responsive.
    pub lane: crate::spend::Lane,
}

fn rule_matches(rule: &RoutingRule, ctx: &TaskContext) -> bool {
    // Parse `lhs == "value"` — anything unparseable never matches (fail
    // closed rather than misroute).
    let mut parts = rule.when.splitn(2, "==");
    let (Some(lhs), Some(rhs)) = (parts.next(), parts.next()) else {
        return false;
    };
    let lhs = lhs.trim();
    let rhs = rhs.trim().trim_matches('"');
    match lhs {
        "task.class" => ctx.task_class.as_deref() == Some(rhs),
        "data.class" => ctx.data_class.as_deref() == Some(rhs),
        _ => false,
    }
}

/// Resolve the inference slot name for a task. Floors are checked first and
/// are final; rules follow; then the default; then, as a last resort, the
/// sole slot if exactly one exists.
pub fn resolve(manifest: &Manifest, ctx: &TaskContext) -> Result<String, crate::Error> {
    if let Some(slot) = &ctx.route_override {
        return manifest
            .inference
            .iter()
            .any(|candidate| candidate.name == *slot)
            .then(|| slot.clone())
            .ok_or_else(|| crate::Error::Routing(format!("slot '{slot}' not in pool")));
    }
    for floor in &manifest.routing.floors {
        if rule_matches(floor, ctx) {
            return Ok(floor.to.clone());
        }
    }
    for rule in &manifest.routing.rules {
        if rule_matches(rule, ctx) {
            return Ok(rule.to.clone());
        }
    }
    if let Some(default) = &manifest.routing.default {
        return Ok(default.clone());
    }
    if manifest.inference.len() == 1 {
        return Ok(manifest.inference[0].name.clone());
    }
    Err(crate::Error::Routing(
        "no routing rule matched and no default is set".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use apiary_core::manifest::Manifest;

    fn manifest() -> Manifest {
        Manifest::from_yaml(
            r#"
manifest_version: 1
identity:
  npub: npub1w6pf5k9unn54c9lx7nh9uvc2z3255l48ptf4494zjytp28qkg7xqvhfmgs
inference:
  - name: workhorse
    provider: mock
    model: claude-opus-5
  - name: fast
    provider: mock
    model: claude-haiku-4-5
  - name: local
    provider: mock
    model: llama3
routing:
  floors:
    - when: data.class == "sensitive"
      to: local
  rules:
    - when: task.class == "reasoning"
      to: workhorse
  default: fast
connectors: []
memory:
  log: local
governance:
  suspend_keys:
    - npub1m8mfxnr32mlkylq9s0cj5l6vheatdu39kaze26e65ptzfr8vudgse6kgv3
"#,
        )
        .unwrap()
    }

    #[test]
    fn floor_clamps_over_rule() {
        // Sensitive + reasoning: the floor wins even though a rule matches.
        let slot = resolve(
            &manifest(),
            &TaskContext {
                task_class: Some("reasoning".into()),
                data_class: Some("sensitive".into()),
                attachments: Vec::new(),
                tokens_per_run: None,
                disable_tools: false,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(slot, "local");
    }

    #[test]
    fn rule_then_default() {
        let m = manifest();
        assert_eq!(
            resolve(
                &m,
                &TaskContext {
                    task_class: Some("reasoning".into()),
                    data_class: None,
                    attachments: Vec::new(),
                    tokens_per_run: None,
                    disable_tools: false,
                    ..Default::default()
                }
            )
            .unwrap(),
            "workhorse"
        );
        assert_eq!(resolve(&m, &TaskContext::default()).unwrap(), "fast");
    }
}
