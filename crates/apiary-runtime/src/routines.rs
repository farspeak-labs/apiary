//! Routines — scheduled, governed runs (SCOPE_routines). The schedule is
//! constitutional (manifest.routines); this module owns the CLOCK side:
//! parsing `when`/`every`/`at`, computing next fires in the routine's
//! zone, and the host-local bookkeeping in `routines.json` (last fired,
//! last outcome, paused) — which, like spend.json, does not travel.
//!
//! What fires and how (lease gate, overlap guard, delivery, log entries)
//! lives in the host supervisor; here is only "is it time, and for which
//! slot" — pure enough to test with a fake clock.

use chrono::{DateTime, Duration, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Minimum interval for `every` — anything faster is a job, not a routine.
pub const MIN_EVERY_SECS: i64 = 60;
/// Fire jitter ceiling (seconds): ten agents at "0 8 * * *" don't hit the
/// provider at once.
pub const JITTER_SECS: i64 = 20;

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)] // cron::Schedule is big; three variants, one instance per routine
pub enum Schedule {
    Cron {
        expr: cron::Schedule,
        tz: chrono_tz::Tz,
    },
    Every(Duration),
    At(DateTime<Utc>),
}

/// Parse a manifest routine's schedule. Errors are manifest errors — the
/// validation in core checks shape; this checks meaning (cron syntax,
/// zone name, duration grammar).
pub fn parse_schedule(r: &apiary_core::manifest::Routine) -> Result<Schedule, crate::Error> {
    if let Some(w) = &r.when {
        let tz = parse_tz(r)?;
        // Accept 5-field cron (min hour dom mon dow) and @aliases; the
        // `cron` crate wants 6/7 fields with seconds first.
        let expr = match w.trim() {
            "@hourly" => "0 0 * * * *".to_string(),
            "@daily" | "@midnight" => "0 0 0 * * *".to_string(),
            "@weekly" => "0 0 0 * * 1".to_string(),
            "@monthly" => "0 0 0 1 * *".to_string(),
            other => {
                let fields: Vec<&str> = other.split_whitespace().collect();
                match fields.len() {
                    5 => {
                        // Standard cron: dow 0-6 = Sun-Sat (7 = Sun). The
                        // `cron` crate: 1-7 = Sun-Sat. Translate numerics.
                        let dow = translate_dow(fields[4]);
                        format!(
                            "0 {} {} {} {} {}",
                            fields[0], fields[1], fields[2], fields[3], dow
                        )
                    }
                    6 | 7 => other.to_string(),
                    n => {
                        return Err(crate::Error::Provider(format!(
                            "routine '{}': cron needs 5 fields (min hour dom mon dow), got {n}",
                            r.name
                        )))
                    }
                }
            }
        };
        let sched = cron::Schedule::from_str(&expr).map_err(|e| {
            crate::Error::Provider(format!("routine '{}': bad cron '{w}': {e}", r.name))
        })?;
        return Ok(Schedule::Cron { expr: sched, tz });
    }
    if let Some(e) = &r.every {
        let secs = parse_duration_secs(e).ok_or_else(|| {
            crate::Error::Provider(format!(
                "routine '{}': every '{e}' — use 15m, 2h, 1d (min 1m)",
                r.name
            ))
        })?;
        if secs < MIN_EVERY_SECS {
            return Err(crate::Error::Provider(format!(
                "routine '{}': every must be at least 1m",
                r.name
            )));
        }
        return Ok(Schedule::Every(Duration::seconds(secs)));
    }
    if let Some(a) = &r.at {
        let tz = parse_tz(r)?;
        let naive = chrono::NaiveDateTime::parse_from_str(a.trim(), "%Y-%m-%dT%H:%M:%S")
            .or_else(|_| chrono::NaiveDateTime::parse_from_str(a.trim(), "%Y-%m-%dT%H:%M"))
            .map_err(|_| {
                crate::Error::Provider(format!(
                    "routine '{}': at must be YYYY-MM-DDTHH:MM[:SS] in tz",
                    r.name
                ))
            })?;
        let local = tz.from_local_datetime(&naive).single().ok_or_else(|| {
            crate::Error::Provider(format!(
                "routine '{}': at '{a}' is ambiguous or nonexistent in {}",
                r.name,
                r.tz.as_deref().unwrap_or("?")
            ))
        })?;
        return Ok(Schedule::At(local.with_timezone(&Utc)));
    }
    Err(crate::Error::Provider(format!(
        "routine '{}' has no schedule",
        r.name
    )))
}

/// Standard-cron day-of-week numbers → the `cron` crate's (Sun=1). Names
/// (MON, FRI) and `*` pass through; step values after `/` are untouched.
fn translate_dow(field: &str) -> String {
    field
        .split(',')
        .map(|part| {
            let (range, step) = match part.split_once('/') {
                Some((r, st)) => (r, Some(st)),
                None => (part, None),
            };
            let mapped: String = range
                .split('-')
                .map(|tok| match tok.trim().parse::<u32>() {
                    Ok(n) => ((n % 7) + 1).to_string(),
                    Err(_) => tok.to_string(),
                })
                .collect::<Vec<_>>()
                .join("-");
            match step {
                Some(st) => format!("{mapped}/{st}"),
                None => mapped,
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn parse_tz(r: &apiary_core::manifest::Routine) -> Result<chrono_tz::Tz, crate::Error> {
    let name =
        r.tz.as_deref()
            .ok_or_else(|| crate::Error::Provider(format!("routine '{}': tz required", r.name)))?;
    name.parse::<chrono_tz::Tz>().map_err(|_| {
        crate::Error::Provider(format!(
            "routine '{}': unknown tz '{name}' (use an IANA name like America/Chicago)",
            r.name
        ))
    })
}

/// "15m" | "2h" | "1d" | "90s" → seconds. Defined in the schema crate so
/// validation and scheduling can never disagree about what a duration is.
pub use apiary_core::manifest::parse_duration_secs;

impl Schedule {
    /// The next fire strictly after `after`. `anchor` is the reference for
    /// `every` (last fire, or "now" for a fresh routine). None = never
    /// again (a spent one-shot).
    pub fn next_after(
        &self,
        after: DateTime<Utc>,
        anchor: Option<DateTime<Utc>>,
    ) -> Option<DateTime<Utc>> {
        match self {
            Schedule::Cron { expr, tz } => {
                let local = after.with_timezone(tz);
                expr.after(&local).next().map(|d| d.with_timezone(&Utc))
            }
            Schedule::Every(d) => {
                let base = anchor.unwrap_or(after);
                let mut t = base + *d;
                while t <= after {
                    t += *d;
                }
                Some(t)
            }
            Schedule::At(t) => {
                if *t > after {
                    Some(*t)
                } else {
                    None
                }
            }
        }
    }

    /// Human-readable next N fires (cockpit preview).
    pub fn preview(&self, now: DateTime<Utc>, n: usize) -> Vec<DateTime<Utc>> {
        let mut out = Vec::new();
        let mut t = now;
        for _ in 0..n {
            match self.next_after(t, Some(t)) {
                Some(next) => {
                    out.push(next);
                    t = next;
                }
                None => break,
            }
        }
        out
    }
}

// ------------------------------------------------------------ host state

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoutineRecord {
    /// The slot that last fired (scheduled time), and when it actually ran.
    #[serde(default)]
    pub last_scheduled: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_fired: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_outcome: Option<String>,
    #[serde(default)]
    pub last_delivery: Option<serde_json::Value>,
    #[serde(default)]
    pub paused: bool,
    /// One-shots: spent after firing.
    #[serde(default)]
    pub spent: bool,
    #[serde(default)]
    pub fires: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoutinesState {
    #[serde(default)]
    pub routines: std::collections::BTreeMap<String, RoutineRecord>,
    /// When this host first evaluated schedules for the agent — catch_up
    /// never reaches back before it (an import does not replay history).
    #[serde(default)]
    pub since: Option<DateTime<Utc>>,
}

pub struct RoutinesFile(PathBuf);

impl RoutinesFile {
    pub fn open(agent_dir: &Path) -> Self {
        Self(agent_dir.join("routines.json"))
    }
    pub fn load(&self) -> RoutinesState {
        std::fs::read_to_string(&self.0)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }
    pub fn save(&self, st: &RoutinesState) -> Result<(), crate::Error> {
        std::fs::write(&self.0, serde_json::to_string_pretty(st)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }
}

/// Decide whether a routine is due at `now`. Returns the SLOT it is due
/// for (its scheduled time) — the caller records that slot so nothing
/// fires twice for it. Encodes catch_up: with `one`, a slot missed while
/// the host was away fires once on wake (never a backlog); with `none`,
/// only a slot whose time has come since the last evaluation fires.
pub fn due_slot(
    sched: &Schedule,
    r: &apiary_core::manifest::Routine,
    rec: &RoutineRecord,
    since: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    if !r.enabled || rec.paused || rec.spent {
        return None;
    }
    // The reference point: the last slot we handled, or when this host
    // began evaluating (import / first sight).
    let after = rec.last_scheduled.unwrap_or(since);
    let anchor = rec.last_fired.or(Some(since));
    let next = sched.next_after(after, anchor)?;
    if next > now {
        return None;
    }
    match r.catch_up.as_str() {
        // Missed slots collapse to the LATEST one ≤ now: fire once.
        "one" => {
            let mut slot = next;
            while let Some(later) = sched.next_after(slot, Some(slot)) {
                if later <= now {
                    slot = later;
                } else {
                    break;
                }
            }
            Some(slot)
        }
        // none: fire only if the due slot is recent (within one tick's
        // slack); older ones were missed and stay missed.
        _ => {
            let mut slot = next;
            while let Some(later) = sched.next_after(slot, Some(slot)) {
                if later <= now {
                    slot = later;
                } else {
                    break;
                }
            }
            if now - slot <= Duration::seconds(90) {
                Some(slot)
            } else {
                None
            }
        }
    }
}

/// Deterministic per-(routine, slot) jitter in [0, JITTER_SECS].
pub fn jitter_secs(name: &str, slot: DateTime<Utc>) -> i64 {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(format!("{name}|{}", slot.timestamp()).as_bytes());
    (u64::from_le_bytes(h[..8].try_into().unwrap()) % (JITTER_SECS as u64 + 1)) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use apiary_core::manifest::Routine;

    fn routine(when: Option<&str>, every: Option<&str>, at: Option<&str>) -> Routine {
        let yaml = format!(
            "name: t\ntask: hi\n{}{}{}{}",
            when.map(|w| format!("when: \"{w}\"\n")).unwrap_or_default(),
            every.map(|e| format!("every: {e}\n")).unwrap_or_default(),
            at.map(|a| format!("at: \"{a}\"\n")).unwrap_or_default(),
            if every.is_some() {
                ""
            } else {
                "tz: America/Chicago\n"
            },
        );
        // Routine is plain serde; parse via JSON to avoid a yaml dep here.
        let v: serde_json::Value = serde_json::from_str(&yaml_to_json(&yaml)).unwrap();
        serde_json::from_value(v).unwrap()
    }

    /// Tiny flat-YAML → JSON for the test fixtures above (key: value lines).
    fn yaml_to_json(y: &str) -> String {
        let mut parts = Vec::new();
        for line in y.lines() {
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            let v = v.trim().trim_matches('"');
            parts.push(format!("\"{}\":\"{}\"", k.trim(), v));
        }
        format!("{{{}}}", parts.join(","))
    }

    fn utc(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn cron_fires_in_its_zone() {
        // 08:00 Chicago (CDT, -5) = 13:00Z.
        let s = parse_schedule(&routine(Some("0 8 * * 1-5"), None, None)).unwrap();
        let next = s.next_after(utc("2026-08-17T10:00:00Z"), None).unwrap(); // Monday
        assert_eq!(next, utc("2026-08-17T13:00:00Z"));
        // Saturday morning → next is Monday.
        let next = s.next_after(utc("2026-08-22T20:00:00Z"), None).unwrap();
        assert_eq!(next, utc("2026-08-24T13:00:00Z"));
    }

    #[test]
    fn every_and_at_and_limits() {
        let s = parse_schedule(&routine(None, Some("30m"), None)).unwrap();
        let t0 = utc("2026-08-17T10:00:00Z");
        assert_eq!(
            s.next_after(t0, Some(t0)).unwrap(),
            utc("2026-08-17T10:30:00Z")
        );
        assert!(
            parse_schedule(&routine(None, Some("30s"), None)).is_err(),
            "sub-minute refused"
        );
        let s = parse_schedule(&routine(None, None, Some("2026-08-17T15:00"))).unwrap();
        assert_eq!(s.next_after(t0, None).unwrap(), utc("2026-08-17T20:00:00Z")); // 15:00 CDT
        assert!(
            s.next_after(utc("2026-08-17T21:00:00Z"), None).is_none(),
            "one-shot spent"
        );
        assert!(parse_schedule(&routine(Some("bogus cron"), None, None)).is_err());
    }

    #[test]
    fn catch_up_one_collapses_a_backlog_to_one_fire() {
        let r = routine(None, Some("1h"), None);
        let s = parse_schedule(&r).unwrap();
        let since = utc("2026-08-17T00:00:00Z");
        let mut rec = RoutineRecord::default();
        // Host was away for 5 hours: due once, for the LATEST slot.
        let now = utc("2026-08-17T05:10:00Z");
        let slot = due_slot(&s, &r, &rec, since, now).unwrap();
        assert_eq!(slot, utc("2026-08-17T05:00:00Z"));
        rec.last_scheduled = Some(slot);
        rec.last_fired = Some(now);
        // Same tick again: not due.
        assert!(due_slot(&s, &r, &rec, since, now).is_none());
        // catch_up none: an old missed slot stays missed.
        let mut r2 = r.clone();
        r2.catch_up = "none".into();
        let rec2 = RoutineRecord::default();
        assert!(due_slot(&s, &r2, &rec2, since, now).is_none());
        // …but a slot that just arrived fires.
        assert!(due_slot(&s, &r2, &rec2, since, utc("2026-08-17T01:00:30Z")).is_some());
    }

    #[test]
    fn standard_dow_numbers_translate() {
        assert_eq!(translate_dow("1-5"), "2-6");
        assert_eq!(translate_dow("0"), "1");
        assert_eq!(translate_dow("7"), "1");
        assert_eq!(translate_dow("MON-FRI"), "MON-FRI");
        assert_eq!(translate_dow("*"), "*");
        assert_eq!(translate_dow("1,3,5"), "2,4,6");
    }

    #[test]
    fn jitter_is_bounded_and_stable() {
        let t = utc("2026-08-17T13:00:00Z");
        let j = jitter_secs("morning-brief", t);
        assert!((0..=JITTER_SECS).contains(&j));
        assert_eq!(j, jitter_secs("morning-brief", t));
    }
}
