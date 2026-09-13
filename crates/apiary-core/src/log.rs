//! The signed episodic log — SPEC §9 store 1, the agent's track record.
//!
//! Every entry is a signed nostr event: attributable, tamper-evident (each
//! entry chains to the previous via a "prev" tag), and portable. The log is
//! both proof for others and the agent's mirror (SPEC §7: self-knowledge is
//! empirical, not introspective) — so entries record enough to learn from:
//! action, acting model, cost, outcome, corrections.
//!
//! Privacy tiers (SPEC §12.3): `public` (governance events others must
//! verify), `self` (operational log, NIP-44-encrypted-to-self when published
//! to a relay), `local` (never leaves the host). Phase 1 storage is a local
//! JSONL file, so tiers are recorded but all entries stay local; relay
//! publication honors them in Phase 3.

use nostr::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use crate::custody::{AgentHandle, Custody};

/// Custom event kind for Apiary log entries (parameterized-replaceable range
/// deliberately avoided — log entries are permanent facts).
pub const LOG_ENTRY_KIND: u16 = 4600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Plain signed event — what governance requires others to verify.
    Public,
    /// Encrypted-to-self when published; readable only by the agent.
    Self_,
    /// Never leaves the host.
    Local,
}

impl Tier {
    fn as_str(&self) -> &'static str {
        match self {
            Tier::Public => "public",
            Tier::Self_ => "self",
            Tier::Local => "local",
        }
    }
}

/// The body of a log entry — serialized as the event content.
/// Record outcomes, costs, corrections, and the acting model from day one:
/// the mirror only works if the log is honest and complete (SPEC §7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryBody {
    /// What happened: "founding.manifest", "founding.ratify", "run.task", …
    pub action: String,
    /// Which brain acted, when inference was involved ("the agent, thinking
    /// with model M, did X").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Token costs of this action, when inference was involved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost: Option<Cost>,
    /// "ok", "refusal", "error: …", "budget-refused", …
    pub outcome: String,
    /// Which loop ran the action: "native", "acp:<command>", … The harness
    /// is rented machinery like the model — attribution needs both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    /// Free-form detail (task text, result summary, manifest hash, …).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

impl EntryBody {
    /// The canonical text a log entry contributes to the semantic index.
    /// ONE derivation, owned by core: the runtime indexes with it and
    /// portability verifies imported index rows against it — an unsigned
    /// index row that disagrees with the signed log is dropped.
    pub fn index_text(&self) -> String {
        let task = self
            .detail
            .as_ref()
            .and_then(|d| d.get("task"))
            .and_then(|t| t.as_str())
            .unwrap_or("");
        format!("{} {} {}", self.action, self.outcome, task)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Cost {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// Append-only, file-backed signed log. One per agent.
pub struct EpisodicLog {
    path: PathBuf,
}

/// Rebuildable operational metadata for the append-only log. It is never
/// consulted for signature or chain verification; it exists so UI/status
/// reads do not rescan years of history just to display a count.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LogProjection {
    version: u8,
    byte_len: u64,
    entry_count: usize,
    tip: Option<String>,
}

const LOG_PROJECTION_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSummary {
    pub byte_len: u64,
    pub entry_count: usize,
    pub tip: Option<String>,
}

impl EpisodicLog {
    pub fn open(agent_dir: &std::path::Path) -> Self {
        Self {
            path: agent_dir.join("log.jsonl"),
        }
    }

    fn projection_path(&self) -> PathBuf {
        self.path.with_file_name("log.meta.json")
    }

    fn write_projection(&self, projection: &LogProjection) -> Result<(), crate::Error> {
        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(self.projection_path())?;
        serde_json::to_writer(&mut file, projection)?;
        file.write_all(b"\n")?;
        file.flush()?;
        Ok(())
    }

    /// Load the tiny projection when it matches the append-only file length;
    /// otherwise rebuild it once. A torn or deleted projection only costs one
    /// scan and can never change the signed log's authority.
    fn projection_locked(&self) -> Result<LogProjection, crate::Error> {
        let byte_len = self.path.metadata().map(|m| m.len()).unwrap_or(0);
        if let Ok(raw) = fs::read_to_string(self.projection_path()) {
            if let Ok(projection) = serde_json::from_str::<LogProjection>(&raw) {
                if projection.version == LOG_PROJECTION_VERSION && projection.byte_len == byte_len {
                    return Ok(projection);
                }
            }
        }

        let mut entry_count = 0;
        let mut last_line = None;
        if self.path.exists() {
            for line in BufReader::new(fs::File::open(&self.path)?).lines() {
                let line = line?;
                if !line.trim().is_empty() {
                    entry_count += 1;
                    last_line = Some(line);
                }
            }
        }
        let tip = last_line
            .map(|line| {
                Event::from_json(&line)
                    .map(|event| event.id.to_hex())
                    .map_err(|e| crate::Error::Manifest(format!("corrupt log tail: {e}")))
            })
            .transpose()?;
        let projection = LogProjection {
            version: LOG_PROJECTION_VERSION,
            byte_len,
            entry_count,
            tip,
        };
        self.write_projection(&projection)?;
        Ok(projection)
    }

    /// Append an entry: signed by the agent (or, for ratification, by the
    /// human's handle), chained to the previous entry's event id.
    pub fn append(
        &self,
        custody: &Custody,
        signer: &AgentHandle,
        tier: Tier,
        body: &EntryBody,
    ) -> Result<Event, crate::Error> {
        self.append_with_tags(custody, signer, tier, body, Vec::new())
    }

    /// Append with extra tags (e.g. a `p` tag making ratifications
    /// discoverable by the agent they govern).
    pub fn append_with_tags(
        &self,
        custody: &Custody,
        signer: &AgentHandle,
        tier: Tier,
        body: &EntryBody,
        extra_tags: Vec<Tag>,
    ) -> Result<Event, crate::Error> {
        // The chain invariant (every entry references the previous) demands
        // that tail-read → sign → append be one critical section: two
        // presence channels appending concurrently would otherwise fork
        // the chain forever. Process-safe flock, same discipline as the
        // spend ledger.
        let lock_path = self.path.with_extension("lock");
        let mut lock_opts = OpenOptions::new();
        lock_opts.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            lock_opts.mode(0o600);
        }
        let lock = lock_opts.open(&lock_path)?;
        fs2::FileExt::lock_exclusive(&lock)
            .map_err(|e| crate::Error::Log(format!("log lock: {e}")))?;
        let result = self.append_locked(custody, signer, tier, body, extra_tags);
        let _ = fs2::FileExt::unlock(&lock);
        result
    }

    fn append_locked(
        &self,
        custody: &Custody,
        signer: &AgentHandle,
        tier: Tier,
        body: &EntryBody,
        extra_tags: Vec<Tag>,
    ) -> Result<Event, crate::Error> {
        let projection = self.projection_locked()?;
        // The chain only needs the current tip. Reading the complete history
        // here made every append O(history): a busy agent became slower for
        // no governance benefit. Tail reading is bounded from the end.
        let prev = self.tail(1)?.pop();
        let content = serde_json::to_string(body)?;
        let mut builder = EventBuilder::new(Kind::Custom(LOG_ENTRY_KIND), content)
            .tag(Tag::custom("tier", vec![tier.as_str().to_string()]))
            .tag(Tag::custom("action", vec![body.action.clone()]));
        if let Some(prev_event) = &prev {
            builder = builder.tag(Tag::custom("prev", vec![prev_event.id.to_hex()]));
        }
        for t in extra_tags {
            builder = builder.tag(t);
        }
        let event = custody.sign(signer, builder)?;
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600); // self-tier records are private to the user
        }
        let mut file = opts.open(&self.path)?;
        writeln!(file, "{}", event.as_json())?;
        file.flush()?;
        self.write_projection(&LogProjection {
            version: LOG_PROJECTION_VERSION,
            byte_len: file.metadata()?.len(),
            entry_count: projection.entry_count + 1,
            tip: Some(event.id.to_hex()),
        })?;
        Ok(event)
    }

    /// Append an event signed elsewhere (external ratification). Foreign
    /// events carry no "prev" tag — they were signed without knowledge of
    /// this log's tip — so they act as chain ANCHORS: the chain restarts
    /// from them. Trade-off, stated plainly: deletion of entries immediately
    /// before an anchor is not tamper-evident. Anchors are rare (external
    /// ratifications), every entry is still individually signed, and the
    /// relay-published log (Phase 3) closes the gap.
    pub fn append_foreign(&self, event: &Event) -> Result<(), crate::Error> {
        event
            .verify()
            .map_err(|e| crate::Error::Manifest(format!("foreign event: bad signature: {e}")))?;
        let lock_path = self.path.with_extension("lock");
        let mut lock_options = OpenOptions::new();
        lock_options.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            lock_options.mode(0o600);
        }
        let lock = lock_options.open(lock_path)?;
        fs2::FileExt::lock_exclusive(&lock)
            .map_err(|e| crate::Error::Log(format!("log lock: {e}")))?;
        let projection = self.projection_locked()?;
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&self.path)?;
        let result = (|| -> Result<(), crate::Error> {
            writeln!(file, "{}", event.as_json())?;
            file.flush()?;
            self.write_projection(&LogProjection {
                version: LOG_PROJECTION_VERSION,
                byte_len: file.metadata()?.len(),
                entry_count: projection.entry_count + 1,
                tip: Some(event.id.to_hex()),
            })?;
            Ok(())
        })();
        let _ = fs2::FileExt::unlock(&lock);
        result
    }

    /// Read all entries in order.
    pub fn read_all(&self) -> Result<Vec<Event>, crate::Error> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let reader = BufReader::new(fs::File::open(&self.path)?);
        let mut events = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let event = Event::from_json(&line)
                .map_err(|e| crate::Error::Manifest(format!("corrupt log line: {e}")))?;
            events.push(event);
        }
        Ok(events)
    }

    /// Number of stored records without parsing or verifying them. Counts are
    /// operational UI metadata; admission continues to use signed events.
    pub fn derived_summary(&self) -> Result<LogSummary, crate::Error> {
        let lock_path = self.path.with_extension("lock");
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(lock_path)?;
        fs2::FileExt::lock_exclusive(&lock)
            .map_err(|e| crate::Error::Log(format!("log lock: {e}")))?;
        let result = self.projection_locked().map(|projection| LogSummary {
            byte_len: projection.byte_len,
            entry_count: projection.entry_count,
            tip: projection.tip,
        });
        let _ = fs2::FileExt::unlock(&lock);
        result
    }

    pub fn entry_count(&self) -> Result<usize, crate::Error> {
        self.derived_summary().map(|summary| summary.entry_count)
    }

    fn tail_lines(&self, n: usize) -> Result<Vec<String>, crate::Error> {
        if n == 0 || !self.path.exists() {
            return Ok(Vec::new());
        }
        let mut file = fs::File::open(&self.path)?;
        let mut cursor = file.seek(SeekFrom::End(0))?;
        let mut bytes = Vec::new();
        const CHUNK: u64 = 8 * 1024;
        while cursor > 0 {
            let take = cursor.min(CHUNK);
            cursor -= take;
            file.seek(SeekFrom::Start(cursor))?;
            let mut chunk = vec![0; take as usize];
            file.read_exact(&mut chunk)?;
            chunk.extend(bytes);
            bytes = chunk;
            // JSON events are one line. One extra newline is needed because
            // the file normally ends in a newline itself.
            if bytes.iter().filter(|&&byte| byte == b'\n').count() > n {
                break;
            }
        }
        // Reading backwards stops at an arbitrary byte offset, and an
        // offset is not a character boundary — one em dash straddling it
        // made the whole tail "not UTF-8" and took an agent's errand down
        // with it. When we did not reach the start of the file the first
        // line is a fragment that gets dropped anyway, so drop it while it
        // is still bytes, before anything has to decode.
        if cursor > 0 {
            if let Some(newline) = bytes.iter().position(|&byte| byte == b'\n') {
                bytes.drain(..=newline);
            }
        }
        let text = String::from_utf8(bytes)
            .map_err(|e| crate::Error::Manifest(format!("log is not UTF-8: {e}")))?;
        let mut lines = text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(String::from)
            .collect::<Vec<_>>();
        if lines.len() > n {
            lines.drain(..lines.len() - n);
        }
        Ok(lines)
    }

    /// Last `n` entries, oldest first.
    pub fn tail(&self, n: usize) -> Result<Vec<Event>, crate::Error> {
        self.tail_lines(n)?
            .into_iter()
            .map(|line| {
                Event::from_json(&line)
                    .map_err(|e| crate::Error::Manifest(format!("corrupt log line: {e}")))
            })
            .collect()
    }

    /// Verify every entry's signature and the prev-chain. Returns entry count.
    pub fn verify(&self) -> Result<usize, crate::Error> {
        let events = self.read_all()?;
        let mut prev_id: Option<String> = None;
        for (i, event) in events.iter().enumerate() {
            event
                .verify()
                .map_err(|e| crate::Error::Manifest(format!("entry {i}: bad signature: {e}")))?;
            let claimed_prev = event.tags.iter().find_map(|t| {
                let s = t.as_slice();
                (s.first().map(String::as_str) == Some("prev")).then(|| s.get(1).cloned())?
            });
            match (&prev_id, &claimed_prev) {
                (None, None) => {}
                (Some(expect), Some(got)) if expect == got => {}
                // No prev tag mid-log = a foreign-signed anchor (external
                // ratification): chain restarts here. See append_foreign.
                (Some(_), None) => {}
                _ => {
                    return Err(crate::Error::Manifest(format!(
                        "entry {i}: prev-chain broken (expected {prev_id:?}, got {claimed_prev:?})"
                    )))
                }
            }
            prev_id = Some(event.id.to_hex());
        }
        Ok(events.len())
    }

    pub fn parse_body(event: &Event) -> Result<EntryBody, crate::Error> {
        Ok(serde_json::from_str(&event.content)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custody::Custody;

    fn temp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("apiary-log-{}-{}", name, std::process::id()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// A log full of em dashes — which every Apiary agent writes, because
    /// the prose it is given is full of them — became unreadable the moment
    /// it outgrew one 8 KiB backwards read and the read boundary landed
    /// inside a character. The failure surfaced on the errand, not the log:
    /// "manifest: log is not UTF-8: invalid utf-8 sequence of 1 bytes from
    /// index 0", with the file itself perfectly valid.
    #[test]
    fn a_multibyte_character_across_the_read_boundary_is_not_a_corrupt_log() {
        let dir = temp_dir("utf8-boundary");
        let path = dir.join("log.jsonl");
        let line = |i: usize, pad: usize| {
            format!(
                "{{\"n\":{i},\"note\":\"{}— an em dash — and more —\"}}\n",
                "x".repeat(pad)
            )
        };
        // Grow the file until the byte the tail read starts on is a UTF-8
        // CONTINUATION byte: that is the defect, and a fixture that merely
        // contains multibyte characters does not reproduce it.
        let mut text = String::new();
        let mut pad = 0;
        loop {
            text.clear();
            for i in 0..400 {
                text.push_str(&line(i, (i + pad) % 7));
            }
            let boundary = text.len() - 8 * 1024;
            let byte = text.as_bytes()[boundary];
            if (0x80..0xC0).contains(&byte) {
                break;
            }
            pad += 1;
            assert!(
                pad < 64,
                "could not position a character across the boundary"
            );
        }
        fs::write(&path, &text).unwrap();

        let log = EpisodicLog::open(&dir);
        let lines = log.tail_lines(5).expect("tail must read a valid log");
        assert_eq!(lines.len(), 5);
        assert!(
            lines.last().unwrap().contains("\"n\":399"),
            "{:?}",
            lines.last()
        );
        for line in &lines {
            serde_json::from_str::<serde_json::Value>(line).expect("each tail line is whole JSON");
        }
        fs::remove_dir_all(&dir).ok();
    }

    fn body(action: &str) -> EntryBody {
        EntryBody {
            action: action.into(),
            model: None,
            cost: None,
            harness: None,
            outcome: "ok".into(),
            detail: None,
        }
    }

    #[test]
    fn append_chain_verify() {
        let dir = temp_dir("chain");
        let mut custody = Custody::new();
        let h = custody.admit(Keys::generate());
        let log = EpisodicLog::open(&dir);
        log.append(&custody, &h, Tier::Public, &body("founding.manifest"))
            .unwrap();
        log.append(&custody, &h, Tier::Self_, &body("run.task"))
            .unwrap();
        log.append(&custody, &h, Tier::Local, &body("run.task"))
            .unwrap();
        assert_eq!(log.verify().unwrap(), 3);
        assert_eq!(log.entry_count().unwrap(), 3);
        let tail = log.tail(2).unwrap();
        assert_eq!(tail.len(), 2);
        assert!(tail
            .iter()
            .all(|event| { EpisodicLog::parse_body(event).unwrap().action == "run.task" }));
        let projection = dir.join("log.meta.json");
        assert!(projection.is_file());
        fs::write(&projection, "not valid json").unwrap();
        assert_eq!(log.entry_count().unwrap(), 3);
        let rebuilt: LogProjection =
            serde_json::from_str(&fs::read_to_string(projection).unwrap()).unwrap();
        assert_eq!(rebuilt.entry_count, 3);
        assert_eq!(rebuilt.tip, tail.last().map(|event| event.id.to_hex()));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tampering_detected() {
        let dir = temp_dir("tamper");
        let mut custody = Custody::new();
        let h = custody.admit(Keys::generate());
        let log = EpisodicLog::open(&dir);
        log.append(&custody, &h, Tier::Self_, &body("a")).unwrap();
        log.append(&custody, &h, Tier::Self_, &body("b")).unwrap();
        // Remove the first line — the chain must break.
        let path = dir.join("log.jsonl");
        let contents = fs::read_to_string(&path).unwrap();
        let second_line_only: String =
            contents.lines().skip(1).collect::<Vec<_>>().join("\n") + "\n";
        fs::write(&path, second_line_only).unwrap();
        assert!(log.verify().is_err());
        fs::remove_dir_all(&dir).ok();
    }
}
