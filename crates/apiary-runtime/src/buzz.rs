//! Buzz membership — SPEC §3: "Buzz interop is structural, not a feature."
//!
//! Buzz IS a nostr relay, so an Apiary agent authenticates with the same
//! key that signs its log: NIP-42 challenge → signed kind-22242 response on
//! the same connection. Messages are Buzz's stream-message vocabulary:
//! kind 9 with an `["h", <channel-uuid>]` tag (see block/buzz
//! crates/buzz-sdk/src/builders.rs — the authoritative wire shape).
//!
//! NIP-42 auth is per-connection, so this is a session, not one-shot calls:
//! the socket that authenticated is the socket that posts and reads.

use apiary_core::custody::{AgentHandle, Custody};
use nostr::prelude::*;
use serde_json::{json, Value};
use std::net::TcpStream;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};

/// Re-read a short tail after a socket reconnect or a manifest-triggered
/// channel bounce. Nostr `since` is inclusive, so the durable recent-id set
/// below suppresses anything already handed to the presence engine.
const REPLAY_OVERLAP_SECS: u64 = 120;
const RECENT_EVENT_LIMIT: usize = 256;

fn subscription_since(now: u64) -> u64 {
    now.saturating_sub(REPLAY_OVERLAP_SECS)
}

/// How long a subscription may go completely silent before the listener
/// stops trusting it. Long enough that a genuinely quiet channel is not
/// churned, short enough that a lapse costs minutes rather than a day.
const RESUBSCRIBE_AFTER_SILENCE: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// How often to look for channels created since the listener connected.
/// Short enough that opening a DM with an agent feels immediate.
const CHANNEL_REFRESH: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Default)]
struct RecentEventIds {
    ids: std::collections::VecDeque<String>,
}

impl RecentEventIds {
    fn load(path: Option<&std::path::Path>) -> Self {
        let Some(path) = path else {
            return Self::default();
        };
        let Ok(bytes) = std::fs::read(path) else {
            return Self::default();
        };
        let Ok(ids) = serde_json::from_slice::<Vec<String>>(&bytes) else {
            return Self::default();
        };
        Self {
            ids: ids
                .into_iter()
                .rev()
                .take(RECENT_EVENT_LIMIT)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect(),
        }
    }

    fn contains(&self, id: &str) -> bool {
        self.ids.iter().any(|seen| seen == id)
    }

    fn remember(&mut self, id: String, path: Option<&std::path::Path>) {
        if self.contains(&id) {
            return;
        }
        self.ids.push_back(id);
        while self.ids.len() > RECENT_EVENT_LIMIT {
            self.ids.pop_front();
        }
        let Some(path) = path else { return };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(bytes) = serde_json::to_vec(&self.ids) {
            // This cursor is a disposable local optimization, not governed
            // agent state. A failed write only means a possible replay.
            let _ = std::fs::write(path, bytes);
        }
    }
}

/// Buzz stream message kind (NIP-29-style group chat).
pub const KIND_STREAM_MESSAGE: u16 = 9;
/// NIP-42 client auth kind.
/// Buzz's "someone is composing" event. Clients expire it after ~8s, so it
/// is a heartbeat rather than a state to set and clear.
pub const KIND_TYPING_INDICATOR: u16 = 20002;

pub const KIND_AUTH: u16 = 22242;
/// NIP-29 group/channel metadata kind (channel discovery).
pub const KIND_GROUP_METADATA: u16 = 39000;

/// NIP-29 channel join request kind.
pub const KIND_JOIN_REQUEST: u16 = 9021;

pub struct BuzzSession<'a> {
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
    url: String,
    custody: &'a Custody,
    agent: &'a AgentHandle,
    authed: bool,
    /// Live-subscription events that arrived while another call (publish,
    /// auth) was waiting for its own reply — drained by `next_mention` so
    /// mentions received mid-reply are not lost.
    pending: Vec<Value>,
    /// When the relay last showed signs of life. A subscription can lapse
    /// while the socket stays open; without this the listener goes deaf and
    /// nothing looks wrong.
    last_traffic: std::time::Instant,
    /// Set once the live mention subscription is active.
    listening: bool,
}

impl<'a> BuzzSession<'a> {
    pub fn connect(
        url: &str,
        custody: &'a Custody,
        agent: &'a AgentHandle,
    ) -> Result<Self, crate::Error> {
        let (socket, _) = tungstenite::connect(url)
            .map_err(|e| crate::Error::Provider(format!("connect {url}: {e}")))?;
        Ok(Self {
            socket,
            url: url.to_string(),
            custody,
            agent,
            authed: false,
            pending: Vec::new(),
            last_traffic: std::time::Instant::now(),
            listening: false,
        })
    }

    fn send(&mut self, frame: Value) -> Result<(), crate::Error> {
        self.socket
            .send(Message::Text(frame.to_string().into()))
            .map_err(|e| crate::Error::Provider(format!("send: {e}")))
    }

    /// Arm keepalive for a long-lived session: a read timeout so a dead
    /// socket is detected (next_mention pings on quiet timeouts) instead of
    /// blocking forever on a connection the relay silently dropped.
    pub fn enable_keepalive(&mut self, timeout: std::time::Duration) {
        let stream = match self.socket.get_ref() {
            MaybeTlsStream::Plain(s) => Some(s),
            MaybeTlsStream::Rustls(t) => Some(&t.sock),
            _ => None,
        };
        if let Some(s) = stream {
            let _ = s.set_read_timeout(Some(timeout));
        }
    }

    fn recv(&mut self) -> Result<Value, crate::Error> {
        loop {
            let msg = self.socket.read().map_err(|e| {
                let timed_out = matches!(
                    &e,
                    tungstenite::Error::Io(io)
                        if io.kind() == std::io::ErrorKind::WouldBlock
                            || io.kind() == std::io::ErrorKind::TimedOut
                );
                if timed_out {
                    crate::Error::Provider("recv-timeout".into())
                } else {
                    crate::Error::Provider(format!("read: {e}"))
                }
            })?;
            match msg {
                Message::Text(text) => return Ok(serde_json::from_str(&text)?),
                Message::Ping(_) | Message::Pong(_) => continue,
                Message::Close(f) => {
                    return Err(crate::Error::Provider(format!("relay closed: {f:?}")))
                }
                _ => continue,
            }
        }
    }

    /// Answer a NIP-42 challenge on this connection: sign kind 22242 with
    /// the agent's own key — identity and relay auth are the same keypair,
    /// which is the whole point.
    fn auth(&mut self, challenge: &str) -> Result<(), crate::Error> {
        let builder = EventBuilder::new(Kind::Custom(KIND_AUTH), "")
            .tag(Tag::custom("relay", vec![self.url.clone()]))
            .tag(Tag::custom("challenge", vec![challenge.to_string()]));
        let event = self.custody.sign(self.agent, builder)?;
        self.send(json!([
            "AUTH",
            serde_json::from_str::<Value>(&event.as_json())?
        ]))?;
        // The relay replies OK <auth-event-id> true/false.
        for _ in 0..64 {
            let v = self.recv()?;
            if v.get(0).and_then(|t| t.as_str()) == Some("EVENT")
                && v.get(1)
                    .and_then(|s| s.as_str())
                    .is_some_and(|s| s.starts_with("apiary-listen"))
            {
                self.pending.push(v);
                continue;
            }
            match v.get(0).and_then(|t| t.as_str()) {
                Some("OK") if v.get(1).and_then(|i| i.as_str()) == Some(&event.id.to_hex()) => {
                    return if v.get(2).and_then(|b| b.as_bool()).unwrap_or(false) {
                        self.authed = true;
                        Ok(())
                    } else {
                        Err(crate::Error::Provider(format!(
                            "auth rejected: {}",
                            v.get(3).and_then(|m| m.as_str()).unwrap_or("")
                        )))
                    };
                }
                _ => continue,
            }
        }
        Err(crate::Error::Provider("no auth response".into()))
    }

    /// Publish an event, transparently answering an auth challenge once.
    pub fn publish(&mut self, event: &Event) -> Result<String, crate::Error> {
        for attempt in 0..2 {
            self.send(json!([
                "EVENT",
                serde_json::from_str::<Value>(&event.as_json())?
            ]))?;
            loop {
                let v = self.recv()?;
                if v.get(0).and_then(|t| t.as_str()) == Some("EVENT")
                    && v.get(1)
                        .and_then(|s| s.as_str())
                        .is_some_and(|s| s.starts_with("apiary-listen"))
                {
                    self.pending.push(v);
                    continue;
                }
                match v.get(0).and_then(|t| t.as_str()) {
                    Some("AUTH") => {
                        let challenge = v
                            .get(1)
                            .and_then(|c| c.as_str())
                            .ok_or_else(|| crate::Error::Provider("bad AUTH frame".into()))?
                            .to_string();
                        self.auth(&challenge)?;
                        break; // retry the publish on the now-authed socket
                    }
                    Some("OK") if v.get(1).and_then(|i| i.as_str()) == Some(&event.id.to_hex()) => {
                        let accepted = v.get(2).and_then(|b| b.as_bool()).unwrap_or(false);
                        let detail = v.get(3).and_then(|m| m.as_str()).unwrap_or("").to_string();
                        if accepted || detail.starts_with("duplicate") {
                            return Ok(if detail.is_empty() {
                                "accepted".into()
                            } else {
                                detail
                            });
                        }
                        if detail.starts_with("auth-required") && attempt == 0 && !self.authed {
                            // Relay wants auth but didn't challenge yet; wait
                            // for its AUTH frame on the next loop turn.
                            continue;
                        }
                        return Err(crate::Error::Provider(format!("rejected: {detail}")));
                    }
                    _ => continue,
                }
            }
        }
        Err(crate::Error::Provider("publish failed after auth".into()))
    }

    /// REQ → events until EOSE, answering an auth challenge once.
    pub fn req(&mut self, filter: Value) -> Result<Vec<Event>, crate::Error> {
        for _attempt in 0..2 {
            let sub = "apiary-buzz";
            self.send(json!(["REQ", sub, filter]))?;
            let mut out = Vec::new();
            let mut reauth = false;
            for _ in 0..500 {
                let v = self.recv()?;
                match v.get(0).and_then(|t| t.as_str()) {
                    Some("AUTH") => {
                        let challenge = v
                            .get(1)
                            .and_then(|c| c.as_str())
                            .unwrap_or_default()
                            .to_string();
                        self.auth(&challenge)?;
                        reauth = true;
                        break;
                    }
                    Some("CLOSED") if v.get(1).and_then(|s| s.as_str()) == Some(sub) => {
                        let why = v.get(2).and_then(|m| m.as_str()).unwrap_or("");
                        if why.starts_with("auth-required") && !self.authed {
                            // Wait for the relay's AUTH frame.
                            continue;
                        }
                        return Err(crate::Error::Provider(format!("closed: {why}")));
                    }
                    Some("EVENT") if v.get(1).and_then(|s| s.as_str()) == Some(sub) => {
                        if let Some(raw) = v.get(2) {
                            if let Ok(event) = Event::from_json(raw.to_string()) {
                                if event.verify().is_ok() {
                                    out.push(event);
                                }
                            }
                        }
                    }
                    Some("EOSE") if v.get(1).and_then(|s| s.as_str()) == Some(sub) => {
                        return Ok(out)
                    }
                    _ => continue,
                }
            }
            if !reauth {
                break;
            }
        }
        Err(crate::Error::Provider("req failed".into()))
    }

    /// Build + sign + post a Buzz stream message to a channel.
    /// Publish a kind-20002 typing indicator for a channel. Ephemeral and
    /// short-lived by design: Buzz drops it a few seconds after the last
    /// one, so an agent that dies mid-run leaves no ghost typing behind.
    pub fn typing(&mut self, channel_uuid: &str) -> Result<(), crate::Error> {
        let builder = EventBuilder::new(Kind::Custom(KIND_TYPING_INDICATOR), "")
            .tag(Tag::custom("h", vec![channel_uuid.to_string()]));
        let event = self.custody.sign(self.agent, builder)?;
        self.publish(&event)?;
        Ok(())
    }

    pub fn post(
        &mut self,
        channel_uuid: &str,
        content: &str,
        mention_hex: &[String],
    ) -> Result<Event, crate::Error> {
        self.post_after(channel_uuid, content, mention_hex, None)
    }

    /// Post with a causal floor: the event's created_at is never at or before
    /// `after`. Clients sort by created_at, so a reply stamped by a clock a
    /// few seconds behind the mention's author would render ABOVE the message
    /// it answers.
    pub fn post_after(
        &mut self,
        channel_uuid: &str,
        content: &str,
        mention_hex: &[String],
        after: Option<Timestamp>,
    ) -> Result<Event, crate::Error> {
        let mut builder = EventBuilder::new(Kind::Custom(KIND_STREAM_MESSAGE), content)
            .tag(Tag::custom("h", vec![channel_uuid.to_string()]));
        if let Some(after) = after {
            let now = Timestamp::now();
            let floor = Timestamp::from_secs(after.as_secs() + 1);
            builder = builder.custom_created_at(if now > floor { now } else { floor });
        }
        for m in mention_hex {
            if let Ok(pk) = PublicKey::parse(m) {
                builder = builder.tag(Tag::public_key(pk));
            }
        }
        let event = self.custody.sign(self.agent, builder)?;
        self.publish(&event)?;
        Ok(event)
    }

    /// Read a channel's recent messages (kind 9, h-tagged).
    pub fn read_channel(
        &mut self,
        channel_uuid: &str,
        limit: usize,
    ) -> Result<Vec<Event>, crate::Error> {
        self.req(json!({
            "kinds": [KIND_STREAM_MESSAGE],
            "#h": [channel_uuid],
            "limit": limit,
        }))
    }

    /// Discover channels (NIP-29 group metadata).
    pub fn channels(&mut self) -> Result<Vec<Event>, crate::Error> {
        self.req(json!({"kinds": [KIND_GROUP_METADATA], "limit": 100}))
    }

    /// Publish the agent's kind-0 profile metadata (name/about/picture) —
    /// how the agent appears to humans in Buzz and every other nostr client.
    /// Replaceable: publishing again updates the profile.
    pub fn set_profile(
        &mut self,
        name: &str,
        about: Option<&str>,
        picture: Option<&str>,
    ) -> Result<Event, crate::Error> {
        let mut meta = json!({ "name": name });
        if let Some(a) = about {
            meta["about"] = json!(a);
        }
        if let Some(p) = picture {
            meta["picture"] = json!(p);
        }
        let builder = EventBuilder::new(Kind::Metadata, meta.to_string());
        let event = self.custody.sign(self.agent, builder)?;
        self.publish(&event)?;
        Ok(event)
    }

    /// Ask to join a channel (NIP-29 kind 9021). Open channels admit
    /// immediately; private ones queue for an admin.
    pub fn join_channel(&mut self, channel_uuid: &str) -> Result<Event, crate::Error> {
        let builder = EventBuilder::new(Kind::Custom(KIND_JOIN_REQUEST), "")
            .tag(Tag::custom("h", vec![channel_uuid.to_string()]));
        let event = self.custody.sign(self.agent, builder)?;
        self.publish(&event)?;
        Ok(event)
    }

    /// One subscription per channel, mirroring buzz-acp's wire shape
    /// (send_subscribe in crates/buzz-acp/src/relay.rs): kinds + single-value
    /// #h + since. Distinct sub ids so relay-side per-channel gating applies
    /// cleanly. The overlap closes the otherwise permanent blind spot while
    /// a listener is restarting; the adapter deduplicates replayed ids.
    fn subscribe_channels(&mut self, channels: &[String]) -> Result<(), crate::Error> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let since = subscription_since(now);
        for (i, channel) in channels.iter().enumerate() {
            self.send(json!([
                "REQ",
                format!("apiary-listen-{i}"),
                {"kinds": [KIND_STREAM_MESSAGE], "#h": [channel], "since": since}
            ]))?;
        }
        Ok(())
    }


    /// Read back the last `limit` messages in a channel, oldest first.
    ///
    /// A separate short-lived subscription on the same authenticated socket:
    /// REQ with a limit, collect until EOSE, then CLOSE. Events that arrive
    /// for the listening subscription meanwhile are buffered rather than
    /// dropped — the caller is mid-mention and must not lose the next one.
    pub fn recent_messages(
        &mut self,
        channel: &str,
        limit: usize,
    ) -> Result<Vec<(String, String, u64)>, crate::Error> {
        const SUB: &str = "apiary-history";
        self.send(json!([
            "REQ",
            SUB,
            {"kinds": [KIND_STREAM_MESSAGE], "#h": [channel], "limit": limit}
        ]))?;
        let mut out = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if std::time::Instant::now() > deadline {
                break;
            }
            let v = match self.recv() {
                Ok(v) => v,
                // A quiet socket means the relay has nothing more to say.
                Err(crate::Error::Provider(msg)) if msg == "recv-timeout" => break,
                Err(e) => return Err(e),
            };
            match v.get(0).and_then(|t| t.as_str()) {
                Some("EOSE") if v.get(1).and_then(|s| s.as_str()) == Some(SUB) => break,
                Some("EVENT") if v.get(1).and_then(|s| s.as_str()) == Some(SUB) => {
                    let Some(raw) = v.get(2) else { continue };
                    let Ok(event) = Event::from_json(raw.to_string()) else {
                        continue;
                    };
                    if event.verify().is_err() {
                        continue;
                    }
                    out.push((
                        event.pubkey.to_hex(),
                        event.content.clone(),
                        event.created_at.as_secs(),
                    ));
                }
                // Anything for the listening subscription belongs to the
                // mention loop; hold it rather than swallow it.
                _ => self.pending.push(v),
            }
        }
        let _ = self.send(json!(["CLOSE", SUB]));
        out.sort_by_key(|(_, _, at)| *at);
        Ok(out)
    }

    /// Block until a kind-9 message MENTIONS this agent (p tag, or the
    /// literal `@name` trigger in the text) — or until `stop` flips, which
    /// returns Ok(None). Subscribes on first call with a short replay overlap;
    /// drains any events buffered while other calls held the socket. Stop
    /// latency is bounded by the keepalive timeout.
    pub fn next_mention(
        &mut self,
        trigger: &str,
        channels: &[String],
        stop: &std::sync::atomic::AtomicBool,
    ) -> Result<Option<Event>, crate::Error> {
        let self_hex = self.agent.pubkey().to_hex();
        if !self.listening {
            self.subscribe_channels(channels)?;
            self.listening = true;
        }
        loop {
            if stop.load(std::sync::atomic::Ordering::Relaxed) {
                return Ok(None);
            }
            let v = if let Some(buffered) = self.pending.pop() {
                buffered
            } else {
                match self.recv() {
                    Ok(v) => v,
                    Err(crate::Error::Provider(msg)) if msg == "recv-timeout" => {
                        // Quiet interval: ping, then hand control back as a
                        // TICK (Ok(None) with stop unset) so the caller can
                        // do periodic work — lease heartbeats live there.
                        self.socket
                            .send(Message::Ping(Vec::new().into()))
                            .map_err(|e| crate::Error::Provider(format!("keepalive ping: {e}")))?;
                        // A subscription can also lapse without a CLOSED, and
                        // a pong keeps answering either way. Re-REQ after a
                        // long silence: replay is bounded by `since` and the
                        // adapter dedupes ids, so the cost of being wrong is
                        // near zero — far below going deaf for a day.
                        if self.last_traffic.elapsed() > RESUBSCRIBE_AFTER_SILENCE {
                            eprintln!(
                                "no relay traffic for {}m — resubscribing",
                                RESUBSCRIBE_AFTER_SILENCE.as_secs() / 60
                            );
                            self.subscribe_channels(channels)?;
                            self.last_traffic = std::time::Instant::now();
                        }
                        return Ok(None);
                    }
                    Err(e) => return Err(e),
                }
            };
            self.last_traffic = std::time::Instant::now();
            match v.get(0).and_then(|t| t.as_str()) {
                Some("AUTH") => {
                    let challenge = v
                        .get(1)
                        .and_then(|c| c.as_str())
                        .unwrap_or_default()
                        .to_string();
                    self.auth(&challenge)?;
                    // Re-subscribe on the now-authed connection.
                    self.subscribe_channels(channels)?;
                }
                Some("CLOSED") => {
                    // The relay dropped this subscription. Logging it and
                    // carrying on left the agent listening to a socket that
                    // would never deliver again — awake, connected, deaf.
                    eprintln!(
                        "subscription closed by relay: {} — {} · resubscribing",
                        v.get(1).and_then(|s| s.as_str()).unwrap_or("?"),
                        v.get(2).and_then(|m| m.as_str()).unwrap_or("")
                    );
                    self.subscribe_channels(channels)?;
                    self.last_traffic = std::time::Instant::now();
                }
                Some("EVENT")
                    if v.get(1)
                        .and_then(|s| s.as_str())
                        .is_some_and(|s| s.starts_with("apiary-listen")) =>
                {
                    let Some(raw) = v.get(2) else { continue };
                    let Ok(event) = Event::from_json(raw.to_string()) else {
                        continue;
                    };
                    if event.verify().is_err() {
                        continue;
                    }
                    eprintln!(
                        "heard [{}…]: {}",
                        &event.pubkey.to_hex()[..8],
                        event.content.chars().take(60).collect::<String>()
                    );
                    if event.pubkey.to_hex() == self_hex {
                        continue;
                    }
                    let p_tagged = event.tags.iter().any(|t| {
                        let s = t.as_slice();
                        s.first().map(String::as_str) == Some("p")
                            && s.get(1).map(String::as_str) == Some(self_hex.as_str())
                    });
                    let text_trigger = !trigger.is_empty()
                        && event
                            .content
                            .to_lowercase()
                            .contains(&trigger.to_lowercase());
                    if p_tagged || text_trigger {
                        return Ok(Some(event));
                    }
                }
                _ => continue,
            }
        }
    }
}

/// The channel a stream message was posted in (its h tag).
pub fn channel_of(event: &Event) -> Option<String> {
    event.tags.iter().find_map(|t| {
        let s = t.as_slice();
        (s.first().map(String::as_str) == Some("h")).then(|| s.get(1).cloned())?
    })
}

/// Discover the channel ids visible on this session's relay (the `d` tag of
/// kind-39000 group metadata — the same UUID Buzz puts in message `h` tags).
pub fn channel_ids(session: &mut BuzzSession) -> Result<Vec<String>, crate::Error> {
    Ok(session
        .channels()?
        .iter()
        .filter_map(|e| {
            e.tags.iter().find_map(|t| {
                let s = t.as_slice();
                (s.first().map(String::as_str) == Some("d")).then(|| s.get(1).cloned())?
            })
        })
        .collect())
}

/// Buzz as a ChannelAdapter: the relay session, channel-scoped
/// subscriptions, mention triggering, loop guards, and the causal
/// timestamp floor — the platform's quirks, and nothing else. Governance
/// lives in the presence engine.
pub struct BuzzAdapter<'a> {
    session: BuzzSession<'a>,
    channels: Vec<String>,
    trigger: String,
    relay: String,
    custody: &'a Custody,
    handle: &'a AgentHandle,
    cursor_path: Option<std::path::PathBuf>,
    recent: RecentEventIds,
    /// When the channel list was last re-read. A listener resolves its
    /// channels once at connect, so a channel created afterwards — including
    /// a DM someone opens with the agent — is invisible until it restarts.
    channels_checked: std::time::Instant,
}

impl<'a> BuzzAdapter<'a> {
    pub fn connect(
        relay: &str,
        custody: &'a Custody,
        handle: &'a AgentHandle,
        trigger: String,
    ) -> Result<Self, crate::Error> {
        Self::connect_with_cursor(relay, custody, handle, trigger, None)
    }

    /// Connect a long-running presence adapter with a local replay cursor.
    /// The cursor contains only recent Nostr event ids; it is deliberately
    /// host-local and disposable, while the actual mention remains signed in
    /// the agent's episodic log.
    pub fn connect_with_cursor(
        relay: &str,
        custody: &'a Custody,
        handle: &'a AgentHandle,
        trigger: String,
        cursor_path: Option<std::path::PathBuf>,
    ) -> Result<Self, crate::Error> {
        Self::connect_as(relay, custody, handle, trigger, cursor_path, None)
    }

    /// Connect, and publish the agent's kind-0 profile so people see a NAME
    /// rather than a hex pubkey.
    ///
    /// An agent asserting who it is, signed by its own key, is Apiary's job
    /// and nobody else's — leaving it to a later manual step means the agent
    /// shows up in every client as `aab49cec…61ba` until somebody notices.
    /// Best effort: a relay that refuses the profile must not stop the agent
    /// from listening.
    pub fn connect_as(
        relay: &str,
        custody: &'a Custody,
        handle: &'a AgentHandle,
        trigger: String,
        cursor_path: Option<std::path::PathBuf>,
        display_name: Option<&str>,
    ) -> Result<Self, crate::Error> {
        let mut session = BuzzSession::connect(relay, custody, handle)?;
        session.enable_keepalive(std::time::Duration::from_secs(15));
        if let Some(name) = display_name.map(str::trim).filter(|n| !n.is_empty()) {
            if let Err(e) = session.set_profile(name, None, None) {
                eprintln!("buzz: could not publish profile for {name}: {e}");
            }
        }
        let channels = channel_ids(&mut session)?;
        let recent = RecentEventIds::load(cursor_path.as_deref());
        Ok(Self {
            session,
            channels,
            trigger,
            relay: relay.to_string(),
            custody,
            handle,
            cursor_path,
            recent,
            channels_checked: std::time::Instant::now(),
        })
    }
}


impl BuzzAdapter<'_> {
    /// Pick up channels created since the listener started.
    ///
    /// Someone opening a DM with an agent creates a new channel; so does
    /// adding it to a channel. Neither is visible to a subscription that was
    /// resolved once at connect, which is why an agent can look perfectly
    /// healthy and never hear a word you say to it.
    fn refresh_channels(&mut self) -> Result<(), crate::Error> {
        if self.channels_checked.elapsed() < CHANNEL_REFRESH {
            return Ok(());
        }
        self.channels_checked = std::time::Instant::now();
        let current = channel_ids(&mut self.session)?;
        let added: Vec<String> = current
            .iter()
            .filter(|c| !self.channels.contains(c))
            .cloned()
            .collect();
        if added.is_empty() {
            return Ok(());
        }
        eprintln!(
            "buzz: {} new channel(s) since connect — subscribing",
            added.len()
        );
        self.channels = current;
        let channels = self.channels.clone();
        self.session.subscribe_channels(&channels)?;
        Ok(())
    }
}

/// Typing on Buzz costs one signed ephemeral event on the connection the
/// listener already holds — no second socket, no second auth.
struct BuzzTyping<'a, 'b> {
    session: &'a mut BuzzSession<'b>,
    channel: String,
}

impl crate::presence::TypingPulse for BuzzTyping<'_, '_> {
    fn pulse(&mut self) {
        // A failed indicator is not worth a word: the reply itself is the
        // thing that matters, and it is still on its way.
        let _ = self.session.typing(&self.channel);
    }
}

impl crate::presence::ChannelAdapter for BuzzAdapter<'_> {
    fn kind(&self) -> &'static str {
        "buzz"
    }

    fn typing<'a>(
        &'a mut self,
        channel: &str,
        _voice: bool,
    ) -> Option<Box<dyn crate::presence::TypingPulse + 'a>> {
        Some(Box::new(BuzzTyping {
            session: &mut self.session,
            channel: channel.to_string(),
        }))
    }

    fn recent_context(&mut self, channel: &str, limit: usize) -> Vec<(String, String)> {
        let me = self.session.agent.pubkey().to_hex();
        self.session
            .recent_messages(channel, limit)
            .unwrap_or_default()
            .into_iter()
            .map(|(author, text, _)| {
                let who = if author == me {
                    "you".to_string()
                } else {
                    format!("{}…", &author[..author.len().min(8)])
                };
                (who, text)
            })
            .collect()
    }

    fn describe(&self) -> String {
        format!(
            "buzz: watching {} channels on {} (trigger {:?} or p-tag)",
            self.channels.len(),
            self.relay,
            self.trigger
        )
    }

    fn next_mention(
        &mut self,
        stop: &std::sync::atomic::AtomicBool,
    ) -> Result<Option<crate::presence::Mention>, crate::Error> {
        use std::sync::atomic::Ordering;
        // Before listening, take in any channel opened since we connected.
        // Rate-limited internally; a failure here is not worth going deaf
        // over, so it is logged and the existing subscription carries on.
        if let Err(e) = self.refresh_channels() {
            eprintln!("buzz: could not refresh channel list: {e}");
        }
        loop {
            match self
                .session
                .next_mention(&self.trigger, &self.channels, stop)
            {
                Ok(Some(event)) => {
                    let event_id = event.id.to_hex();
                    if self.recent.contains(&event_id) {
                        continue;
                    }
                    self.recent.remember(event_id, self.cursor_path.as_deref());
                    let Some(channel) = channel_of(&event) else {
                        return Ok(None); // malformed: treat as tick
                    };
                    return Ok(Some(crate::presence::Mention {
                        channel,
                        author: event.pubkey.to_hex(),
                        text: event.content.clone(),
                        // The mention's created_at rides along for the causal
                        // timestamp floor on the reply.
                        reply_ref: event.created_at.as_secs().to_string(),
                        // Nostr embeds images as URLs in content; fetching
                        // arbitrary URLs is a policy decision, deliberately
                        // not a silent default. Text-only for now.
                        attachments: Vec::new(),
                    }));
                }
                Ok(None) => return Ok(None),
                Err(e) => {
                    // Dead or dropped connection: reconnect with backoff rather
                    // than dying — resilience is the platform's quirk, so it
                    // lives in the adapter.
                    for _ in 0..5 {
                        if stop.load(Ordering::Relaxed) {
                            return Ok(None);
                        }
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    }
                    return match BuzzSession::connect(&self.relay, self.custody, self.handle) {
                        Ok(mut fresh) => {
                            fresh.enable_keepalive(std::time::Duration::from_secs(15));
                            self.session = fresh;
                            Ok(None) // tick; resubscribes on the next call
                        }
                        Err(_) => {
                            let _ = e;
                            Ok(None) // keep retrying on subsequent ticks
                        }
                    };
                }
            }
        }
    }

    fn reply(
        &mut self,
        mention: &crate::presence::Mention,
        reply: &crate::presence::Reply,
    ) -> Result<String, crate::Error> {
        let text = reply.text.as_str();
        // No p-tag (a p-tag is a trigger — two listening agents would
        // ping-pong forever) + causal floor (clients sort by created_at).
        let after = mention
            .reply_ref
            .parse::<u64>()
            .ok()
            .map(Timestamp::from_secs);
        let event = self
            .session
            .post_after(&mention.channel, text, &[], after)?;
        Ok(event.id.to_hex())
    }
}

/// The CLI's single-channel Buzz service: inline lease (claim → heartbeat
/// on ticks → yield/release) around the generic presence loop. The daemon
/// uses the per-agent lease keeper instead and drives adapters directly.
#[allow(clippy::too_many_arguments)]
pub fn run_mention_service(
    manifest: &apiary_core::manifest::Manifest,
    agent_dir: &std::path::Path,
    custody: &Custody,
    handle: &AgentHandle,
    relay: &str,
    trigger: &str,
    stop: &std::sync::atomic::AtomicBool,
    mut sink: impl FnMut(String),
) -> Result<(), crate::Error> {
    let lease_relays = manifest.memory.log_relays.clone();
    let agent_hex = handle.pubkey().to_hex();
    let home = agent_dir
        .parent()
        .and_then(|p| p.parent())
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| agent_dir.to_path_buf());
    let host = crate::lease::host_id(&home);
    let heartbeat_secs = manifest.lease.heartbeat_secs.max(10);
    let expiry_secs = manifest.lease.expiry_secs.max(heartbeat_secs * 2);
    let mut lease_seq: Option<u64> = None;
    if lease_relays.is_empty() {
        sink(
            "lease: no memory.log_relays declared — running WITHOUT cross-host coordination".into(),
        );
    } else {
        match crate::lease::claim(
            custody,
            handle,
            &lease_relays,
            &agent_hex,
            &host,
            expiry_secs,
        )? {
            crate::lease::Claim::Held { seq } => {
                lease_seq = Some(seq);
                sink(format!("lease claimed (host {host}, seq {seq})"));
            }
            crate::lease::Claim::Contested(l) => {
                return Err(crate::Error::Provider(format!(
                    "lease held by host {} (seq {}) — this agent appears to be running                      elsewhere; takeover is a human decision (Overview → Lease)",
                    l.host, l.seq
                )));
            }
        }
    }
    let mut adapter = BuzzAdapter::connect(relay, custody, handle, trigger.to_string())?;
    let mut last_heartbeat = std::time::Instant::now();
    let mut yielded = false;
    let mut lines: Vec<String> = Vec::new();
    let result = crate::presence::run_presence(
        &mut adapter,
        manifest,
        agent_dir,
        custody,
        handle,
        stop,
        || {
            let Some(seq) = lease_seq else {
                return Ok(true);
            };
            if last_heartbeat.elapsed().as_secs() < heartbeat_secs {
                return Ok(true);
            }
            last_heartbeat = std::time::Instant::now();
            match crate::lease::fetch(&lease_relays, &agent_hex) {
                Some(l) if l.host != host && l.seq > seq => {
                    yielded = true;
                    lines.push(format!(
                        "lease superseded by host {} (seq {}) — yielding",
                        l.host, l.seq
                    ));
                    Ok(false)
                }
                _ => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let _ = crate::lease::publish(
                        custody,
                        handle,
                        &lease_relays,
                        &host,
                        seq,
                        now + expiry_secs,
                    );
                    Ok(true)
                }
            }
        },
        &mut sink,
    );
    for l in lines {
        sink(l);
    }
    // Graceful stop releases; a yield must NOT (the successor's seq rules).
    if let (Some(seq), false) = (lease_seq, yielded) {
        match crate::lease::release(custody, handle, &lease_relays, &host, seq) {
            Ok(()) => sink("lease released".into()),
            Err(e) => sink(format!("lease release failed ({e}) — expires naturally")),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscriptions_overlap_listener_restarts() {
        assert_eq!(subscription_since(1_000), 880);
        assert_eq!(subscription_since(30), 0);
    }

    #[test]
    fn recent_event_ids_survive_adapter_recreation() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "apiary-buzz-recent-{}-{unique}.json",
            std::process::id()
        ));
        let mut recent = RecentEventIds::default();
        recent.remember("event-a".into(), Some(&path));
        recent.remember("event-a".into(), Some(&path));
        recent.remember("event-b".into(), Some(&path));

        let loaded = RecentEventIds::load(Some(&path));
        assert!(loaded.contains("event-a"));
        assert!(loaded.contains("event-b"));
        assert_eq!(loaded.ids.len(), 2);
        let _ = std::fs::remove_file(path);
    }
}
