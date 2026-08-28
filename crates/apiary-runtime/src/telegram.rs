//! Telegram as a ChannelAdapter — Bot API long polling.
//!
//! The bot token is a platform shim, sealed to the agent like any
//! credential; the identity stays the npub and every interaction lands in
//! the signed log. Long polling (`getUpdates`) means no webhook, no
//! inbound port. `allowed_chats` is the human-owned gate: anyone can find
//! a bot, but the MANIFEST decides who may engage the agent ("*" opts out
//! deliberately). Telegram never delivers bot messages to other bots, so
//! Buzz's ping-pong guard is structurally unnecessary here.

use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const POLL_SECS: u64 = 15;

pub struct TelegramAdapter {
    client: reqwest::blocking::Client,
    token: String,
    bot_username: String,
    allowed_chats: Vec<String>,
    offset: i64,
}

impl TelegramAdapter {
    pub fn connect(token: &str, allowed_chats: Vec<String>) -> Result<Self, crate::Error> {
        if allowed_chats.is_empty() {
            return Err(crate::Error::Provider(
                "telegram presence requires allowed_chats (chat ids; [\"*\"] admits \
                 anyone — say so deliberately)"
                    .into(),
            ));
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(POLL_SECS + 10))
            .build()
            .map_err(|e| crate::Error::Provider(format!("telegram client: {e}")))?;
        let me: Value = client
            .get(format!("https://api.telegram.org/bot{token}/getMe"))
            .send()
            .and_then(|r| r.json())
            .map_err(|e| crate::Error::Provider(format!("telegram getMe: {e}")))?;
        if me["ok"].as_bool() != Some(true) {
            return Err(crate::Error::Provider(format!(
                "telegram rejected the bot token: {}",
                me["description"].as_str().unwrap_or("unknown")
            )));
        }
        let bot_username = me["result"]["username"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        Ok(Self {
            client,
            token: token.to_string(),
            bot_username,
            allowed_chats,
            offset: 0,
        })
    }

    fn call(&self, method: &str, body: Value) -> Result<Value, crate::Error> {
        self.client
            .post(format!(
                "https://api.telegram.org/bot{}/{method}",
                self.token
            ))
            .json(&body)
            .send()
            .and_then(|r| r.json())
            .map_err(|e| crate::Error::Provider(format!("telegram {method}: {e}")))
    }

    fn chat_allowed(&self, chat_id: &str) -> bool {
        self.allowed_chats.iter().any(|c| c == "*" || c == chat_id)
    }

    /// Download a Telegram file by id, size-capped: an oversized or
    /// failed file is skipped, never fatal to the mention.
    fn fetch_file(&self, file_id: &str) -> Option<Vec<u8>> {
        const MAX_BYTES: u64 = crate::presence::MAX_ATTACHMENT_BYTES;
        let f = self.call("getFile", json!({"file_id": file_id})).ok()?;
        if f["result"]["file_size"].as_u64().unwrap_or(0) > MAX_BYTES {
            return None;
        }
        let path = f["result"]["file_path"].as_str()?;
        let bytes = self
            .client
            .get(format!(
                "https://api.telegram.org/file/bot{}/{path}",
                self.token
            ))
            .send()
            .ok()?
            .bytes()
            .ok()?;
        if bytes.len() as u64 > MAX_BYTES {
            return None;
        }
        Some(bytes.to_vec())
    }

    /// Everything attached to a message that the agent can take as DATA:
    /// the largest photo size, a voice note, or an audio file.
    fn attachments(&self, msg: &Value) -> Vec<crate::presence::Attachment> {
        use crate::presence::Attachment;
        use base64::Engine;
        let b64 = |b: Vec<u8>| base64::engine::general_purpose::STANDARD.encode(b);
        let mut out = Vec::new();
        if let Some(id) = msg["photo"]
            .as_array()
            .and_then(|a| a.last())
            .and_then(|p| p["file_id"].as_str())
        {
            if let Some(bytes) = self.fetch_file(id) {
                out.push(Attachment::Image {
                    media_type: "image/jpeg".into(), // Telegram photos are JPEG
                    base64: b64(bytes),
                });
            }
        }
        // `voice` = recorded in-app (OGG/Opus); `audio` = an uploaded file.
        for key in ["voice", "audio"] {
            let a = &msg[key];
            let Some(id) = a["file_id"].as_str() else {
                continue;
            };
            if let Some(bytes) = self.fetch_file(id) {
                out.push(Attachment::Audio {
                    media_type: a["mime_type"].as_str().unwrap_or("audio/ogg").to_string(),
                    base64: b64(bytes),
                    duration_secs: a["duration"].as_f64().map(|d| d as f32),
                });
            }
        }
        out
    }

    /// Trigger rules: DMs always; groups on @botname or a reply to the bot.
    fn triggers(&self, msg: &Value) -> bool {
        let chat_type = msg["chat"]["type"].as_str().unwrap_or_default();
        if chat_type == "private" {
            return true;
        }
        let text = msg["text"]
            .as_str()
            .or_else(|| msg["caption"].as_str())
            .unwrap_or_default();
        if !self.bot_username.is_empty()
            && text
                .to_lowercase()
                .contains(&format!("@{}", self.bot_username.to_lowercase()))
        {
            return true;
        }
        msg["reply_to_message"]["from"]["username"].as_str() == Some(self.bot_username.as_str())
    }
}

/// Telegram shows a chat action for about five seconds, so this is a
/// heartbeat too. It names the right activity: a voice reply announces
/// itself as recording, because "typing" followed by audio is a small lie.
struct TelegramTyping<'a> {
    client: &'a reqwest::blocking::Client,
    token: &'a str,
    chat_id: i64,
    action: &'static str,
}

impl crate::presence::TypingPulse for TelegramTyping<'_> {
    fn pulse(&mut self) {
        let _ = self
            .client
            .post(format!(
                "https://api.telegram.org/bot{}/sendChatAction",
                self.token
            ))
            .json(&serde_json::json!({
                "chat_id": self.chat_id,
                "action": self.action,
            }))
            .send();
    }
}

impl crate::presence::ChannelAdapter for TelegramAdapter {
    fn kind(&self) -> &'static str {
        "telegram"
    }

    fn typing<'a>(
        &'a mut self,
        channel: &str,
        voice: bool,
    ) -> Option<Box<dyn crate::presence::TypingPulse + 'a>> {
        let chat_id = channel.parse::<i64>().ok()?;
        Some(Box::new(TelegramTyping {
            client: &self.client,
            token: &self.token,
            chat_id,
            action: if voice { "record_voice" } else { "typing" },
        }))
    }

    fn describe(&self) -> String {
        format!(
            "telegram: @{} long-polling ({} allowed chats)",
            self.bot_username,
            self.allowed_chats.len()
        )
    }

    fn next_mention(
        &mut self,
        stop: &AtomicBool,
    ) -> Result<Option<crate::presence::Mention>, crate::Error> {
        if stop.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let updates = match self.call(
            "getUpdates",
            json!({"timeout": POLL_SECS, "offset": self.offset, "allowed_updates": ["message"]}),
        ) {
            Ok(v) => v,
            Err(_) => {
                // Network hiccup: tick; the engine calls again.
                std::thread::sleep(Duration::from_secs(2));
                return Ok(None);
            }
        };
        for u in updates["result"].as_array().cloned().unwrap_or_default() {
            if let Some(id) = u["update_id"].as_i64() {
                self.offset = self.offset.max(id + 1);
            }
            let msg = &u["message"];
            // Text, a captioned photo/voice note, or a bare one all engage.
            let has_media =
                msg["photo"].is_array() || msg["voice"].is_object() || msg["audio"].is_object();
            let text = msg["text"]
                .as_str()
                .or_else(|| msg["caption"].as_str())
                .unwrap_or_default()
                .to_string();
            if text.is_empty() && !has_media {
                continue;
            }
            let chat_id = match msg["chat"]["id"].as_i64() {
                Some(id) => id.to_string(),
                None => continue,
            };
            if !self.chat_allowed(&chat_id) || !self.triggers(msg) {
                continue;
            }
            let author = msg["from"]["username"]
                .as_str()
                .map(String::from)
                .unwrap_or_else(|| msg["from"]["id"].as_i64().unwrap_or(0).to_string());
            let reply_ref = msg["message_id"].as_i64().unwrap_or(0).to_string();
            let attachments = if has_media {
                self.attachments(msg)
            } else {
                Vec::new()
            };
            let text = if text.is_empty() {
                if msg["voice"].is_object() || msg["audio"].is_object() {
                    "(a voice message, with no caption)".to_string()
                } else {
                    "(an image, with no caption)".to_string()
                }
            } else {
                text
            };
            // Telegram confirms an update only when a later getUpdates call
            // carries an offset beyond it. Confirm this claim before the
            // governed model call: a manifest bounce may stop the adapter as
            // soon as that call returns, otherwise the same message is
            // replayed to the replacement listener. Any update returned by
            // this zero-timeout call remains unconfirmed at `self.offset` and
            // will be read normally on the next poll.
            let _ = self.call(
                "getUpdates",
                json!({"timeout": 0, "offset": self.offset, "limit": 1, "allowed_updates": ["message"]}),
            );
            return Ok(Some(crate::presence::Mention {
                channel: chat_id,
                author,
                text,
                reply_ref,
                attachments,
            }));
        }
        Ok(None) // quiet poll = tick
    }

    fn reply(
        &mut self,
        mention: &crate::presence::Mention,
        reply: &crate::presence::Reply,
    ) -> Result<String, crate::Error> {
        let chat_id = mention.channel.parse::<i64>().unwrap_or_default();
        let reply_to = mention.reply_ref.parse::<i64>().unwrap_or_default();
        send_reply(&self.client, &self.token, chat_id, Some(reply_to), reply)
    }
}

/// Deliver a Reply to a chat: voice (sendVoice, text as caption) when
/// audio is present and the text fits a caption, else sendMessage. A
/// refused voice upload (codec, size) still delivers the text. Shared by
/// the presence adapter and the `telegram-send` connector.
pub fn send_reply(
    client: &reqwest::blocking::Client,
    token: &str,
    chat_id: i64,
    reply_to: Option<i64>,
    reply: &crate::presence::Reply,
) -> Result<String, crate::Error> {
    if let Some(crate::presence::Attachment::Audio {
        base64: b64,
        duration_secs,
        ..
    }) = &reply.audio
    {
        if reply.text.chars().count() <= 1024 {
            use base64::Engine;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| crate::Error::Provider(format!("voice reply audio: {e}")))?;
            let mut form = reqwest::blocking::multipart::Form::new()
                .text("chat_id", chat_id.to_string())
                .text("caption", reply.text.clone())
                .part(
                    "voice",
                    reqwest::blocking::multipart::Part::bytes(bytes)
                        .file_name("reply.ogg")
                        .mime_str("audio/ogg")
                        .map_err(|e| crate::Error::Provider(e.to_string()))?,
                );
            if let Some(r) = reply_to {
                form = form.text("reply_to_message_id", r.to_string());
            }
            if let Some(d) = duration_secs {
                form = form.text("duration", (d.round() as i64).to_string());
            }
            let resp: Value = client
                .post(format!("https://api.telegram.org/bot{token}/sendVoice"))
                .multipart(form)
                .send()
                .and_then(|r| r.json())
                .map_err(|e| crate::Error::Provider(format!("telegram sendVoice: {e}")))?;
            if resp["ok"].as_bool() == Some(true) {
                return Ok(resp["result"]["message_id"]
                    .as_i64()
                    .unwrap_or_default()
                    .to_string());
            }
        }
    }
    let mut body = json!({ "chat_id": chat_id, "text": reply.text });
    if let Some(r) = reply_to {
        body["reply_to_message_id"] = json!(r);
    }
    let resp: Value = client
        .post(format!("https://api.telegram.org/bot{token}/sendMessage"))
        .json(&body)
        .send()
        .and_then(|r| r.json())
        .map_err(|e| crate::Error::Provider(format!("telegram sendMessage: {e}")))?;
    if resp["ok"].as_bool() != Some(true) {
        return Err(crate::Error::Provider(format!(
            "telegram sendMessage refused: {}",
            resp["description"].as_str().unwrap_or("unknown")
        )));
    }
    Ok(resp["result"]["message_id"]
        .as_i64()
        .unwrap_or_default()
        .to_string())
}

/// Outbound Telegram as a governed TOOL — bound automatically for any
/// agent with Telegram presence (same sealed token, same `allowed_chats`
/// gate as inbound; declaring presence is the ratified act). The model
/// asks; the host checks the allowlist, JIT-opens the token, optionally
/// voices the text through the `speak` slot, and sends. Every call is a
/// `tool.call` log entry carrying the destination.
pub struct TelegramSend {
    pub credential: apiary_core::manifest::EncryptedBlob,
    pub allowed_chats: Vec<String>,
    pub speaker: Option<Box<dyn crate::speak::Speaker>>,
}

impl crate::connector::Connector for TelegramSend {
    fn def(&self) -> crate::connector::ToolDef {
        crate::connector::ToolDef {
            name: "telegram_send".into(),
            description: format!(
                "Send a Telegram message from this agent's bot to a chat it is allowed to \
                 address (allowed chats: {}). Use for proactive messages, not for replying \
                 to a mention (replies happen automatically). Set as_voice=true to send it \
                 as a spoken voice note (the text is included as the caption){}.",
                self.allowed_chats.join(", "),
                if self.speaker.is_some() {
                    ""
                } else {
                    " — no speak slot on this host, so as_voice falls back to text"
                }
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "chat_id": {"type": "string", "description": "Telegram chat id (numeric string)"},
                    "text": {"type": "string", "description": "Message text (max 4096 chars; 1024 if voice)"},
                    "as_voice": {"type": "boolean", "description": "Also synthesize and send as a voice note", "default": false}
                },
                "required": ["chat_id", "text"]
            }),
        }
    }

    fn execute(
        &self,
        custody: &apiary_core::custody::Custody,
        agent: &apiary_core::custody::AgentHandle,
        args: &Value,
    ) -> Result<String, crate::Error> {
        let chat = args["chat_id"]
            .as_str()
            .map(str::to_string)
            .or_else(|| args["chat_id"].as_i64().map(|i| i.to_string()))
            .ok_or_else(|| crate::Error::Provider("telegram_send: chat_id required".into()))?;
        if !self.allowed_chats.iter().any(|c| c == "*" || c == &chat) {
            return Err(crate::Error::Provider(format!(
                "telegram_send: chat {chat} is not in the manifest's allowed_chats — refused"
            )));
        }
        let chat_id: i64 = chat
            .parse()
            .map_err(|_| crate::Error::Provider("telegram_send: chat_id must be numeric".into()))?;
        let text = args["text"].as_str().unwrap_or_default().trim().to_string();
        if text.is_empty() {
            return Err(crate::Error::Provider(
                "telegram_send: text required".into(),
            ));
        }
        let text: String = text.chars().take(4096).collect();
        let want_voice = args["as_voice"].as_bool().unwrap_or(false);
        // Voice is best-effort — the text always goes — but a downgrade is
        // REPORTED in the tool result, never silent: the model (and the
        // operator reading the log) should know why a voice note came out
        // as text.
        let mut voice_note: Option<String> = None;
        let audio = match (&self.speaker, want_voice) {
            (None, true) => {
                voice_note = Some("no speak slot bound on this host".into());
                None
            }
            (Some(_), true) if text.chars().count() > crate::speak::MAX_SPEAK_CHARS => {
                voice_note = Some(format!(
                    "text is {} chars, over the {} voice ceiling",
                    text.chars().count(),
                    crate::speak::MAX_SPEAK_CHARS
                ));
                None
            }
            (Some(sp), true) => match sp.speak(&text).and_then(|s| crate::speak::to_ogg_opus(&s)) {
                Ok(s) => {
                    use base64::Engine;
                    Some(crate::presence::Attachment::Audio {
                        media_type: s.media_type,
                        base64: base64::engine::general_purpose::STANDARD.encode(&s.bytes),
                        duration_secs: s.duration_secs,
                    })
                }
                Err(e) => {
                    voice_note = Some(format!("speech synthesis failed: {e}"));
                    None
                }
            },
            _ => None,
        };
        let token = custody.open(agent, &self.credential)?;
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| crate::Error::Provider(format!("telegram client: {e}")))?;
        let voiced = audio.is_some();
        let id = send_reply(
            &client,
            token.as_str(),
            chat_id,
            None,
            &crate::presence::Reply { text, audio },
        )?;
        Ok(match voice_note {
            Some(why) => format!(
                "sent to chat {chat} as TEXT (voice requested but unavailable: {why}) (message_id {id})"
            ),
            None => format!(
                "sent to chat {chat} as {} (message_id {id})",
                if voiced { "voice+caption" } else { "text" }
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter() -> TelegramAdapter {
        TelegramAdapter {
            client: reqwest::blocking::Client::new(),
            token: "t".into(),
            bot_username: "helper_bot".into(),
            allowed_chats: vec!["100".into()],
            offset: 0,
        }
    }

    #[test]
    fn dms_trigger_groups_need_mention() {
        let a = adapter();
        assert!(a.triggers(&json!({"chat": {"type": "private"}, "text": "hello"})));
        assert!(!a.triggers(&json!({"chat": {"type": "group"}, "text": "hello"})));
        assert!(a.triggers(&json!({"chat": {"type": "group"}, "text": "hey @Helper_Bot help"})));
        assert!(a.triggers(&json!({
            "chat": {"type": "group"}, "text": "yes",
            "reply_to_message": {"from": {"username": "helper_bot"}}
        })));
    }

    #[test]
    fn captioned_photos_trigger_like_text() {
        let a = adapter();
        // A bare photo in a DM engages; in a group it needs a caption mention.
        assert!(a.triggers(&json!({"chat": {"type": "private"}, "photo": [{}]})));
        assert!(!a.triggers(&json!({"chat": {"type": "group"}, "photo": [{}]})));
        assert!(a.triggers(&json!({
            "chat": {"type": "group"}, "photo": [{}],
            "caption": "what is this @helper_bot?"
        })));
    }

    #[test]
    fn voice_notes_engage_like_photos() {
        let a = adapter();
        // Bare voice note in a DM engages; in a group it needs a caption mention.
        assert!(a.triggers(&json!({"chat": {"type": "private"}, "voice": {"file_id": "v"}})));
        assert!(!a.triggers(&json!({"chat": {"type": "group"}, "voice": {"file_id": "v"}})));
        assert!(a.triggers(&json!({
            "chat": {"type": "group"}, "voice": {"file_id": "v"},
            "caption": "@helper_bot listen to this"
        })));
    }

    #[test]
    fn send_tool_refuses_chats_outside_the_allowlist_before_touching_the_key() {
        use crate::connector::Connector;
        let tool = TelegramSend {
            credential: apiary_core::manifest::EncryptedBlob {
                nip44: "not-a-real-blob".into(),
            },
            allowed_chats: vec!["100".into()],
            speaker: None,
        };
        let mut custody = apiary_core::custody::Custody::new();
        let handle = custody.admit(nostr::prelude::Keys::generate());
        let err = tool
            .execute(&custody, &handle, &json!({"chat_id": "999", "text": "hi"}))
            .unwrap_err()
            .to_string();
        assert!(err.contains("allowed_chats"), "{err}");
        assert!(tool.def().name == "telegram_send");
        // Missing text is refused before the key is opened, too.
        let err = tool
            .execute(&custody, &handle, &json!({"chat_id": "100", "text": ""}))
            .unwrap_err()
            .to_string();
        assert!(err.contains("text required"), "{err}");
    }

    #[test]
    fn allowlist_is_default_deny() {
        let a = adapter();
        assert!(a.chat_allowed("100"));
        assert!(!a.chat_allowed("999"));
        let mut open = adapter();
        open.allowed_chats = vec!["*".into()];
        assert!(open.chat_allowed("999"));
    }
}
