# Scope: an Apiary agent in a Buzz huddle
Voice so far has meant the **companion app** (apiary-voice): a Mac app, a push-to-talk key, one human talking to one agent. It works — roughly 1.2–2s round trip — but it is a desktop app to install, it is one-to-one, and the audio crosses a tunnel to reach a remote host.

A huddle is a better fit, for one reason that outweighs the rest: **Buzz and Apiary run on the same machine.** The audio path is localhost. And because Buzz has mobile, an agent in a huddle reaches you on your phone without shipping an iOS app.

## What Buzz already provides
Huddle audio lives in `buzz-relay` (`src/audio/`) — no external SFU:

- `wss://…/huddle/{channel_id}/audio`, each participant authenticated by NIP-42 challenge and checked for channel membership. Apiary already speaks NIP-42 to this relay for mentions.
  
- **Frame protocol v2:** 8-byte big-endian header — sequence `u16`, 48 kHz timestamp `u32`, **level dBov** `i8`, flags `u8` — then an opaque Opus payload.
  
- **The relay forwards frames between peers; it does not mix them.**
  
- Room state: soft cap 25 peers, bounded per-peer channel that drops on full, separate control channel that never drops join/leave.
  
- **Lifecycle events as signed Nostr events**: participant joined, left, huddle ended.
  
- Not built: recording and per-track publishing (kinds reserved, no producer).
  

Three of those facts make this much easier than a general "agent joins a call" problem:

1. **Per-peer streams, so speaker attribution is free.** No diarization: each stream is one person, already identified by their key.
  
2. **No mix, so no echo.** The agent never hears its own output, which deletes the acoustic echo cancellation problem that cost real effort in apiary-voice.
  
3. `level_dbov` **is in the header**, so voice-activity detection costs nothing — silence is visible without decoding a frame.
  
## What Apiary has to build
**A** `buzz-huddle` **presence channel.** Presence already means "the platforms an agent lives on, answering when spoken to"; this is one more adapter beside `buzz` and `telegram`. Joining is the door.

**Opus in and out.** Apiary encodes OGG/Opus today only for Telegram voice notes, via ffmpeg. A huddle needs raw 48 kHz Opus frames, so this needs a real codec binding (`audiopus`/`opus`) rather than shelling out per frame.

**Turn-taking**, which is the actual work:

- Decode a peer's stream only while its `level_dbov` says someone is talking.
  
- Transcribe through the existing `transcribe` slot, streaming.
  
- Speak when addressed — by name, or by a direct question after the agent has been brought in. **Quiet by default**, the same principle as watches.
  
- Never talk over anyone: if a human starts while the agent is speaking, stop mid-sentence. apiary-voice already does barge-in this way.
  
- A hard ceiling on turns per minute, so a confused agent cannot filibuster.
  

**One governed run per turn**, through the ordinary gates. A turn is short, so `tokens_per_run` matters more than usual.
## Governance — the part that is genuinely new
Every door so far has been one person addressing an agent. A huddle is **several people, continuously**. That deserves its own rules.

**Consent is structural, not implied.** Buzz emits a signed participant-joined event, so everyone in the room can see the agent is present — that is a real affordance and the design should lean on it rather than a spoken disclaimer. An agent that cannot be seen to have joined should not be able to listen.

**What it hears is not automatically what it remembers.** By default the agent retains only **its own turns** — what it was asked and what it said — and never the raw transcript of everyone else's speech. Retaining the room's conversation is a separate, ratified decision, and even then it stays `local` tier: never published to relays, never in an export. An agent's episodic log is signed and portable, which is exactly why a multi-party conversation must not land in it by default.

**Leaving is as governed as joining.** When the last human leaves, the agent leaves. It never sits alone in a room with the microphone open.

**Budget.** A minute of huddle is a stream of small runs. The ceiling that matters is per-minute, not per-day, and I would put huddle turns on the **proactive lane** when the agent speaks unprompted and the responsive lane when it was addressed — the same distinction the allowance already draws.
## Latency
On the mini, everything is local: relay, agent, and (once installed there) the speech models. The pieces that already exist run at 1.2–2s end to end over a tunnel, so co-located should be meaningfully better. Sub-second is the target for "answers when addressed"; natural interjection is not the goal and should not be.

Buzz ships its own local voice primitives (`buzz-voice`: April ASR and a local TTS through sherpa-onnx/ONNX). Apiary has its own `transcribe` and `speak` slots. These should stay separate — Apiary's slots are ratified per agent — but Buzz's models are proof the machine can do this locally, and a sherpa-onnx provider for Apiary's slots is a reasonable way to avoid running two model stacks on one host.
## Build order
1. **Join and listen.** Presence adapter, NIP-42, WS connect, Opus decode, `level_dbov` gating, streaming transcription. The agent hears the room and says nothing. Proof: an accurate attributed transcript in the log of its own turns only.
  
2. **Speak when addressed.** Opus encode, one governed run per turn, turn ceiling, barge-in.
  
3. **Leave properly.** Lifecycle handling, last-human-leaves, budget accounting per session.
  
4. **Then judge whether it is good**, before adding anything clever.
  
## Open questions
- **Which agent?** The first candidate is whichever agent already has voice slots configured and a proven speak path.
  
    
    
- **Does the mini have the headroom** for a resident TTS model alongside the relay, Postgres, Redis, and the roastery stack? Worth measuring before committing to a local model rather than an API.
  
    
- **Does apiary-voice survive?** I would keep it: it is the right shape for 1:1 desktop dictation, and it is where the streaming and barge-in logic was worked out. The huddle path is for multi-party and mobile.
  
  