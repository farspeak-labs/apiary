# Scope: Multi-channel presence + the Channel Plugin Protocol
**Goal.** An agent works through many communication platforms simultaneously — Buzz, Telegram, and anything the community builds — under one lease, one budget, one signed log, one governed run path. Channels are pluggable: some built in, some installed.
## The plugin thesis
Apiary already hosts two plugin standards, deliberately not invented here:

| Surface | Standard | Who defines it |
| --- | --- | --- |
| Tools / capabilities | **MCP** (2026-07-28 client, both eras) | industry |
| Foreign harnesses | **ACP** | industry |
| **Standing presence** | **Channel Plugin Protocol (**`apiary-channel/1`**)** | **this spec** |

Inbound presence — living on a platform and answering when spoken to — has no industry standard. That is the one protocol Apiary authors. Everything else about plugins stays borrowed and boring: subprocesses over stdio JSON-RPC with newline framing (the MCP stdio framing, reused per that spec's own guidance), scrubbed environments, host-side governance.
## Architecture
**One trait, two homes.** `ChannelAdapter` (connect → next_mention → reply) is the internal seam. Built-in channels (buzz, telegram) implement it in-process; installed plugins implement it out-of-process via the protocol below, driven by a generic `PluginAdapter`. One registry lists both: `PRESENCE_KINDS` = built-ins + whatever `plugins.yaml` declares.

**One generic loop.** `run_presence` replaces the buzz-specific service: log the mention (`{kind}.mention`, self tier), frame the message as DATA from an untrusted platform member, run through the governed path (budget, floors, checkpoints), reply through the adapter. Platform quirks live in adapters; governance never does.

**One lease per agent, all channels.** The lease stops being buzz-internal: a per-agent lease keeper claims and heartbeats once, and every channel thread for that agent lives or dies with it. Contested start blocks ALL channels; a takeover yields ALL channels. The supervisor reconciles per (agent, channel): registry keyed `(npub, kind)`.
## Manifest: presence becomes a map
```yaml
presence:
  buzz:
    relay: wss://relay.example.com      # config keys are per-kind
  telegram:
    credential: <nip44-sealed bot token> # sealed to the agent, as ever
    allowed_chats: ["123456789"]
  discord-community-plugin:              # an installed plugin, same shape
    credential: <sealed token>
    guild: "…"
```

Every entry: optional sealed `credential` + kind-specific config. Existing `presence.buzz` manifests parse unchanged (`relay`/`trigger` are just config keys now). Declaring a channel stays constitutional — where the agent lives is ratified, per channel.
## The Channel Plugin Protocol (`apiary-channel/1`)
A plugin is an executable. The host spawns it (env_clear + allowlist, the MCP/ACP hygiene) and speaks newline-delimited JSON-RPC 2.0 on stdio:

1. `initialize {protocol: "apiary-channel/1", config, credential?}` → `{name, kind, triggers?}`. The host opens the sealed credential and passes plaintext HERE, at the instant of use — the plugin never sees the keystore, the manifest, or any other agent's material.
  
2. `poll {timeout_ms}` → `{mentions: [{ref, channel, author, text}]}` — long-poll; empty list is a tick (the host heartbeats the lease between polls).
  
3. `reply {ref, text}` → `{id}`.
  
4. `shutdown` (notification) → process exits; host escalates to kill.
  

Rules: stdout is protocol-only, stderr is free logging, one JSON-RPC message per line. The host enforces everything that matters — budgets, provenance framing, logging, lease — so a buggy or malicious plugin can spam its own platform at worst; it cannot exceed the agent's constitution, touch credentials it wasn't handed, or bypass the spend ledger.

**Trust model, stated plainly:** installing a plugin is installing code, host-trusted like an MCP server. The protocol confines what it's _given_, not what it _is_. The env scrub + credential-at-initialize design keeps the blast radius to the one platform the plugin serves.
## Installation
Host-scoped `<home>/plugins.yaml` (sibling of `connectors.yaml`):

```yaml
plugins:
  - name: discord-community-plugin
    protocol: apiary-channel/1
    command: /usr/local/bin/apiary-discord
    args: []
```

GUI: managed beside the host connector library. A manifest may declare a plugin kind the host hasn't installed — the supervisor reports "channel declared but not installed" and starts everything else (per-channel failure never blocks sibling channels).
## Built-ins in this build
- **buzz** — refactor of the existing service onto the trait, behavior- preserving (loop guards, causal timestamp floor, channel discovery).
  
- **telegram** — Bot API long-poll (`getUpdates`/`sendMessage`, no inbound port): sealed bot token, `allowed_chats` allowlist (default-deny — the manifest decides who may engage the agent, not whoever finds the bot), DMs and @-mentions trigger, replies threaded. Telegram never delivers bot messages to bots, so Buzz's ping-pong guard is structurally unnecessary here.
  
- **slack** — Socket Mode (`apps.connections.open` → WebSocket the CLIENT
  opens; no inbound port, same posture as Telegram long-poll — and we
  already carry tungstenite). Two Slack credentials travel as ONE sealed
  JSON blob ({app_token, bot_token}): the app token opens the socket, the
  bot token replies via `chat.postMessage`. Triggers: `app_mention` events
  and DMs; optional `allowed_channels` cap; replies threaded. Events are
  acked by envelope id; Slack retries unacked events, which the mention
  log entry makes idempotent.

- **reference plugin** — a mock channel shipped as a test binary AND a ~40-line commented example in the spec doc, so "write a plugin" has a copyable answer.
  
## Surface changes
- Supervisor + registry: per (npub, kind); lease keeper per agent; amendment-bounce and activation semantics unchanged, now spanning channels.
  
- Listener API: status returns a channels map (+ lease keeper state); start/stop take a channel kind (default buzz, for compatibility).
  
- GUI: Overview presence section lists every declared channel with live per-channel status; Telegram declare form (paste token → sealed → manifest → re-ratify) with allowlist editing; plugins list beside the host connector library. The Buzz tab keeps its workspace operations (channels, profile, posting).
  
- CLI: `apiary buzz listen` unchanged; plugin/telegram presence runs under the daemon/app supervisor (that's what supervision is for).
  
## Tests & live proof
- Unit: mock-channel plugin round trip over real subprocess stdio; trigger/allowlist logic for telegram (crafted update JSON); presence map manifest migration (old buzz manifests parse).
  
- Live: one agent on Buzz + Telegram + the reference plugin SIMULTANEOUSLY — one lease, three channels, replies on each through the governed path; kill one channel (it restarts alone); deactivate (all stop); contested lease blocks all three on a second host.
  
- Telegram's live leg needs a BotFather token (requested when we get there; everything else proves without it).
  
## Out of scope (named follow-ups)
1. Connector-side plugins — MCP already is that standard, and **Apiary
  ships full MCP support today** (commit `fb5c33e`: 2026-07-28 client with
  legacy fallback, stdio + Streamable HTTP, OAuth grants, `mcp` connector
  kind, live-proven against a real server). Revisit only if a capability
  genuinely doesn't fit MCP.
  
2. Plugin distribution/registry (install = drop a binary + one yaml entry for now); signing/verification of plugin binaries.
  
3. WASM-sandboxed plugins (the protocol is transport-shaped for it later).
  
4. Outbound-anytime messaging connectors (agent initiates, not replies).
  
## Estimate
Presence engine + manifest map + buzz refactor ≈ half day; telegram +
slack adapters + plugin protocol/adapter + spec + reference plugin ≈
half day+; supervisor/API/GUI + proofs ≈ half day. A long full-day build.

---
comments:
  c1:
    body: Added — slack is the third built-in, via Socket Mode (client-opened WebSocket, no inbound port; app_token + bot_token sealed as one blob). Estimate bumped accordingly.
    by: AI
    at: "2026-08-16T00:30:00.000Z"
    re: s1
  c2:
    body: Yes — full MCP support shipped in fb5c33e (2026-07-28 client + legacy fallback, stdio + Streamable HTTP + OAuth, mcp connector kind, live-proven). The doc now states it explicitly.
    by: AI
    at: "2026-08-16T00:30:30.000Z"
    re: s2
