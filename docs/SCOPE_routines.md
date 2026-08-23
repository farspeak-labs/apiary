# Scope: Routines — scheduled, governed runs

**Goal.** An agent does things on a schedule without a human present: a morning brief at 8:00, a weekly memory consolidation, a one-shot reminder at 15:00, an hourly check on something it watches. Every routine run is an ordinary governed run — same constitution, floors, budget, signed log — that happens to be triggered by the clock instead of a mention or a keypress. Nothing about the trust model changes; what changes is that **time becomes a fourth door**, and it is the only door with no human on the other side, so its authority has to come from ratification.

**One-line thesis.** A routine is a *standing instruction* the governor ratified once; the host replays it on schedule. It lives in the manifest (constitutional, portable, amendable), runs only where the agent's lease is held (one host, once), and delivers its result through the same channel machinery presence uses.

## What a routine is

```yaml
routines:
  - name: morning-brief
    when: "0 8 * * 1-5"                # cron (5-field), or `every: 30m`, or `at: 2026-08-17T15:00`
    tz: America/Chicago                # explicit; no host-local guessing
    task: |
      Look over the last 24 hours of your log and any mentions you answered.
      Give Ryan a short spoken brief: what happened, anything waiting on him.
    class: routine                     # task_class for routing (rules can send routines to a cheap slot)
    deliver:
      - telegram: "1479516122"         # reply text (voice per reply_as) to a chat the agent may address
        as_voice: true
    budget:
      tokens_per_run: 8000             # per-run ceiling within the day's cap
    catch_up: one                      # none | one — a missed fire (host asleep) runs once on wake
    enabled: true                      # governor toggle; also pausable host-locally without amendment
```

- **`task`** is the instruction. It is written by a human (or drafted by the agent — see below) and ratified with the manifest, so a chat mention cannot plant one. When the run executes, `task` is the operator text; anything the run *reads* (log, vaults, tool results) is DATA as always.
- **`when`** — three spellings, one field: a 5-field cron expression; `every: <duration>` (`15m`, `2h`, `1d`); `at: <ISO datetime>` for one-shots (auto-disables after firing). `@hourly`/`@daily`/`@weekly` aliases accepted. `tz` is required for cron and `at` (a portable agent must not fire at the wrong hour because it moved hosts).
- **`deliver`** — where the reply goes. Targets are the surfaces the agent already has: `telegram: <chat_id>` (gated by that presence's `allowed_chats`), `buzz: <channel>`, `nostr: publish` (needs the nostr-publish connector), `companion: true` (spoken by apiary-voice — see below), or none (log only — the run itself is the deliverable, e.g. a vault write). Delivery uses the same `send_reply` / connector paths as presence and `telegram_send`, so it inherits their allowlists and their `reply_as`/voice behavior.
- **`budget.tokens_per_run`** clamps the reservation for this routine (default: MAX_RESERVATION). A routine that overruns is refused like any run, and the refusal is logged. Routines draw from the same `tokens_per_day` as everything else — a chatty routine can starve the agent's conversations, which is a governance choice made visible in the spend meter (per-routine spend shown).
- **`catch_up`** — `none`: a missed fire is skipped; `one` (default): fire once on wake, never replay a backlog. Nothing ever fires twice for the same slot.

## Where it runs, and how many times

**Exactly one host, at most once per slot.** Routine scheduling rides the existing per-agent lease keeper: only the host holding the agent's lease evaluates schedules. A contested or lost lease means no fires here — same rule as presence, same visibility in the Lease panel. Two desktops with the same imported agent do not both send the morning brief.

**Never overlapping.** A routine that is still running when its next fire arrives skips that fire (logged as `routine.skipped: overlap`). Runs are the runner's bounded loop (8 tool iterations, reservation-clamped output), so "still running" is minutes at most.

**Host-local state.** `routines.json` in the agent dir: per routine `last_fired`, `last_outcome`, `next_fire`, `paused`. Like `spend.json` and `active`, it does not travel with the agent — the schedule (constitutional) travels; the bookkeeping is the host's. Import → next fires computed fresh; `catch_up` never reaches back before import.

**Ratification gate, unlock gate.** Unratified manifest → no routines fire (they are amendments like any other). Locked keystore → nothing fires; the supervisor notes it exactly as it notes presence ("locked — routines paused") so a routine silently not firing is never a mystery.

**Jitter.** ±0–20s on every fire so ten agents on one host with `0 8 * * *` do not hit the provider at once.

## The signed record

Every fire writes a `routine.run` entry (self tier) with `{routine, scheduled_for, fired_at, outcome, log_event of the run}` and delivery results (`delivered: [{telegram: chat, message_id | error}]`). Skips and refusals are entries too (`routine.skipped` with the reason: overlap, locked, lease-not-held, budget). The Log tab shows them; the Routines tab shows the last N per routine. What ran, when, why not — in the record, not in a daemon log.

## Who may author a routine

- **Governors** add/edit routines as manifest amendments (cockpit form or YAML), then ratify. Standard.
- **The agent may draft one** ("I could send you this every morning — shall I?"): a proposed amendment written to `manifest.proposed.yaml`, surfaced in the cockpit as *pending your ratification*, never active until a governor ratifies. Same shape as any agent-authored amendment; nothing new to trust. This is the honest answer to "can the agent schedule things for itself" — yes, subject to the same signature it needs for everything else.
- **Never**: a routine created from a chat mention, a tool result, or a vault note. `task` text is instructions; the only path to instructions is ratification (or the operator door, which is a human at a keyboard — see companion below).

## Host surface

- **hostd**: `GET /api/agents/{npub}/routines` (schedule + host state + last runs), `POST …/routines/{name}/run` (fire now — governor, operator door), `POST …/routines/{name}/pause|resume` (host-local, no amendment). Routine amendments go through the existing manifest PUT + ratify.
- **Supervisor**: the 10s tick gains a `reconcile_routines(agent)` — cheap: compare `next_fire` to now for each enabled routine, fire in a blocking task, update `routines.json`. Cron parsing via the `cron` crate (5-field + aliases) with `chrono-tz`.
- **CLI**: `apiary routine list|run|pause|resume <npub> [name]`; `apiary routine add` writes the amendment (then `agent ratify`).
- **Cockpit**: a Routines tab — table (name, when, next fire in human words, last outcome, delivered where), Run now / Pause, an add form (name, when with a live "next 3 fires" preview, tz picker, task, deliver targets drawn from the agent's presence + connectors), and the pending-proposal banner. Help text says plainly: *routines are ratified instructions that run without you; keep them small and bounded.*

## The companion as a delivery target

`deliver: [{companion: true}]` means: when this fires, the human's apiary-voice should *say it*. Mechanism: hostd gains an SSE `GET /api/events` (governor/operator auth) that broadcasts host-level events — `routine.delivered`, later `mention.answered` etc. — and apiary-voice subscribes while running, speaking `companion` deliveries and showing them in the HUD (thin bar: "agent · morning brief ▸"). If no companion is connected, the delivery is logged as `undelivered: no companion` and, if the routine also names a chat, that copy still goes. This is the "morning brief spoken at 8:00 while you make coffee" case, and it costs one small endpoint. Not a push notification system; a live subscription.

## Non-goals, stated so they stay out

- **Event triggers other than time** (webhooks, file watchers, "when X happens"). Webhook-fired routines are a natural extension — `POST …/routines/{name}/run` already is one, governor-authed — but arbitrary triggers are how a routine becomes an attack surface. Time and an authenticated operator only, for now.
- **Sub-minute schedules.** Minimum `every: 1m`. Anything faster is a job, not a routine.
- **A workflow engine.** No routine-calls-routine, no DAGs, no retries-with-backoff beyond `catch_up: one`. A routine is one governed run. If it needs to be several, the agent's tool loop is the several.
- **Backlog replay.** `catch_up: one` at most. A host that was off for a week runs the morning brief once, not seven times.
- **Cross-agent scheduling.** A routine belongs to one agent; if two agents should coordinate, that is a mention between them on Buzz, not a shared schedule.

## Sequence

1. Manifest: `routines:` schema (validation: cron/every/at exclusive; tz required unless `every`; deliver targets must reference declared presence/connectors) + `routines.json` state. Cron + tz crates.
2. Supervisor `reconcile_routines`, lease-gated, overlap-guarded, jittered; `routine.run`/`routine.skipped` log entries; delivery via `send_reply` and connectors.
3. hostd endpoints + CLI. Cockpit Routines tab with next-fire preview.
4. `GET /api/events` + apiary-voice subscription + `companion` delivery.
5. Agent-drafted proposals (`manifest.proposed.yaml` + cockpit banner) — reuse for any agent-authored amendment.

Live proof: an agent's `morning-brief` at a near-future minute, delivered to Telegram as af_heart voice and spoken by the companion, both in the signed log; a deliberately overlapping second routine skipped and logged; a paused routine not firing; the same agent imported into a second home firing nowhere while the first holds the lease.
