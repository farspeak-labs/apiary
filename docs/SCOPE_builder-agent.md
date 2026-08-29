# Scope: a builder — an agent that improves Apiary
The stated goal: _make an agent in Apiary into an agent that builds and improves on Apiary autonomously._

Every piece this needs already exists. `harnesses` in the manifest grants a real coding loop (Claude Code, Goose, Codex) over ACP, with a `workdir`, an OS sandbox, a profile, and permission requests routed back to host policy rather than answered by the model. Watches give it an occasion to notice. Errands give it work that outlives a reply. `propose_amendment` and its siblings are already "the agent asks; a human approves." The signed log is already the record of what it did and what that cost.

So this is not a new subsystem. It is a manifest, a working copy, and a short list of rules about the one thing that makes this agent different from every other agent in the system: **its output is the code that runs it.**
## The one hazard that is not like the others
Every other agent here acts on the world. This one acts on the host. Three specific ways that goes wrong, in the order they will actually happen:

**It breaks the host and cannot report that it did.** Ordinary agent failure is legible because the host survives to log it. A builder that lands a bad change into a running daemon takes the logger down with it. That is why deploying is not in scope for the agent — see below.

**It edits its own governance.** `suspend_keys`, the spend ceilings, the section-access floors, `humanProcedure` — these are code. An agent with write access to the repository can write a patch that loosens them, and the patch would look like every other patch. This is not paranoia about intent; it is that a model asked to "make the tests pass" will delete an assertion, and some of those assertions are the governor's.

**It optimizes the thing it is measured by.** Told to reduce failures, the cheapest patch is to stop recording failures. The log is its own subject matter here in a way it is for no other agent.

None of these is solved by asking it not to. They are solved by where the work lands.
## The shape
The builder never changes anything that is running. It produces **branches and pull requests, in a clone that is not the deployed tree**, and a human merges. That is the whole safety design, and everything else is detail.

```
  a signal ──▶ an intention ──▶ a branch ──▶ a PR ──▶ a human merges
  (log, human,   (one sentence,   (worktree,   (tests
   watch)         governed)        sandboxed)    ran)
```

**Working copy.** A dedicated clone (`~/builder/apiary`), granted as the harness `workdir`. The builder is an ordinary contributor with a checkout, not an operator with a shell.

**Correction, found while building this.** An earlier draft said `sandbox: no-network`, "so a coding loop cannot reach the relay, the keystore, or the internet mid-edit". That is not available: the sandbox profile is `(deny network*)` applied to the whole harness process, and a coding harness that cannot reach a model cannot run at all. `read-only` is equally out — the builder's entire job is writing files. So the coding harness runs with `sandbox: none`, and the isolation that actually holds is:

- **`profile: isolated`** — a per-agent `HOME` under `.apiary-harnesses/`, so the host user's credentials, global agents, and extensions are not in scope. The builder logs its harness in once, into its own profile, and that login is its own.
- **No key material anywhere near it.** Custody never enters a harness environment; `~/.apiary` is not its workdir and its secrets are not in its env. It has network but nothing worth sending.
- **The clone, the merge gate, and no deploy** — the three that were doing the real work all along.

Worth being blunt about the residual: a coding loop with network and file-write in a checkout can, in principle, reach the internet. What stops that from mattering is that it holds no secret and its output is reviewed before it runs anywhere. If that stops being enough, the fix is a network sandbox with an allowlist for the model endpoint, which the current profiles cannot express.

**Where work comes from.** Two sources, both narrow:

1. A human files it — in the channel, which is already the door. "The connectors page reloads on every keystroke, fix it."
  
2. Its own reading of the record. A weekly routine over the log: what refused, what errored repeatedly, what a supervisor note has been complaining about for a week. This is the _adaptive_ leg named at the end of SCOPE_errands, and the log is the only honest input for it.
  

Not: "look for things to improve." An agent given an unbounded mandate to improve a codebase produces volume, and volume is what makes review stop happening — which quietly removes the one gate this design rests on.

**One branch at a time.** The pending cap that errands have, for the same reason. A reviewer with six open PRs from a bot reviews none of them properly.

**The tests are the gate, not the model's account of the tests.** The build and the suite run in the harness; the _host_ records the exit code into the log. "I ran the tests and they pass" is a claim; a recorded exit status is a fact. This distinction is the whole difference between a colleague and a plausible one.

**A change arrives with its reason.** The PR body says which log entries prompted it. A patch nobody can trace back to a real failure is a patch nobody should merge.
## What it must not have
- **No deploy.** Not `scripts/deploy.sh`, not `launchctl`, not the ability to restart `apiary-hostd`. An agent that can restart its own host can silence its own governor, and would not need to intend to.
  
- **No credentials.** No provider keys, no keystore, no `~/.apiary`. It writes code; code does not need secrets to be written.
  
- **No network from the harness.** It reads the repository it was given. Docs research is a separate, ordinary `web-fetch` grant on the _agent_, not a hole in the coding sandbox.
  
- **No write access to its own manifest.** It proposes, like everything else. `propose_amendment` already lands in the governor's queue.
  

That last one has an edge worth naming: it _can_ propose a patch that edits `manifest.rs` — the code that validates manifests. That is a real path around the proposal gate, and it is not closable by permissions. It closes at review, which is one more reason the volume cap matters more here than anywhere else.
## Honesty about "autonomously"
It will be autonomous in the loop and supervised at the boundary — the same trade the whole system makes. It notices, decides, writes, tests, and opens a PR without anyone present. It does not merge and it does not deploy.

I do not think that is a compromise on the goal. The bottleneck in improving Apiary is not typing; it is knowing which change is worth making and whether it worked. An agent that reliably turns "this failed eleven times last week" into a tested branch with an argument attached is doing the part that is actually slow.
## Build order
1. **The working copy and the grant.** Clone, `harnesses` entry with `workdir`, `profile: isolated`, curated permission mode, `tokens_per_day: 1_000_000` with a hard per-branch ceiling, and a Buzz DM target for the alarm. Prove it can read the tree and run `cargo test` with the exit code landing in the log.

   Three prerequisites the host does not have yet, all named here because each is a decision rather than a chore: an **ACP coding harness** (only Goose is discovered today; Claude Code is an inference provider here, deliberately tool-less, so using it as the loop means an ACP adapter), a **Rust toolchain** on the host that will run the tests, and the harness's **own login** in its isolated profile.
  
2. **One human-filed change, end to end, on Apiary.** Ask it in the channel for something small and real; get a branch and a PR back through an errand. This is the whole loop, and it either works or it does not.
  
3. **The record-reading routine.** Weekly, over its own host's log: propose at most one thing, with the entries that motivated it.
  
4. **The change history.** The readable per-agent account named in SCOPE_errands: what changed, when, at whose request, and why. For this agent it is not optional — a builder without a legible history of its own changes is exactly the thing nobody can reason about.
  
## Decisions

Reviewed and approved 2026-08-29. Four questions were open; all four came
back against my lean, and the reasoning is worth keeping next to the
answers.

**The target is Apiary itself — self-evolving.** I had leaned toward Buzz
first, on the grounds that a bug there cannot take down the host doing the
work. That caution is already spent elsewhere: the builder edits a clone,
never the deployed tree, and it cannot deploy. Pointing it at Buzz would
have bought a little safety by aiming it away from the actual goal. So:
Apiary, from step 2.

This makes one thing above load-bearing rather than merely sensible. The
working copy is a **clone**, and the running daemon is upgraded by a human
running `scripts/deploy.sh` against a merged main. A builder whose patch
is wrong produces a red PR, not a dead host.

**It reviews other agents' proposals.** I had leaned no — a reviewing
builder is a second gate that is not a person, and gates that are not
people are how review quietly stops happening. Decided the other way, so
the shape has to carry the concern instead:

- It reviews by **commenting**, never by approving or merging. A human
  still merges; the builder's review is an input to that person, not a
  substitute for them.
- Its comments say what it checked and what it could not. "Tests pass" and
  "I read this and it looks reasonable" are different claims and must not
  arrive in the same voice.
- It never reviews its own proposals. That is not a rule it is told; it is
  a filter on which proposals it is handed.

**It DMs the governor on Buzz when its work breaks the host.** This is the
case with no other reporting path — a bad change that takes the daemon
down takes the log and the cockpit with it, so the notification has to
leave the host to be worth anything. A direct message, not a channel post:
this is the one class of event that should interrupt a person.

Concretely: a failed build or a failed suite on the builder's own branch
delivers to a Buzz DM, and `docs/RECOVERY.md` is linked in the builder's
constitution so the runbook is one hop from the alarm. The delivery uses
the ordinary `deliver` path, so a DM that cannot be sent is recorded as
undelivered rather than lost.

**One million tokens a day, with a hard per-branch ceiling.** Coding runs
are long and a builder starved mid-refactor produces worse than nothing —
a half-applied change. The bound that matters is per-branch, not per-day:
the failure mode is one runaway session, not steady overuse. So the daily
cap is generous and the per-run ceiling is the real fence.

## Still open

- **What does the builder do while waiting for review?** With one branch
  at a time and a human in the loop, it will spend most of its life
  blocked. Idle is the correct answer and an unsatisfying one; the honest
  version is that its throughput is bounded by review, and pretending
  otherwise just means more unreviewed PRs.
- **Who reviews the builder's review?** Its comments on other agents'
  proposals are unbounded output that nobody is obliged to read. If they
  turn out to be noise, that shows up as reviewers skimming past them, and
  the fix is to narrow what it is handed rather than to ask it for better
  comments.
