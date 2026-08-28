# Scope: a builder — an agent that improves Apiary

The stated goal: *make an agent in Apiary into an agent that builds and
improves on Apiary autonomously.*

Every piece this needs already exists. `harnesses` in the manifest grants a
real coding loop (Claude Code, Goose, Codex) over ACP, with a `workdir`, an
OS sandbox, a profile, and permission requests routed back to host policy
rather than answered by the model. Watches give it an occasion to notice.
Errands give it work that outlives a reply. `propose_amendment` and its
siblings are already "the agent asks; a human approves." The signed log is
already the record of what it did and what that cost.

So this is not a new subsystem. It is a manifest, a working copy, and a
short list of rules about the one thing that makes this agent different
from every other agent in the system: **its output is the code that runs
it.**

## The one hazard that is not like the others

Every other agent here acts on the world. This one acts on the host. Three
specific ways that goes wrong, in the order they will actually happen:

**It breaks the host and cannot report that it did.** Ordinary agent
failure is legible because the host survives to log it. A builder that
lands a bad change into a running daemon takes the logger down with it.
That is why deploying is not in scope for the agent — see below.

**It edits its own governance.** `suspend_keys`, the spend ceilings, the
section-access floors, `humanProcedure` — these are code. An agent with
write access to the repository can write a patch that loosens them, and
the patch would look like every other patch. This is not paranoia about
intent; it is that a model asked to "make the tests pass" will delete an
assertion, and some of those assertions are the governor's.

**It optimizes the thing it is measured by.** Told to reduce failures, the
cheapest patch is to stop recording failures. The log is its own subject
matter here in a way it is for no other agent.

None of these is solved by asking it not to. They are solved by where the
work lands.

## The shape

The builder never changes anything that is running. It produces **branches
and pull requests, in a clone that is not the deployed tree**, and a human
merges. That is the whole safety design, and everything else is detail.

```
  a signal ──▶ an intention ──▶ a branch ──▶ a PR ──▶ a human merges
  (log, human,   (one sentence,   (worktree,   (tests
   watch)         governed)        sandboxed)    ran)
```

**Working copy.** A dedicated clone (`~/builder/apiary`), granted as the
harness `workdir`, with `sandbox: no-network` so a coding loop cannot
reach the relay, the keystore, or the internet mid-edit. The deployed tree
and `~/.apiary` are not reachable from it. The builder is an ordinary
contributor with a checkout, not an operator with a shell.

**Where work comes from.** Two sources, both narrow:

1. A human files it — in the channel, which is already the door. "The
   connectors page reloads on every keystroke, fix it."
2. Its own reading of the record. A weekly routine over the log: what
   refused, what errored repeatedly, what a supervisor note has been
   complaining about for a week. This is the *adaptive* leg named at the
   end of SCOPE_errands, and the log is the only honest input for it.

Not: "look for things to improve." An agent given an unbounded mandate to
improve a codebase produces volume, and volume is what makes review stop
happening — which quietly removes the one gate this design rests on.

**One branch at a time.** The pending cap that errands have, for the same
reason. A reviewer with six open PRs from a bot reviews none of them
properly.

**The tests are the gate, not the model's account of the tests.** The
build and the suite run in the harness; the *host* records the exit code
into the log. "I ran the tests and they pass" is a claim; a recorded exit
status is a fact. This distinction is the whole difference between a
colleague and a plausible one.

**A change arrives with its reason.** The PR body says which log entries
prompted it. A patch nobody can trace back to a real failure is a patch
nobody should merge.

## What it must not have

- **No deploy.** Not `scripts/deploy.sh`, not `launchctl`, not the ability
  to restart `apiary-hostd`. An agent that can restart its own host can
  silence its own governor, and would not need to intend to.
- **No credentials.** No provider keys, no keystore, no `~/.apiary`. It
  writes code; code does not need secrets to be written.
- **No network from the harness.** It reads the repository it was given.
  Docs research is a separate, ordinary `web-fetch` grant on the *agent*,
  not a hole in the coding sandbox.
- **No write access to its own manifest.** It proposes, like everything
  else. `propose_amendment` already lands in the governor's queue.

That last one has an edge worth naming: it *can* propose a patch that
edits `manifest.rs` — the code that validates manifests. That is a real
path around the proposal gate, and it is not closable by permissions. It
closes at review, which is one more reason the volume cap matters more
here than anywhere else.

## Honesty about "autonomously"

It will be autonomous in the loop and supervised at the boundary — the
same trade the whole system makes. It notices, decides, writes, tests, and
opens a PR without anyone present. It does not merge and it does not
deploy.

I do not think that is a compromise on the goal. The bottleneck in
improving Apiary is not typing; it is knowing which change is worth making
and whether it worked. An agent that reliably turns "this failed eleven
times last week" into a tested branch with an argument attached is doing
the part that is actually slow.

## Build order

1. **The working copy and the grant.** Clone, `harnesses` entry with
   `workdir` + `no-network` sandbox, curated permission mode. Prove it can
   read the tree and run `cargo test` with the exit code landing in the
   log.
2. **One human-filed change, end to end.** Ask it in the channel for
   something small and real; get a branch and a PR back through an errand.
   This is the whole loop, and it either works or it does not.
3. **The record-reading routine.** Weekly, over its own host's log:
   propose at most one thing, with the entries that motivated it.
4. **The change history.** The readable per-agent account named in
   SCOPE_errands: what changed, when, at whose request, and why. For this
   agent it is not optional — a builder without a legible history of its
   own changes is exactly the thing nobody can reason about.

## Open questions

- **Which repository?** Apiary itself is the stated target. Buzz is the
  other obvious one and is a better *first* target: a bug there cannot
  take down the host doing the work. I lean Buzz for step 2 and Apiary
  from step 3.
- **Does it review other agents' proposals?** It is the agent best placed
  to, and that makes it a second gate that is not a person. I lean no,
  until the first ten of its own PRs have been reviewed by a human and
  found sound.
- **What happens when it lands something that breaks the host?**
  `docs/RECOVERY.md` covers a broken daemon. It should be linked from the
  builder's constitution, because it is the one runbook the builder's own
  work makes more likely to be needed.
- **Does a builder deserve a bigger allowance?** Coding runs are long.
  Probably yes, and it should come with a hard per-branch ceiling rather
  than a raised daily cap — the failure mode is one runaway session, not
  steady overuse.
