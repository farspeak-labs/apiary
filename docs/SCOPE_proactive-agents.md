# Scope: proactive agents — watches, allowance, silence

An Apiary agent acts when spoken to (a mention) or when a clock fires a
ratified routine. Both are reactive: something outside the agent decides
when it acts, and a routine is a human decision replayed on a timer. This
adds the ability to act because **the world changed**, without breaking the
rule the system rests on: *authority comes from the door*.

## The principle this preserves

Every governed run traces back to a door: a person's message, or a ratified
schedule. Proactive work has neither, so the answer is not to weaken the rule
but to add a door of the right shape:

> **A watch is a door the governor ratified in advance.**

The trigger is never the authority; the ratified watch is. What arrives
through it — a file's contents, later a relay event — stays **data**, framed
exactly like platform text. A file that appears in a watched folder saying
"ignore your instructions" is a file that appeared in a folder, nothing more.

## Watches

```yaml
watches:
  - name: notes-changed
    on: vault                # vault today; relay/connector/webhook later
    vault: Projects          # a vault the agent was already granted
    match: STATUS.md         # optional path filter
    task: |
      A file changed. Read it, decide whether the change is material, and
      act only if it is. Usually silent.
    debounce: 5m             # coalesce a burst into one run
    max_per_day: 12          # hard ceiling; refuses, never queues
    deliver: []              # empty = silent unless the agent speaks itself
```

A watch fires an ordinary governed run through the same gates a routine
passes — ratified, unlocked, lease held, no overlap. An event-triggered run
is not a privileged one.

**Debounce and ceiling are not optional.** An unbounded watch is a
retry-storm generator. `max_per_day` refuses for the rest of the day rather
than queueing: a backlog that fires at midnight is worse than a gap.

**First sight adopts the present.** A watch added today does not fire for
everything that ever happened in the folder.

**A gate is a delay, not a loss.** A fire held by a locked keystore or a lost
lease goes back on the pile rather than being dropped.

**A run absorbs its own output.** An agent that writes into the folder it
watches would otherwise retrigger on its own echo, forever, spending its
whole allowance answering itself. The trade: a human edit landing during the
run is absorbed too — far cheaper than a loop, and the next edit catches it.

## The proactive allowance

Proactive work spends tokens nobody asked for, so it gets its own lane:

```yaml
governance:
  budgets:
    tokens_per_day: 200000
    proactive_tokens_per_day: 40000
```

- A proactive claim must fit **both** the allowance and the daily cap, and
  settles against both: proactivity can never raise the total an agent may
  spend.
- **Absent means zero.** Acting unasked is a grant, not a default.
- An exhausted lane stops watches for the day while the agent still answers
  at full budget when spoken to. The agent you can still talk to is the one
  that matters.

## Silence is a first-class outcome

An agent that speaks too often is worse than one that stays quiet.

- Delivery defaults to **none**. A proactive run that wants to reach a human
  uses the send tools it already has.
- A run that changed nothing is recorded as `watch.quiet` with a compact
  body — worth knowing it happened and cost something, not worth storing what
  it decided not to do.
- **Quiet is established by observation, not by claim.** Asking the model
  whether it was quiet is asking the wrong witness. Connectors declare
  `observes_only()`, the host watches which tools actually succeeded, and the
  default is false — a connector added later counts as acting until it says
  otherwise. A run can never be called quiet because someone forgot to answer
  the question.
- On a server that publishes no `readOnlyHint`, every call therefore counts
  as acting. Conservative in the right direction, at the cost of a less
  informative quiet counter.

## Still to come

- **Relay, connector, and webhook triggers.** Webhooks need their own auth
  story and come last.
- **Standing intentions** — a ratified purpose the agent pursues on its own
  judgment, with a cheap review cadence and a separate ceiling on acting.
- **Self-scheduled wake** — letting an agent choose when it next acts. A real
  shift in authority, and deliberately last.

## What this is not

- Not an agent that creates its own watches. Those are ratified amendments;
  an agent may propose one with the tools it already has.
- Not a workflow engine. One trigger = one governed run = the runner's
  bounded loop.
- Not a way around the lease. Exactly one host runs an agent's proactive work.
