# Scope: errands — work that outlives the reply
You asked Hal for a press release draft. He said "I'll share it here shortly for your review." By morning he had no idea what "this" referred to, and could not have produced it anyway: a mention is one bounded run, and there is no later in which anything finishes.

Memory fixed the second half of that. This fixes the first.
## The mistake I was making
I described deferred work as blocked by _authority comes from the door_. That was wrong. When you said "give it a shot", a door opened and the work was authorized. Doing it three minutes after the reply instead of in the eight seconds before it does not change who authorized it.

What is missing is not a door. It is a way to **carry an authorization past the end of a run**.

> **An errand is a request still being fulfilled.** The mention is the door; the errand is that door staying open for the length of the work.
## Why nothing existing fits
- **A routine** requires ratification. Approving an amendment every time you ask for a one-off draft is absurd, and it trains the governor to rubber- stamp — the worst possible habit to build.
  
- **A watch** is event-triggered. Nothing in the world changed here; a person asked for something.
  
- **A longer run** is the obvious answer and the wrong one. You are waiting on a reply, the channel listener is blocked, and a mention that takes ten minutes to answer is broken even when it succeeds.
  
## The shape
During a run a person initiated, the agent may call `follow_up`:

```
follow_up(summary, task, deliver_to)
  summary   — one line, shown to the governor and repeated in the reply
  task      — what the agent will actually do, in its own words
  deliver_to— the channel and message this answers (defaults to the origin)
```

It writes an entry to `errands.json` beside the manifest and returns. The agent then finishes its reply — honestly, because now the promise is backed by a filed piece of work. The supervisor picks it up on the next tick, runs it as an ordinary governed run, and delivers the result to where it was asked.
## The rules that keep this from being a back door
**Only in response to a person.** An errand may be filed only during a run that a human initiated. Routine runs, watch runs, and errand runs cannot file them.

**An errand can never file an errand.** Without this, one request becomes an unbounded chain of self-authorized work. This is the most important rule here, and it is enforced by not binding the tool during an errand run rather than by asking the model to behave.

**Bounded three ways:**

- `max_pending` per agent — a person who asks for six things gets told the sixth will not happen, rather than discovering it silently didn't.
  
- A token ceiling per errand, like a routine's `tokens_per_run`.
  
- An expiry. An errand that has not run within its window is dropped with a note. Work requested an hour ago that fires at 3am is not helpfulness.
  

**Failure is reported, never swallowed.** Someone was promised something. If the run fails, that goes back to the channel where it was asked, in plain words. Silence after a promise is the worst outcome available.

**Same gates as everything else.** Ratified, unlocked, lease held, no overlap. An errand is not a privileged run.

**Visible and cancellable.** The cockpit shows what each agent owes and to whom: "press release draft · asked by Ryan 22:15 · not yet run". Cancelling is one click, and the channel is told.
## Honesty
Right now an agent is told it exists for one reply and must never promise future work. With errands that becomes:

> You may promise to do something later **only by filing it**. If you say you will send something and file nothing, you have lied to a person who is now waiting.

That is a better rule than "never promise", because the thing people actually want is for the promise to be kept.
## Budget
The debatable piece. An errand runs unattended, which is what the proactive lane exists to bound — but it was explicitly requested, and starving a requested draft because a watch had a busy morning is the wrong failure.

**Proposal: the responsive lane, with a hard per-errand ceiling and a low pending cap.** The bound comes from the ceiling and the cap rather than the lane. If this proves wrong in use, moving errands to the proactive lane is a one-line change.
## Implementation
An errand is close to a one-shot `at:` routine with delivery, minus ratification. Reuse the routines engine rather than growing a parallel one: same tick, same gates, same lease, same delivery path, same signed-log shape (`errand.filed`, `errand.run`, `errand.failed`, `errand.expired`).

Build order:

1. `errands.json` + the `follow_up` tool, bound only on human-initiated runs.
  
2. Supervisor pickup, delivery to origin, failure reporting.
  
3. Caps, expiry, and the cockpit view.
  
4. Live proof: ask Hal for a press release draft; get a reply that says it is coming; get the draft in the same channel a few minutes later; see the errand appear and clear in the cockpit.
  
## An errand may ask

An errand that gets stuck should ask, not fail. Questions are how real work
gets done — a colleague who silently abandons a task because they weren't
sure which product line you meant is worse than one who asks.

So an errand has four ends, not two: **delivered**, **asked**, **failed**,
**expired**.

```
pending → running → delivered
                  → asked      (question posted; waiting on a person)
                  → failed     (said out loud, in the channel)
                  → expired    (said out loud, with what it was)
```

**asked** posts the question into the originating conversation and parks the
errand. The next reply from the person who asked resumes it, carrying the
question and their answer — it does not start a fresh unrelated run.

Questions are also *cheaper* than the alternative. An agent that asks which
product line you meant spends one short exchange; an agent that guesses
spends a full draft and then spends another one redoing it. Focus buys more
than it costs.

The bounds that keep this from becoming an unmanaged conversation:

- **One open question at a time** per errand.
- **A question restarts the expiry clock but does not reset the ceiling** —
  an errand cannot buy itself unlimited life by asking repeatedly.
- **Ask about the work, not for permission.** "Which product line?" is a
  question. "May I proceed?" is the agent trying to hand its judgment back,
  and the trust position above says it shouldn't.

## Open questions
- **How soon is soon?** I would run errands on the next tick — deferred, not scheduled. If a person asks for something at 22:15 they want it at 22:16, not tomorrow.
  
- **Should an errand be able to ask a question back** when it gets stuck, or only report failure? Asking is friendlier and is also how an errand becomes a conversation the agent cannot manage. I lean: report, do not ask.
  
- **Does the governor approve errands?** I say no — approving each one recreates the ratification problem the primitive exists to avoid. The governor sets the caps; the person asking is the authorization.

## The larger direction this belongs to

The governor's framing, worth keeping in front of the next few pieces of
work:

> If an agent is going to be an active part of our workflow, it needs to be
> present and communicative. Agents ultimately need to be proactive, reactive
> and adaptive to their environment, skills and jobs, just like humans.

Errands are one leg of that — **reactive**, carried through to completion.
Watches are **proactive**. The missing leg is **adaptive**: an agent that
notices it lacks a skill, or that a skill it has is wrong for the work it
keeps being asked to do, and proposes the change.

That mechanism already half exists. `propose_amendment`, `propose_routine`
and `propose_agent` are exactly "the agent asks for a change to its own
shape, and a human approves." Self-adaptation is not a new subsystem so much
as an agent that reflects on its own track record and uses the tools it
already has — the agent works *with* the governor to change itself, rather
than either drifting on its own or staying frozen.

That makes one thing load-bearing: **a per-agent record of what changed and
why.** Not a diff buried in git, but a readable history — "gained the vault
write capability on the 14th, at its own request, because three drafts in a
row died on not being able to save." An agent that changes shape over months
without a legible account of why is one nobody can reason about.

What it would need:

- Something to reflect **on** — the signed log already holds every run, its
  outcome, and its cost.
- An occasion to reflect — a routine, or the review cadence of a standing
  intention.
- The discipline to propose rarely and specifically. An agent that proposes
  a new skill every week is noise; one that proposes a sharp change after a
  month of being asked the same unanswerable question is a colleague.

That is a separate scope. It is named here so the pieces are built to fit it.

## The question this raised: agent-to-agent communication

Extending an errand's budget, a steward keeping an eye on a colleague's
work, one agent assigning another its tools — all of these want agents to be able to
address each other directly, and right now they cannot. They can only reach
each other the way people do: by posting in a channel both are present in.

That is not obviously the wrong answer. It is legible, it is audited by
construction, and a human can read the exchange. A dedicated agent-to-agent
layer would be faster and would also be the first channel in this system that
no person is watching, which is exactly the kind of thing that should be
built deliberately rather than by accident.

Named here, not answered here. It deserves its own scope.
