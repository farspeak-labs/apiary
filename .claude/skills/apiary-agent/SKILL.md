---
name: apiary-agent
description: Create, configure, and troubleshoot an Apiary agent end to end — found the identity, write and validate the manifest, get it ratified and active, make it reachable on Buzz or Telegram, grant capabilities with least privilege, and give it a coding harness. Use when creating a new Apiary agent, amending an existing one, or diagnosing an agent that is founded but not answering, not listening, not ratifiable, or has no tools.
user-invocable: true
---

# Creating an Apiary agent

An agent is four things, in this order: **an identity** (a nostr keypair in
the host keystore), **a manifest** (the contract — what it may do, spend, and
reach), **a ratification** (a human signs that contract), and **a way to be
reached** (presence). Miss any one and it looks founded but does nothing.

Most failures here are silent — the agent exists, the cockpit shows it, and
it simply never works. The gotchas section is the point of this skill; read
it before debugging.

## Before you start

Know the host you are working on. The commands below assume the daemon's
state directory (`~/.apiary`) and the `apiary` CLI on the same machine. On a
remote host, ship the CLI first — the binary must match the daemon's version,
or manifest fields the daemon understands will fail validation:

```bash
cargo build --release -p apiary-cli
scp target/release/apiary <host>:/tmp/apiary-cli
```

**The passphrase must be the workspace's.** Never type a remembered one.
Read it from the host's own unlock file so it cannot be wrong, and never
print it:

```bash
APIARY_PASSPHRASE="$(cat ~/.apiary/headless-unlock)" apiary agent new ...
```

## 1. Found the identity

```bash
APIARY_HOME=~/.apiary APIARY_PASSPHRASE="$(cat ~/.apiary/headless-unlock)" \
  apiary agent new --name <Name> --suspend-key <governor-npub>
```

The suspend key is the governor: a person (or a separate manager agent) who
can suspend this agent. It can never be the agent's own key. Copy the
suspend keys from a sibling agent's manifest so governance is consistent
across the host.

This writes a deliberately minimal provisional manifest. Founding is the
moment of maximum ignorance — you replace it in the next step.

## 2. Write the manifest

The manifest is the contract. Compose it and validate before installing:

```yaml
manifest_version: 1
identity:
  npub: <the npub from step 1>

inference:                      # the native loop
- name: workhorse
  provider: claude-code         # or anthropic, openai, mock…
  model: claude-sonnet-5
routing:
  default: workhorse

connectors: []                  # capabilities — default deny, see step 5

memory:
  log: local
  index: local
  vaults:                       # optional: filesystem it may read/write
  - name: Work
    path: /absolute/path
  knowledge_home:               # optional: where durable notes land
    vault: Work
    folder: what-we-know

presence:                       # optional: how people reach it
  buzz:
    relay: wss://<relay-host>
    trigger: '@<Name>'

governance:
  suspend_keys:
  - <governor npub>
  - <second governor npub>
  budgets:
    tokens_per_day: 150000
    proactive_tokens_per_day: 40000   # REQUIRED for watches to ever fire

skills:                         # durable instructions, not prompts
- name: <kebab-case>
  description: <one line — when this applies>
  instructions: |
    …
```

**Skills are where an agent's judgment lives.** Write them as instructions to
a colleague: what to do, what never to do, and how to report. Two or three
focused skills beat one long one — the runner selects at most three per run
by relevance.

Validate before installing. This catches every schema error offline:

```bash
apiary manifest validate /tmp/<name>.yaml
```

## 3. Install it, unratified

```bash
cp /tmp/<name>.yaml ~/.apiary/agents/<npub>/manifest.yaml
```

Landing it unratified is correct — `manifest.yaml` is the proposal and
`manifest.approved.yaml` is the contract. The agent will not run until a
human signs. Confirm the two differ:

```bash
D=~/.apiary/agents/<npub>
[ "$(shasum -a 256 < $D/manifest.yaml)" = "$(shasum -a 256 < $D/manifest.approved.yaml)" ] \
  && echo "ratified" || echo "awaiting the governor"
```

## 4. The human ratifies and activates

In the cockpit: open the agent, review the effective setup, **Approve with
Nostr**, then activate. Both steps are required — ratified-but-inactive is a
common half-state, and the Overview tab says which is missing.

Every later change repeats this: edit `manifest.yaml`, validate, and the
governor ratifies again. The supervisor notices the change and bounces the
agent's channels on its own.

## 5. Grant capabilities — least privilege is not the default

Capabilities are default-deny: an empty `connectors` list means no tools
exist. Grants come from the cockpit's Capabilities tab, and for MCP servers
the credential is **sealed with NIP-44 to that agent's key** — it cannot be
copied from another agent, so each agent connects for itself.

**Granting copies the library entry's full tool list.** If the host library
entry has all 46 tools ticked, the new grant gets all 46. Trim
`caps.allowed_tools` to what the agent's charter actually permits, and check
it against the agent's own constitution — an agent whose skills say "no
access to customer data" holding `tenants_list` is a contradiction that no
test will catch.

## 6. Make it reachable

Presence in the manifest is necessary and not sufficient. On Buzz there are
**two separate memberships**, and both are managed in Buzz, not Apiary:

```bash
# 1. Relay membership — without it, auth fails outright
docker exec <buzz-relay-container> buzz-admin add-member --pubkey <npub> --role member
docker exec <buzz-relay-container> buzz-admin list-members

# 2. Channel membership — done in the Buzz app, per channel
```

A relay member that is not a channel member connects fine and hears nothing.

## Gotchas that actually bite

Each of these produced a working-looking agent that did nothing.

**Wrong passphrase at founding → can never be ratified.** `agent new` used to
seal the key with whatever passphrase it was handed, so an agent founded with
the wrong one appeared normal and failed only at the approval button, where
it reads as the ratify being broken. Now refused up front; if you meet it on
an older binary, delete the agent (it has no signed events) and refound.

**`not a relay member`** in the host log → step 6, relay membership. The agent
is otherwise perfectly configured.

**Founded, ratified, active, and silent** → check channel membership, and check
`trigger` matches what people actually type. A DM carries a p-tag and needs no
trigger; a channel mention needs the exact string.

**Watches never fire** → no `proactive_tokens_per_day`. A watch with no
proactive allowance is inert and says so on the Watches endpoint.

**MCP tools present but never called** → read the run record. `run.task` logs
`tools_offered` and `tool_calls`; a connector that bound nothing and a model
that chose not to look are different problems with the same symptom, and
asking the agent tells you nothing — it answers from its prompt.

**A tool policy of `read-write` does not mean the tool writes.** That flag
governs whether Apiary will call a tool the server did not declare read-only.
It cannot add an operation the server does not have — a catalogue whose verbs
are all `get`, `list`, `search` and `lookup` is read-only however it is
ticked. Read the tool NAMES before promising an agent can write anywhere.

**Agent claims it lacks access it has** → same check. Trust the log, not the
agent's self-report.

## Agents with a coding harness

A harness rents a foreign agent loop (Goose, Claude Code via
`claude-code-acp`) under Apiary's governance. Grant it and route work to it:

```yaml
harnesses:
- name: coder
  kind: acp
  command: /absolute/path/to/claude-code-acp
  access: full            # or curated + allowed_tools
  profile: isolated       # its own HOME — see below
  sandbox: none           # see below
  metering: estimated
  estimated_tokens_per_run: 60000
  workdir: /path/to/a/clone
routing:
  harness: coder          # errands run here; mentions never do
```

Three things to know before you promise isolation you do not have:

- **`sandbox: no-network` breaks a coding harness.** The profile is `(deny
  network*)` over the whole process, so a loop that must reach a model never
  starts. `read-only` blocks the writing that is the point. Use `none` and
  isolate by other means.
- **`profile: isolated` gives it its own `HOME`** at
  `<agent-dir>/.apiary-harnesses/<name>/home`, with none of the host user's
  credentials — so the harness needs its own one-time login there. That is a
  person's interactive step:
  ```bash
  HOME=<agent-dir>/.apiary-harnesses/<name>/home claude /login
  ```
- **`workdir` selects a directory, it is not a sandbox.** For an agent that
  edits code, the real isolation is a clone that is not the deployed tree, no
  credentials in reach, and a human merging.

`routing.harness` can only name a harness the manifest already grants —
routing points, it never grants.

## Verify before declaring it done

```bash
# ratified and active
ls ~/.apiary/agents/<npub>/            # manifest.approved.yaml + active
# what the manifest actually says
apiary manifest validate ~/.apiary/agents/<npub>/manifest.yaml
# reachable
docker exec <relay> buzz-admin list-members | grep <hex-pubkey>
# and then: say something to it, and read the run record
```

The last step is not optional. Every failure in the gotchas list passes every
check above it.
