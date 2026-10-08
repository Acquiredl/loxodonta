# ADR-0041: The harness's own tool-call events are a second record kept out of the writer's reach, and the reading that counts runs where they land

**Status:** proposed 2026-10-06. Ruled by the author in a design session of 2026-10-05 and 2026-10-06, eight questions one at a time, and restated in the author's words. Measured on one version of the harness before it was written; the words are the author's to change, and the third promise waits for a run on two machines.
**Deciders:** Acquiredl

## Context

The red-team pass of 2026-10-05 attacked 29 stated guarantees. The two
promises of `docs/CLAIMS.md` held. What fell was completeness: the
[witness](../docs/GLOSSARY.md#witness) counts a session's tool calls
against a [second record](../docs/GLOSSARY.md#second-record) that sits
on the agent's machine, and a writer who garbles, empties or deletes the
transcript reads as quiet or is not seen (#473); a writer who deletes the
baseline and the day book together retires a standing alarm (ADR-0039,
addendum of 2026-10-05). Both findings have one root: everything the
check stands on, the second record and the supervisor's memory, is
within the writer's reach. `docs/CLAIMS.md` said as much, and said
completeness becomes a promise the day a second record exists that the
agent cannot reach.

`docs/DIRECTION.md` section 6 declined that record before 1.0, when the
only way to get one looked like a proxy. The author's goal has since
been stated: build tools on top of the log, tripwires first, which lean
on "nothing is missing" (the round of 2026-10-04).

### What the harness offers, measured

Claude Code 2.1.287, Windows, a throwaway stdlib collector on the
loopback, telemetry switched on for the run; the runs are the design
session's record. Read against the harness's *Monitoring usage* page the
same days.

- With `OTEL_EXPORTER_OTLP_PROTOCOL=http/json`, Claude Code posts its
  events as plain JSON over HTTP every few seconds. A stdlib HTTP server
  reads them; no protobuf, no library.
- One `tool_result` event per tool call that ran: the session id (the
  one the chain is named after), the tool name, a call id (the one in
  the transcript), success or failure, a duration, the sizes of input
  and output, and a per-session counter, so a missing event leaves a
  visible gap. One `tool_decision` event per permission decision, a
  refused call among them, with no `tool_result` after a refusal. No
  command text, no path, no parameters: those appear only under flags
  this project never sets, and prompts and replies are redacted by
  default. The harness also reports each hook it ran, by event name.
- A subagent's calls arrive under the parent's session id, as the hook's
  receipts do.
- On every event: the account's email address, user id, account ids and
  organization id. No documented setting removes them from events.
- The events are still sent when a run passes `disableAllHooks` on its
  command line, and the managed hook still writes its receipt beside
  them.
- Given a base address with a secret path, the harness posts to
  `/<secret>/v1/logs`; given the per-signal logs address, to that address
  as written. Either fits the receiver's rule that the path is the
  credential.
- A proxy variable in the writer's shell does not redirect the export.
- **A pin in managed settings holds against a `--settings` file and
  does not hold against the launch environment.** With the telemetry
  pinned in a managed `env`, a run whose shell set the telemetry off, or
  set another endpoint, sent nothing to the pinned collector; the
  harness's own debug log says a value in the launch environment takes
  precedence over a managed setting. The managed hook kept writing
  receipts through every such run.

### Prior art

Read at the primary source, or already in `docs/GROUNDING.md`:

| System | What it does | Here |
|---|---|---|
| PeerReview (GROUNDING section 3) | A counterparty holds its own record of each message, and an omission shows when the two are compared | The receiver's machine holds the harness's record of each call |
| Certificate Transparency monitors (GROUNDING section 2) | Third parties check their own copy of the log, not the operator on the log's own server | The supervisor on the receiver's machine, over its own copies |
| PillarBox, Bowers and others (GROUNDING section 3) | Heartbeats and a gap check on a forwarded log, so a stopped forwarder shows | The per-session counter's gaps are named; a machine that sends nothing is the stated limit |
| NIST SP 800-53 AU-9(2) (`docs/CONTROLS.md`) | The record copied off the audited system as it is produced | The events leave every few seconds |
| Claude Code's own documentation | Managed settings pin the telemetry's destination; the launch environment is above them | Condition 5, worded as a pin against settings |

From memory, not read at the source for this decision: the remote syslog
loghost, a plain appender on another box (already ADR-0031's precedent);
Jaeger, which added a native door for the OTLP standard inside the same
program it already was; a SIEM, where endpoints forward and the
correlation runs where the logs land; and CC-Monitor, the near miss from
the tripwire research of 2026-10-04, which cross-checks hooks against a
kernel probe on the same machine.

## Decision

Ratified restatement, in the author's words: *the receiver also listens
for Claude Code's tool-call events, sanitised of identity as best we
can. The box lets us check the laptop's record against a second one:
the laptop can be duped, but the box can only be kept in the dark,
never lied to.*

1. **The decline is reversed, narrowly.** `docs/DIRECTION.md` section 6
   no longer declines a second record for Claude Code out of the
   writer's reach. It still declines capture through a proxy or a
   gateway. The harness's own events are the second producer the
   `loxodonta-second-record/0` contract waited for, in place of another
   agent framework.

2. **The receiver grows a second door and stays dumb.** `receiver.py`
   accepts the harness's events at `/<token>/v1/logs`, under the token's
   path as every arrival is, and appends what arrives to its own disk,
   one received request per line, in one `events-<day>.jsonl` file per
   day of arrival, under the caps it already keeps. It understands none
   of it. Which events are tool calls, and what the harness calls them,
   is a reader's business on the supervisor's side (DIRECTION section 3).
   ADR-0031's rule stands: the receiver knows a standard envelope and no
   vendor.

3. **The identity namespace is dropped at the door.** Every attribute
   named `user.*` or `organization.*` is removed before a line is kept.
   Those names are OpenTelemetry's conventions, not Claude Code's, and
   the same rule applies to any sender. The rest is kept whole: tool
   names, timing, success, sizes, model and cost, machine and version.
   The installer never sets the flags that would add prompts, replies,
   commands, paths or parameters to the events, and its install text
   lists what leaves before the pin is written, as it does for `full`.

4. **The reading that counts runs where the records land.** The
   supervisor reads the receiver's folder as a store: the published
   chains and the event files. It judges each finished session tool by
   tool, as ADR-0034 does, with the harness's `tool_result` events as
   what was owed, and keeps its baseline and day book on that machine.
   The on-machine supervisor changes nothing: its reading stays the fast
   one and the writer-reachable one, a reason to look. `docs/CLAIMS.md`
   says which reading counts.

5. **Silence has three meanings, and a fourth is the limit.** Events
   arrived and receipts fell short: the deficit, named tool by tool.
   Receipts arrived and no events: named as a session whose second
   record never arrived, never clean. A gap in a session's counter:
   named as a gap in the second record. A machine that sends nothing at
   all is not seen by the receiver, and the reading there says when it
   last heard from each machine. No heartbeat; one can follow if that
   line is not enough.

6. **A third promise, for sessions the receiver heard from.** For such a
   session, a tool call the harness reported that has no receipt shows,
   tool by tool. It goes onto `docs/CLAIMS.md` only after rulings 2 to 4
   are built and run end to end on two machines.

7. **A fifth condition, worded for what was measured.** The vantage setup
   gains: the harness's events are pinned to the receiver in managed
   settings. That holds against the settings files and the command line,
   and not against the environment a run is launched with. Condition 4
   becomes "somebody reads it where it landed". The installer writes
   the pin as a second managed file of its own, beside the hooks file
   (ADR-0040 ruling 5 stands), removable on its own, and warns when
   another managed source already sends the harness's events elsewhere:
   the harness sends to one place only, and an organisation that already
   collects its events keeps them.

8. **The hook writes down a cut second record.** The hook runs in the
   harness's environment. When that environment has the telemetry off or
   pointed elsewhere, the hook appends a bookkeeping entry in its own
   voice, as it does for a transcript commitment, saying so. The writer
   cannot hand the hook an environment the harness did not have, and
   under a managed install cannot silence the hook, so the chain carries
   its own note that the second record was cut, and the note reaches the
   receiver at session end.

9. **Three slices, words first, promise last.** The receiver's door;
   the installer's pin with the hook's note; the supervisor over the
   receiver's folder. This ADR and the DIRECTION and glossary changes
   land before code. The promise lands last.

### What it claims, and what it does not

For a session the receiver heard from, a missing receipt shows, and
nothing on the agent's machine can reach the comparison or its memory.

It does not claim:

- **That the events cannot be stopped.** A run launched with its own
  environment stops or redirects them. That session is then named as
  one whose second record never arrived, and the chain carries the
  hook's note; neither reads as clean.
- **A machine cut off entirely.** It sends nothing, and the receiver
  does not know the session existed. The on-machine reading still sees
  it, while its files stand.
- **A live alarm off the machine.** Receipts reach the receiver at
  session end, so its reading is of finished sessions.
- **The events' truth.** They are the harness's word, like the
  transcript was. What changes is their reach.
- **An organisation's own collector.** The harness sends to one place.
  Reading another collector's files is a later path.

### Not yet measured

- A run under `--bare`: the harness's documentation does not say.
- A session killed outright: whether the last seconds of events are
  lost and the counter shows the gap.
- The receiver's TLS with the exporter, through the documented
  certificate variable.
- Flooding the second door to its cap, so later real events are refused.
- Any version of the harness but 2.1.287, and any system but Windows.

## Consequences

**What gets easier:**

- Completeness is judged somewhere the writer cannot edit, and the two
  red-team findings are closed for that copy.
- The second producer for `loxodonta-second-record/0` exists without a
  new agent framework, and the first two-machine run is also the first
  export from another machine (gate 3).

**What gets harder or more constrained:**

- The vantage setup needs two machines, two pins and a supervisor on
  each. `docs/CLAIMS.md` says what each part left out opens.
- The receiver's files hold more than chains: tool names, timing, cost
  and machine details, with identity removed. The caps and the operator's
  handling cover them as they cover chains.
- This half of the design rides on one vendor's event names and on the
  precedence its settings keep. The reader holds that knowledge; the
  receiver does not.
- The hook on 2.1.287 writes two receipts for a failed call and one for
  a refused call (#476). The harness's events count those calls as one
  and none, so the off-machine reading will show a surplus until #476 is
  settled.

**What we'll have to revisit if:**

- A later version of the harness lets managed settings beat the launch
  environment: condition 5 strengthens, and the hook's note becomes
  rare.
- The event names or attributes change under us.
- "Last heard" turns out not to be enough: a heartbeat follows.

## Alternatives considered

- **Keep the decline, and tell readers that completeness is only a
  fault-catcher.** Rejected: the author's goal is tools that lean on
  "nothing is missing", and the cost of the record dropped to a small
  door once the harness was found to emit the events itself.
- **A proxy or gateway between the agent and the model.** The second
  decline, kept: heavy, and not needed.
- **A fourth single file to collect.** Rejected: a fifth file in every
  release and a second process on the second machine, for no gain over a
  second door.
- **An off-the-shelf collector.** Not built: a stranger would install
  and configure a separate program, and its storage is not append-only.
  Storing the events in the shape they arrive keeps that path open.
- **Judge on the agent's machine, fetching events back.** Rejected: the
  receiver would need a door that gives things back, and the judgment
  and its memory would stay in reach.
- **Keep identity in the receiver's files.** Rejected: the operator's
  email on every line of every file on a second box, in a project that
  keeps identity out of everything, for no use the session id does not
  serve.
- **Fold the pin into the hooks file.** Rejected: a different switch,
  with its own failure and its own conflict with an organisation's
  telemetry, and ADR-0040 ruling 5 would no longer be true.
- **A heartbeat now.** Deferred: a new sender the writer can also stop,
  needing a threshold the author's own usage would trip.

## References

- `docs/CLAIMS.md`, `docs/DIRECTION.md` sections 3 and 6, `docs/GLOSSARY.md`
  *Second record*, *Witness*, *Receiver*, *Harness events*
- ADR-0002, ADR-0025, ADR-0029, ADR-0031, ADR-0034, ADR-0039, ADR-0040
- #473, #474, #476; the red-team pass of 2026-10-05
- `docs/GROUNDING.md` sections 2 and 3; Claude Code, *Monitoring usage*
  and *Deploy managed settings*, read 2026-10-05 and 2026-10-06
