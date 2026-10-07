# ADR-0040: A managed install wires the hook where only an administrator writes, and the hook then has one home

**Status:** accepted 2026-10-05. Ruled by the author on #259 and restated in the author's words on 2026-10-04; the live cases were run on 2026-10-05 and are under *Measured*.
**Deciders:** Acquiredl

## Context

`install-hook` writes the recorder's hook entries into the operator's
own settings file, `~/.claude/settings.json`. #259 measured what that
leaves open (Claude Code 2.1.259, loxodonta 0.7.0):

| Run | Command | Receipts |
|---|---|---|
| A | `claude -p "..." --dangerously-skip-permissions` | a drawer, three entries, an anchor at session end |
| B | the same, plus `--settings` naming a file with `{"disableAllHooks": true}` | no drawer, no chain |

Run B still ran its tool and still wrote its transcript. The witness
reported it afterwards as `ALARM-SILENT`. That report needs the
transcript, which the writer can reach and which the harness deletes
after `cleanupPeriodDays` days (ADR-0016, ADR-0017, #260). An edit to
the settings file does the same as the flag: the file is the
operator's, so anything running as the operator can take the entries
out.

ADR-0002 names the writer as the adversary. A switch the writer can
reach, that stops the record without the record saying so, is the
cheapest move against completeness there is today.

### What the harness offers

Read in Claude Code's documentation on 2026-10-04 (the pages *Hooks
reference*, *Deploy managed settings*, *Settings*, *CLI reference* and
*Run Claude Code programmatically*). This is what the documentation
says; what was then run is under *Measured*:

- **Managed settings rank above the command line.** No user, project,
  local or `--settings` value overrides a managed one.
- **A managed hook keeps running when `disableAllHooks` is set below
  it.** Only the same key set in managed settings stops it. `--safe-mode`
  turns customizations off and still runs hooks configured by policy.
- **The files.** `managed-settings.json` lives in
  `C:\Program Files\ClaudeCode\`, `/Library/Application Support/ClaudeCode/`
  or `/etc/claude-code/`. Beside it, every `*.json` file in a
  `managed-settings.d/` folder is merged in after it, in alphabetical
  order: lists combine, nested blocks merge key by key. The page offers
  the folder so that each owner of a part of the policy keeps a file of
  their own.
- **A handler defined in more than one settings file runs once.**
- **Four managed sources, ranked:** settings fetched from the vendor's
  server, a device-management policy, the files above, and a per-user
  registry key. By default the highest-ranked source that sets anything
  supplies the whole policy and the rest are skipped without a warning.
  `/status` names the source in use and the ones skipped.
- **An administrator on the machine can edit the managed source.** The
  page says so in its own list of limits, and says the folder on WSL
  counts as user-writable.
- **`--bare` skips the discovery of hooks,** and the documentation does
  not say whether a managed hook runs under it. It needs an API key in
  place of the subscription login, and the page says it will become the
  default for `claude -p` in a later release.

### Prior art, read at the primary source on 2026-10-04

| System | The switch the checked party holds | Where the part that holds lives |
|---|---|---|
| Git hooks (`githooks`) | `--no-verify` skips `pre-commit` and `commit-msg` | `pre-receive` runs in the receiving repository, which the committer does not own |
| The Linux audit system (`auditctl`, `augenrules`) | None once loaded: rules are read from a root-owned folder, and `-e 2` locks the configuration until a reboot | `/etc/audit/rules.d/`, where each file is concatenated in sort order, so a tool adds a file of its own and edits nobody else's |
| Claude Code | `disableAllHooks`, at any level below managed | Managed settings, and the `managed-settings.d/` folder |
| Codex CLI | Turning hooks off locally | `requirements.toml`, where an administrator pins hooks on |

All four put the part that must hold in a place the checked party does
not write, and two of them offer a folder of separate files for it.
None claims more than that: a root user rewrites audit rules after a
reboot, and both harness pages say an administrator can edit the
managed source.

## Decision

Ratified restatement, in the author's words: *we are removing the
access from the agent's control as long as the administrator does not
give the AI agent a way to access or know the key to get in to change
it.*

1. **`install-hook --managed` writes the hook entries to a file of the
   recorder's own,** `managed-settings.d/loxodonta.json`, in the
   harness's managed settings folder. It never reads or writes
   `managed-settings.json` or any other file there. It is asked for by
   name: a plain `install-hook` does what it did.

2. **It never raises its own rights.** Run without the right to write
   that folder, it writes nothing anywhere, names the file it could not
   write, and exits 73 (ADR-0037).

3. **One home.** Once the managed file is written, the installer's
   entries are removed from the operator's settings file, the recorder's
   and the digest's alike, and everything else in that file is left as
   it lies. In that order: a failure between the two steps leaves two
   homes and never none (ADR-0004). While the managed file holds the
   entries, a plain `install-hook` refuses and says where the hook is
   wired.

4. **`uninstall-hook --managed` deletes that one file** and nothing else
   in the folder. It does not put the entries back in the operator's
   file, and it writes no coverage marker (ADR-0030 ruling 2 stands).

5. **The file holds `hooks` and nothing else.** It sets neither
   `allowManagedHooksOnly` nor `disableAllHooks`: other people's hooks
   are not the recorder's to switch.

6. **The coverage marker says which home.** An entry a managed install
   writes carries `level: "managed"`, and moving the hook is a change
   that appends one. An entry without the field is the operator's own
   settings file. The marker stays testimony (ADR-0030).

7. **Whatever reads what is wired reads both homes.** The supervisor
   reads the operator's settings file for the session-end commands and
   the retention setting; it reads the managed file for the same
   purpose, by the same rule (`docs/TWINS.md`).

8. **Claude Code only.** Codex has the same tier and does not get this
   until its vertical is complete (`docs/DIRECTION.md` section 3).

9. **`docs/HOOK.md` says it,** under coverage: hooks fire in a headless
   run with permissions skipped; a run that sets `disableAllHooks` on
   the command line writes nothing where the hook is wired in the
   operator's file, and the witness reports it; a managed install is
   the wiring that flag does not reach; and what a managed install does
   not claim, below.

### What it claims, and what it does not

It claims one thing: a run cannot switch the recorder off from the
command line or from a settings file the operator owns, for as long as
the writer holds no administrator rights.

It does not claim:

- **A boundary on the machine.** A writer in an elevated shell, or on a
  machine where `sudo` asks for no password, or under WSL, writes the
  managed folder as easily as any other.
- **The recorder file.** The hook's command names `loxodonta.py` at a
  path the operator owns, and the managed file applies to every account
  on the machine (#460).
- **That the file is the source in use.** On a machine whose
  organization delivers settings from a server or through device
  management, the file is skipped without a warning. `/status` shows it,
  and the witness is still what reports a silent session.
- **`--bare` in a later version.** A managed hook was measured to run
  under it; the documentation does not say it does.

### Measured

On 2026-10-05, on a managed install the author made from an
administrator shell: Claude Code 2.1.287, loxodonta 0.13.0, Windows,
profile `timestamped`. Everything after the install ran from an ordinary
shell. The runs are on #259.

| What was run | What it showed |
|---|---|
| The install | The managed file holds `hooks` and nothing else; the installer's four entries left the operator's settings file and its other hooks stayed; the coverage marker gained an entry with `level: "managed"`; `/status` lists the managed settings among its sources |
| One headless session, one tool call | One receipt for the call, not two, with the session-end commitment and the anchor |
| The same session with `disableAllHooks` set through `--settings` (run B of #259) | The drawer and its receipts are written, and the chain verifies |
| The same, in a project carrying a hook of its own that writes a marker file | Without the flag the marker and the receipt are both written. With it the marker is not and the receipt is: the flag switches an ordinary hook off, and the managed one outlasts it |
| A headless session under `--bare`, with an API key | The drawer, the receipt, the commitment and the anchor are written. That the run was a bare one is read from its transcript, a thirtieth the size of an ordinary run's, with no skill listing, no MCP tools and no instruction files |
| `install-hook --managed` again, and a plain `install-hook`, neither elevated | "already installed ... nothing changed", exit 0; and a refusal that names the managed file, exit 73. The three files are byte for byte as before |
| The ordinary shell opening the managed file for writing | Refused by the operating system |

Not measured: macOS and Linux by hand (the suite runs the installer as
root there against temp folders, #462); `--safe-mode`, which the
documentation says keeps hooks configured by policy; whether `--bare`
skips an ordinary hook on this version; and a machine with a
higher-ranked managed source.

## Consequences

**What gets easier:**

- The cheapest move against completeness stops working for a writer
  without administrator rights, and the install is the shape an
  organization already uses to deploy policy.
- Removing it is deleting one file, and nothing of anyone else's was
  opened to put it there.

**What gets harder or more constrained:**

- The managed file is machine-wide. Every account's sessions run the
  recorder and the digest, each into its own store, through one command
  that names one path.
- Changing the profile, the remote or the authority means writing the
  managed file again, with the same rights.
- The installer now knows two homes, and so does every reader of what
  is wired. Ruling 3 keeps it to one at a time.
- The README's sentence that `install-hook` adds entries to the
  harness's own settings file and nothing else stays true of the plain
  install. A managed install creates one file and removes the
  installer's entries from one other.

**What we'll have to revisit if:**

- A later version of the harness stops running a managed hook under
  `--bare`. The documentation says `--bare` will become the default for
  `claude -p`, so headless runs would then write no receipts, and the
  finding in #259 that the headless case is covered would no longer
  hold. The measurement above is the thing to repeat when that default
  changes.
- The harness changes the folder, the merge order or the ranking of
  managed sources.
- #460 rules that the recorder moves too.

## Alternatives considered

- **Merge the entries into `managed-settings.json`.** The shape the
  plain install uses, and it needs no drop-in folder. Rejected: the file
  is an administrator's, and the harness offers the folder for exactly
  this.
- **Keep the entries in both homes.** The documentation says a handler
  in two files runs once. Rejected: two homes is two places to check
  and two to uninstall, and the second one is the one this decision
  exists to stop depending on.
- **Put the entries back on uninstall.** Rejected: it means remembering
  what was there, and a machine with no hook after an uninstall is what
  the word says.
- **Raise rights from inside the installer.** Rejected: a tool that
  records an agent's actions does not ask for an administrator's key on
  its own behalf.
- **Set `allowManagedHooksOnly`.** It would also block a copy of the
  hook left in the operator's file. Rejected: it switches off every
  other hook on the machine.
- **Detect the override from inside the hook.** Rejected in #259: a
  hook that does not run cannot report that it did not run. That is the
  witness's job.
- **Words only.** `docs/HOOK.md` says the hole exists and nothing is
  built. Kept as ruling 9, rejected as the whole answer.

## References

- #259 (the measurement and the two options), #460 (where the recorder
  file lives), #260 (the transcript the witness needs is deleted)
- ADR-0002 (the writer is the adversary), ADR-0004 (never stop
  recording), ADR-0015 (the recorder notice), ADR-0016 and ADR-0017
  (coverage and the writer-reachable transcript), ADR-0030 (the coverage
  marker, and why an uninstall writes none), ADR-0037 (exit 73)
- `docs/DIRECTION.md` section 3, `docs/HOOK.md`, `docs/TWINS.md`

## Addendum, 2026-10-06: the installer reads the other managed files once, and still writes only its own

Ruling 1 said a managed install never reads or writes `managed-settings.json` or any other file in the folder. ADR-0041 ruling 7 narrows that to the writes. At `--profile full` the installer also writes a second file of its own beside the hooks file, `managed-settings.d/loxodonta-telemetry.json`, which pins the harness's events to the receiver, and before it writes the pin it opens `managed-settings.json` and every other `*.json` drop-in read-only, through the same reader that refuses a folder or a pipe, to look for an `env` that already sets one of the four telemetry variables. It warns naming the file and the key, never the value, and writes its pin all the same: the harness sends to one place, and an organisation that already collects its events keeps them. Nothing else moves: the installer still merges into no file of anyone else's, the hooks file still holds `hooks` and nothing else (ruling 5), and `uninstall-hook --managed` deletes the two files of the recorder's own and nothing else (ruling 4). A file at the pin's name that is not the installer's pin refuses a `full` install before anything is written, and is left alone and named by every other verb. Ruling 1 reads from this date: *it writes nothing to `managed-settings.json` or to any file there but its own two, and reads the others only to warn.*
