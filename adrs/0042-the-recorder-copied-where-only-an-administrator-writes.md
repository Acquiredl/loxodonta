# ADR-0042: A managed install copies the recorder where only an administrator writes, and the same install moves it again

**Status:** proposed 2026-10-19. Ruled by the author on #460 in a grill of 2026-10-19, three questions one at a time, and restated in the author's words. Nothing is built or measured yet: accepted once the build lands and the runs under *Measured* are made.
**Deciders:** Acquiredl

## Context

ADR-0040 put the switch out of the agent's reach: the hook entries sit
in `managed-settings.d/loxodonta.json`, which a run cannot write
without administrator rights. The command in that file still names two
files the operator's account owns. On the author's machine it reads:

```
"…/AppData/Local/Python/pythoncore-3.13-64/python.exe" "…/repos/loxodonta-stable/loxodonta.py" hook
```

The checkout is the account's, and so is the interpreter: a per-user
Python install lives under the profile folder, and the recorder imports
`json` and `hashlib` from that interpreter's own library folder, which
ADR-0035's addendum already names as within the writer's reach.

The comment of 2026-10-15 on #460 gives the sequence that sharpens it.
The hook fires after the tool call it records has completed
(`docs/HOOK.md`). So when a session edits the recorder file, the
receipt for that edit is written by the edited recorder. One `Edit` of
`loxodonta.py`, or one shell line that rewrites it, and every receipt
from that call on is written by code of the writer's choosing. The
chain stays `VALID`, because the chain is checked for what was written
and never for who wrote it (SPEC section 8.1). No administrator rights
are needed. Under the `full` profile what remains is the second record
at the receiver, where a recorder that stops writing shows as
`ENDED-DEFICIT` tool by tool, and a recorder that keeps writing one
plausible receipt per call matches the count and shows nowhere.

So the test for where the recorder lives is this: an edit of the
recorder's path from inside a session must not be able to write its
own receipt, which means a path the account the agent runs as cannot
write. The same test covers the interpreter.

### What the harness offers

Read in Claude Code's documentation on 2026-10-19, the pages *Hooks*
and *Settings*. The pages say where managed settings live and that an
administrator on the machine can edit them. They say nothing about
where the program a managed hook runs should live. They do say that a
hook process inherits the environment the harness was launched with,
which is what ruling 4 answers.

### Prior art, read on 2026-10-19

Where other tools put the program an audited account must not write,
and how it is upgraded:

| System | Where the program lives | How it is upgraded |
|---|---|---|
| The Linux audit system | `auditd` and `auditctl` in `/sbin`, root-owned; only the rules sit in `/etc/audit/rules.d/` | root runs the package manager; the rules folder is untouched |
| Git hooks | `pre-receive` in the receiving repository's `hooks/`, under the server's account | the server administrator |
| Sysmon (Sysinternals) | `sysmon -i` copies itself to `C:\Windows\Sysmon64.exe` and runs as SYSTEM | an administrator runs the new release's installer |
| osquery | `C:\Program Files\osquery\`, `/opt/osquery/`, run as SYSTEM or root | the package manager by an administrator, or Fleet's `orbit`, a separate self-updater |
| `pre-commit`, the counter-example | `~/.cache/pre-commit/` and `.git/hooks/`, both the committer's | the committer |

Every one that holds puts the program in the system's program area,
never in the configuration folder, has a human with rights run the new
installer, and has the program say what version it is. `orbit` is the
shape ADR-0015 refuses: a second road to the one file that has to stay
honest. `pre-commit` makes no claim against the committer, and says so.

## Decision

Ratified restatement, in the author's words: *it is in the
administrator's hands, they must run the command to update to new
versions; we are giving a more standard shape to our tool.*

1. **Where.** A managed install runs the recorder from a folder of the
   recorder's own under the system program area:
   `C:\Program Files\loxodonta\` on Windows, `/opt/loxodonta/` on
   macOS, Linux and WSL. Not beside the managed settings: `/etc` holds
   no programs, the folder is the harness's, and the recorder is not
   Claude Code's, so when Codex's managed install arrives its
   `requirements.toml` names the same copy. Not
   `/Library/Application Support/loxodonta/` on the Mac: that parent is
   group-writable by `admin`, so an account in that group renames a
   root-owned folder away without `sudo`.

2. **Who.** `install-hook --managed` copies the two files its commands
   name, `loxodonta.py` and `supervisor.py`, from the folder it is run
   from into that folder, with the rights it was run with, and the
   managed file's commands name the copy. The copy is written first,
   then the managed file, then the operator's entries are removed
   (ADR-0040 ruling 3): a failure after the copy leaves a file nothing
   points at, never a command pointing at nothing. Each file is written
   through a temporary file beside it and moved into place. ADR-0040
   ruling 2 stands: the installer never raises its own rights, and
   without the right to write the folder it writes nothing anywhere,
   names the folder and exits 73.

3. **The check, one question asked twice.** Is this path out of an
   ordinary account's reach, as far as this tool can see? Asked of the
   interpreter the command will name, which is the one running the
   installer, as today, and of the folder the copy goes in.
   - On POSIX: symlinks resolved, every component from the root down is
     owned by root and has no group or other write bit. A system Python
     passes. A Python under the home folder, from pyenv, uv or conda,
     fails.
   - On Windows the standard library cannot read an access list, so the
     check is by place. Under `Program Files` or `Windows` passes. Under
     any user profile fails, which is what Python's per-user install is.
     Anywhere else fails too, and the refusal says the installer cannot
     read that folder's access list from here.

   A failed check refuses before anything is written, exit 64 as
   `--profile full` without `--remote` refuses (ADR-0031), naming the
   path and the fix: run the installer with a Python installed for all
   users. Python's own installer offers that as an option. No new flag:
   the interpreter wired is the one the administrator chose to run the
   installer with.

4. **`-I` on every command the installer writes,** managed and plain,
   so there is one command shape. When the recorder reaches
   `import hashlib`, Python looks first in the script's own folder,
   then in the folders `PYTHONPATH` names, then in its own library.
   Ruling 1 closes the first by ownership. The second needs no rights:
   a hook process inherits the environment the harness was launched
   with, so one line added to a shell profile puts a `hashlib.py` of
   the writer's choosing ahead of the real one, with nothing under
   `Program Files` touched and the chain `VALID`. Isolated mode ignores
   every `PYTHON*` variable, the script's folder and the user's
   site-packages. It costs nothing here: the tools have no dependencies,
   and the hook reads its payload as bytes and decodes UTF-8 itself.
   The recipient already runs `verifier.py` this way (ADR-0035
   addendum).

5. **The upgrade is the same verb.** `install-hook --managed` run again
   from newer files replaces the copy whose bytes differ and says both
   versions; run from the same files it says nothing changed; the
   managed file is rewritten only when the flags changed, as today. Run
   from older files it moves the copy backwards and says so: no
   refusal, since the administrator running the verb is the one it
   answers to. No `--upgrade` verb, no fetch, no check against the
   releases page. The copy learns of a newer release when the
   administrator does (ADR-0015).

6. **The notice reads a copy by its version line and its hash.** For a
   recorder outside a git checkout, the supervisor reads the
   `TOOL_VERSION` line from the file's text, hashes the file, reports
   both, and says when the supervisor doing the reading is another
   version. The export's machine line, which prints the recorder's
   commit or `unknown`, prints the same. Testimony and never an alarm,
   and the exit code is untouched (ADR-0015, addendum of this date).

7. **`uninstall-hook --managed` deletes the copy's two files,** and the
   folder when that leaves it empty, with the two managed files, and
   nothing else (ADR-0040 ruling 4).

8. **The sum stays the administrator's.** The installer prints no
   checksum. `docs/HOOK.md` says, in one sentence, to hash the copy
   against `SHA256SUMS` after the install, and that a mismatch means
   the file it was installed from had been edited: download it again
   and install again.

9. **The docs say it** once built: `docs/HOOK.md` under wiring (the
   copy, the check and its refusal, `-I`, the upgrade, the sum
   sentence); `docs/CLAIMS.md` (condition 1 covers the recorder and the
   interpreter, and the limit line about the recorder's path goes);
   `docs/START.md` and the README's recommended setup (the install
   line, run with an all-users Python); the glossary's *Recorder
   notice* entry (the version line where git has nothing to say).

### What it claims, and what it does not

It claims one thing more than ADR-0040: after a managed install that
passed its check, a run without administrator rights can neither switch
the recorder off nor change what it runs. The switch, the recorder, the
supervisor the digest runs and the interpreter all sit where that
account cannot write, as far as the installer could see.

It does not claim:

- **A boundary on the machine.** As ADR-0040: a writer in an elevated
  shell, or where `sudo` asks for no password, writes the copy as
  easily as the managed file.
- **Windows access lists.** The check there is by place. A Python on
  another drive is refused though it may be fine, and a folder under
  `Program Files` whose list someone loosened passes.
- **Every file of the interpreter.** The check reads the interpreter's
  path, not each file in its library folder.
- **That the copy is the published file.** The sum is the
  administrator's check (ruling 8).
- **The harness's own program.** The harness is what reads the managed
  settings and fires the hook. On a per-user install its files are the
  account's, and a harness changed there fires no hook, managed or
  not. What shows it is the count at the receiver: events that stop
  arriving, or arrive for calls that left no receipt.

### Measured

Not yet. Once built, on the author's machine, from an ordinary shell
after an install from an administrator one:

- The `Edit` test: an `Edit` of `C:\Program Files\loxodonta\loxodonta.py`
  from inside a session is refused by the operating system, and the
  receipt for the refused call is written by the unchanged copy.
- The refusal: `install-hook --managed` run with this machine's per-user
  Python exits 64 and names the path and the fix; run with an all-users
  Python it copies, and the managed command names the copy.
- The upgrade: the same line run from a newer checkout moves the copy
  and says both versions; run again, nothing changed.
- The notice: `supervisor scan` from the checkout names the copy's
  version and hash, and says when its own version differs.
- `PYTHONPATH` naming a folder with a `hashlib.py` of its own, in the
  environment a session is launched with: the hook runs the real one
  under `-I`, and the fake without it.

## Consequences

**What gets easier:**

- Condition 1 of `docs/CLAIMS.md` covers the recorder and the
  interpreter, not only the switch, and its check stays what it was:
  run the install again and it says already installed.
- The shape is one every administrator knows: a program under
  `Program Files` or `/opt`, placed and replaced by its installer.
- The harness's folder stays the harness's, and the copy serves Codex's
  managed install when it arrives.

**What gets harder or more constrained:**

- A second protected location to document and to test: the suite needs
  a variable beside `LOXODONTA_MANAGED_DIR` to point the copy at a
  folder it may write.
- A Windows operator with the default per-user Python installs an
  all-users Python before a managed install, from the administrator
  shell they are already in.
- Two supervisors on the agent's machine: the copy's runs the digest,
  the operator's checkout runs `serve` and `scan`. The notice says when
  they differ.
- Every hook command the installer writes changes shape with `-I`, so
  the first plain install after the change rewrites existing entries
  once.
- A release on the author's machine gains a step: after pulling the
  stable checkout, run the managed install again from an administrator
  shell.

**What we'll have to revisit if:**

- The harness documents a place for the programs its managed hooks
  run.
- Codex's managed install arrives; ruling 1 is written to serve it.
- The by-place check on Windows refuses too many real installs, or a
  plain way to read an access list from the standard library appears.

## Alternatives considered

- **Beside the managed settings, in a folder of the recorder's own.**
  The copy's protection would be the managed file's by construction and
  one test variable would move both. Rejected: `/etc` holds no programs,
  the folder is the harness's, and it ties a harness-neutral recorder to
  one harness.
- **Stay at the checkout and state the limit.** Rejected: fails the
  test in the context outright.
- **Warn and write when the interpreter is reachable.** Friendlier.
  Rejected: it leaves a managed install whose claim is false, with the
  only trace a line that scrolled past. ADR-0040 rejected words-only as
  the whole answer for the switch, and this is the same shape for the
  recorder.
- **A flag to accept a reachable interpreter.** Rejected: the warn
  option under a longer name. The plain install exists for anyone who
  wants less.
- **A checksum of the recorder kept in the managed file.** Rejected in
  #460 itself: whatever checked it would run from the same reachable
  file. Ownership is the check.
- **An `--upgrade` verb, or a fetch.** Rejected: ADR-0015, and the same
  verb is what every precedent does.
- **Printing the copy's sum from the installer.** Deferred by the
  author: one sentence in `docs/HOOK.md` keeps the check in the
  administrator's hands, where START.md already puts it.
- **Copying the interpreter.** Not possible: a Python is not one file.

## References

- #460 (the decision), #259 (the managed install's measurement), #469
  (the supervisor's check of condition 2 gains the copy's folder as a
  second path to ask about)
- ADR-0002 (the writer is the adversary), ADR-0004 (never stop
  recording), ADR-0015 (the recorder notice, and its addendum of this
  date), ADR-0031 (the refusal of `full` without a remote), ADR-0035
  and its addendum (what single-file does and does not buy; `-I`),
  ADR-0037 (exit codes), ADR-0040 and its addendum of this date
- `docs/CLAIMS.md`, `docs/HOOK.md`, `docs/DIRECTION.md` section 6
