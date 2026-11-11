# ADR-0043: A managed hook takes its orders from its command, never from the environment

**Status:** proposed 2026-11-10. Ruled by the author on that date after a design review of the whole tool: the two open choices (ruling 5 and ruling 6) answered one at a time, the restatement waived. Nothing is measured yet: accepted once the build lands and the runs under *Measured* are made.
**Deciders:** Acquiredl

## Context

ADR-0040 put the switch where only an administrator writes, and
ADR-0042 put the recorder and its interpreter there too. A managed
command on the author's machine reads:

```
"C:/Program Files/Python313/python.exe" -I "C:/Program Files/loxodonta/loxodonta.py" hook
```

Every word of it is out of the agent's reach. What the recorder does
once it runs is not, because it still asks the environment, and
ADR-0042 already found that a hook process inherits the environment
the harness was launched with. One line in a shell profile, or one
`env` key in the operator's own settings file, sets a variable for
every hook that follows. `-I` ignores the `PYTHON*` variables and the
script's folder. It leaves every other variable as it was.

What the recorder reads that an ordinary account can set:

| Read | What it moves |
|---|---|
| `LOXODONTA_HOME` | the whole store, so the receipts land where no scan looks |
| `LOXODONTA_LOCK_TIMEOUT`, `LOXODONTA_CHAIN_BATCH_BYTES` | how long an append waits, and how much one send carries |
| `LOXODONTA_MANAGED_DIR` | where the hook looks for the telemetry pin it checks the second record against (ADR-0041 ruling 7) |
| `HTTPS_PROXY` and its kin, read by `urllib` | the road every send, stamp and anchor takes |
| the operator's settings file, at install | the matcher: a managed install starts its entries from what is wired there, so a matcher narrowed in a file the agent can write is copied into the file it cannot |

A store moved this way is not silent to the supervisor: the sessions
show as transcripts with no receipts. But that reading is made on the
same machine, and the chains in the moved store are `VALID`. The
narrowed matcher shows nowhere but in the coverage marker.

One more read sits outside the hook. `verify` runs `openssl` and
`ssh-keygen` by bare name, and the tools run `git` so. On Windows a
bare name is looked for in the working directory before the system's
folders, so a file of that name in the folder a recipient verifies a
package from is the program that runs.

### Prior art, read on 2026-11-10

| System | What it does | What is taken from it |
|---|---|---|
| sudo, `env_reset` and `secure_path` | empties the environment, then lets a named few variables back; it replaced a list of variables to remove, which kept missing some | a list of what is allowed, never of what is refused |
| glibc, `AT_SECURE` and `secure_getenv` | the kernel sets one bit at program start when the program runs with more rights than its caller, and one function answers nothing while it is set | one bit the caller cannot set, one place that reads the environment |
| Git, `safe.directory` | honoured only from configuration the repository itself cannot supply | the setting that grants trust comes from the protected side |
| Go 1.19, `ErrDot` | refuses to run a program found through the working directory | the tool's own lookup, which skips it |

Every one that holds decides by one fact the untrusted side cannot
set, and reads the environment in one place.

## Decision

1. **The bit is a word in the command.** `install-hook --managed`
   writes `--managed` on every command it puts in the managed file,
   the recorder's `hook` and the supervisor's `digest` alike. Only the
   file an administrator writes can say it. A plain install never
   writes it. Not a variable, which is what the rule exists to stop
   listening to, and not a look at the managed folder, whose path the
   suite moves with a variable.

2. **Under that word, the environment is read through one function,
   which answers for a named few.** `CLAUDE_PROJECT_DIR`, which the
   harness sets, and whatever the standard library reads to find the
   home folder. Every other variable the tools read has its built-in
   value: the store is `~/.loxodonta`, the lock waits its ten seconds,
   a send carries its default, the managed folder is the harness's
   own. The one read that is a check and not an order stays as it is:
   the hook reads the telemetry variables to say when the second
   record has been cut (ADR-0041), and that reading is of the
   environment as it stands.

3. **Under that word, nothing the recorder sends goes through a proxy
   the environment names.** The publishes, the stamp and the anchor
   connect directly.

4. **A helper program is run by its full path, in every mode and in
   every tool.** `openssl`, `ssh-keygen`, `git`, `gh` and the default
   `claude` of `explain` are found by the tool's own walk of `PATH`,
   which skips the working directory under any spelling and every
   entry that is not an absolute path, and the path found is the one
   run. On Windows only an `.exe` or `.com` is taken, never a batch
   file. An `--llm` the operator types is
   run as typed. A helper not found is absent, and what was said for an
   absent helper is said. This is in the verifier's fence, so
   `verifier.py` is generated again and carries it to the recipient.

5. **A managed install writes the full matcher, and takes a narrower
   one only from its own command line.** It no longer starts from the
   entries in the operator's settings file. `install-hook --managed
   --matcher PATTERN` is how an administrator narrows it, and a re-run
   without the flag widens it again, saying so. When the operator's
   file held a narrower matcher, the install says it was not carried
   and names the flag. ADR-0040 ruled nothing on this; the installer
   carried it so that a re-run left a deliberate choice alone, and
   under a managed install the choice is the administrator's to make
   where the administrator writes.

6. **Worktree filing stays, as the one exception.** The recorder
   still reads a worktree's `.git` file to file its sessions with the
   repository they belong to. That file is in the writer's reach, and
   a forged one moves a session to another drawer of the same store.
   The scan reads every drawer of the store, so the chain is judged
   wherever it lands. What is lost is the attribution of the session
   to its project, and what is kept is a project's history in one
   place across the worktrees a build round makes and deletes.

7. **The docs say it** once built: `docs/HOOK.md` under wiring (the
   word, what it stops reading, `--matcher`); `docs/CLAIMS.md`
   (condition 1 covers what the recorder is told as well as where it
   lives); ADR-0040 gains an addendum for ruling 5.

### What it claims, and what it does not

It claims one thing more than ADR-0042: after a managed install, a run
without administrator rights cannot move the store, the matcher, the
lock, the batch or the road a send takes by setting a variable or
editing the operator's settings file.

It does not claim:

- **The home folder.** The standard library finds it through the
  environment, and so does the harness. A changed home moves the
  store with everything else the account owns.
- **The operator's own commands.** `scan`, `serve` and every verb
  typed in a shell read the environment as before. The word is in the
  hook's command, and nowhere else.
- **A plain install.** Nothing here changes it but ruling 4.
- **The lock.** It prevents accidents, not adversaries, as ADR-0004
  says.
- **A proxy the network requires.** A managed install behind a proxy
  it must use cannot publish, stamp or anchor until the install has a
  way to name one.
- **The certificates a send trusts.** The TLS library still reads
  `SSL_CERT_FILE` and `SSL_CERT_DIR` under the word. The road is
  fixed, but who is believed at its end is not, and using that needs
  a place on the network.

### Measured

Not yet. Once built, on the author's machine, from an ordinary shell
after an install from an administrator one:

- `LOXODONTA_HOME` set in the environment a session is launched with:
  the receipts land in `~/.loxodonta`, and without `--managed` on the
  command they land where the variable points.
- The same for `HTTPS_PROXY` naming a port nothing listens on: the
  session-end publish arrives at the receiver.
- A matcher narrowed in the operator's settings file, then
  `install-hook --managed`: the managed file holds the full matcher,
  and the install says the narrower one was not carried.
- A file named `openssl.exe` in the folder `verify` is run from: it
  does not run.

## Consequences

**What gets easier:**

- Condition 1 of `docs/CLAIMS.md` reads the same for the switch, the
  recorder and what the recorder is told.
- One function to read when asking what the environment can change.
- A recipient on Windows verifies a package from its own folder
  without that folder choosing the program that checks a stamp.

**What gets harder or more constrained:**

- Every managed command changes shape, so the first managed install
  after the change rewrites the managed file once.
- An administrator who narrowed the matcher by editing the operator's
  file says it again, as a flag.
- A managed install cannot be pointed at another store. The suite
  moves the home folder instead.
- A helper installed where `PATH` names it by a relative entry is no
  longer found.

**What we'll have to revisit if:**

- A managed install is needed behind a required proxy: the answer is
  a flag the installer writes into the command, not the variable.
- The harness documents what environment a managed hook runs in.
- Codex's managed install arrives: `CODEX_HOME` is then a variable to
  rule on.

## Alternatives considered

- **A list of variables to ignore.** Rejected: sudo's history. The
  next variable the tools learn to read would be listened to until
  someone remembered the list.
- **The bit read from the managed folder.** Rejected: the folder's
  path is itself moved by a variable for the suite, so the bit would
  rest on what it guards against.
- **Helpers found only in system folders.** Considered for the hook,
  and dropped: the hook runs no helper. `verify` runs under the
  environment of whoever verifies, which is not the writer's.
- **Stop reading the worktree's `.git` file.** Rejected by the author:
  the cost is certain and daily, and the harm of keeping it is a
  session filed under the wrong project in a store that is still read
  whole.
- **Carry the narrowed matcher and print it.** Rejected by the author:
  it rests on the output of an upgrade being read.
- **An operating-system lock in place of the lock file.** Not taken
  up: ADR-0004 stands.

## References

- ADR-0002 (the writer is the adversary), ADR-0004 (the lock),
  ADR-0011 (the store), ADR-0023 (one session, one drawer), ADR-0035
  (the verifier is copied out), ADR-0040 and ADR-0042 (the managed
  install), ADR-0041 (the telemetry pin)
- `docs/CLAIMS.md`, `docs/HOOK.md`
