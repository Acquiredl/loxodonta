# Start here

You were handed this because everything in these docs was measured on one
machine: mine. The thresholds, the verdicts, the numbers all came out of one
store. What I need is not another feature, it is evidence that the recorder
holds up somewhere else, and a look at what agent sessions are like when they
are not my sessions.

Five steps. Nothing to install, no service, no account, no dependencies.
Python 3.9 or newer is the whole requirement. The commands below say
`python`; on macOS and Linux it is usually `python3`.

## Let an agent do this with you

If you run Claude Code, Codex, or anything else that can use your terminal,
you do not have to follow the steps by hand. Open it in an empty folder and
say something like:

```
Install loxodonta from github.com/Acquiredl/loxodonta, following docs/START.md
in that repo. Go one step at a time, show me each command before you run it,
and stop if anything looks wrong.
```

Yes, that is asking an agent to wire up its own recorder, and it is worth
saying what that means. The hook is one entry in your harness's settings
file, which you can open and read afterward. Once it is wired it fires
outside the agent's control, so what gets recorded no longer depends on the
agent's cooperation, and `python loxodonta.py uninstall-hook` takes out
exactly that entry and nothing else.

## The five steps

### 1. Get the two files

From the [releases page](https://github.com/Acquiredl/loxodonta/releases),
download `loxodonta.py` and `supervisor.py` into one folder. They have to sit
side by side: the installer looks for the supervisor beside the recorder, and
says so if it is not there. Check both against the `SHA256SUMS` attached to
the same release, then ask the file which version it is.

```
sha256sum loxodonta.py            # certutil -hashfile loxodonta.py SHA256 on Windows
python loxodonta.py --version     # loxodonta 0.4.0 (format 0.1, commit ...)
```

### 2. Wire the hook

One command. Restart any session that is already open.

```
python loxodonta.py install-hook            # Claude Code
python loxodonta.py install-hook --codex    # Codex CLI
```

Every new session on this machine now leaves a chain of receipts under
`~/.loxodonta/receipts/`, one drawer per project (`C:\Users\<you>\.loxodonta\`
on Windows). There is no daemon and no scheduled job. The command writes one
entry into your harness's settings file, and the harness runs the recorder as
a child process after each completed tool call.

### 3. Work normally

This is the step that takes time and no effort. Use your agent the way you
were going to anyway, for a week or for a few real sessions. Each completed
tool call becomes one receipt, about 135 ms on the machine that was measured,
and nothing asks you for anything.

### 4. Look

```
python supervisor.py scan      # every chain in the store, one verdict each
python supervisor.py serve     # the same reading as a page, on localhost only
```

`scan` is the one that matters here. If it tells you something you were not
expecting, that is already worth an issue, before you send anything at all.

### 5. Send back what your machine saw

```
python supervisor.py export           # writes the export and prints it, sends nothing
python supervisor.py export --send    # secret gist under your own login, then an issue
```

Run the first one and read the file. It is assembled from a list of fields I
wrote down, not from your scan with things crossed out: no paths, no command
lines, no file references, and repo names become `repo-1`, `repo-2`. The top
of the file is a plain-words block saying what was left out. Raw chains are a
separate flag that shows you a sample line and asks first, because chains
carry command lines and that call is yours.

When you are happy with what you read, `--send` puts it in a secret gist
under your own account, which stays yours and which you can delete, and opens
a field-data issue on this repo. If `gh` is not on the machine, nothing is sent: it
leaves the issue body beside the export so you can file it by hand, or you
can just send the file back to whoever handed you this.

What arrives gets read end to end by a person and written up in
[FIELD-DATA.md](FIELD-DATA.md), one row per export, including the rows that
say it changed nothing. That is also information, and you can see what your
export did.

## If it goes sideways

[Open an issue](https://github.com/Acquiredl/loxodonta/issues/new/choose)
even if you got nowhere. "I could not get past step 2" is a finding about
step 2, and right now the install path has been walked by one person. A verdict that looks wrong, a count that does not add up, a session
the scan will not read: all of it is the same kind of useful.

Everything else this tool does is in the [README](../README.md): anchoring a
chain head to Bitcoin, handing a session to someone off the machine as a
sealed package, agents reading their own history. None of it is needed for
these five steps.
