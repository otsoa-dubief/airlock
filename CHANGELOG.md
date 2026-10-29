# Changelog

## 0.2.4 — 2026-10-29

- Security (GHSA-w8j8-5ph5-rrff): on Windows, the walls on folders never matched a path inside them, because
  Windows writes paths with backslashes and airlock compared with `/` only. Writes to `memories`, `skills`, `cron`,
  `plugins` (airlock's own folder included) and `hooks` went through, as did reads of airlock's data and of other
  profiles; from a named profile, `{hermes_root}` was the profile itself; 10 of 15 secret file names tried
  (`.env`, `id_rsa`, `.netrc`, `token.json`, a `secrets` folder...) were not recognized. Every path airlock
  compares is now in one form, with forward slashes, and the test suite runs on Windows in CI, where the report's
  cases are decided as on macOS and Linux. Reported by jeanpaul-source.
- Same fix, the other names Windows gives one file: Git Bash's `/c/...`, `/cygdrive/c/...`,
  `/proc/cygdrive/c/...` and `/mnt/c/...` (Hermes's terminal on Windows is Git Bash, and its file tools translate
  them, `..` resolved first as Git Bash does), Git Bash's `/tmp` (the user's temp folder, where a junction can lead
  anywhere) and its `/` (Git's own folder, found from the bash Hermes runs; a path with no drive is checked both
  there and on the current drive, where Python and the browser open it), the `\\?\`, `\\.\` and
  `\??\` prefixes, the local administrative share (`\\localhost\C$\...`, also as `file://localhost/C$/...`),
  NTFS streams (`file::$DATA`, `dir::$INDEX_ALLOCATION`), trailing dots and spaces (`.env.`), a path with no drive,
  case, `file:///C:/...` in the browser, `C:\...` after `MEDIA:`, and `$USERPROFILE`, `$APPDATA` and
  `$LOCALAPPDATA` in commands and code. Links and junctions are followed as before.
- Another machine: on Windows, a file tool, an attachment or a `file:` URL that names a `\\server` path (a server
  alone included) is blocked, and so is a command that cites a `\\host\share` path (a Git Bash `//switch` is not
  one). Such a path is never resolved, listed or tested to decide: on Windows that alone connects to the machine
  and can send the user's NTLM credentials. No name lookup is made to decide either.
- Default policy, Windows places: saved credentials and DPAPI keys, Chrome, Edge, Brave and Firefox profiles,
  `gcloud` and GitHub CLI logins (never read nor written); the Startup folder and PowerShell profiles, OneDrive's
  included (never written). Deleting a drive root or the user's profile, from Git Bash, `cmd` or PowerShell, is a
  destructive deletion; so is deleting, through `cmd` (`rd`, `del`) or PowerShell (`Remove-Item`), a protected path
  or a folder that holds one, named in the command, as `-Path:`, piped in from `Get-ChildItem`, or below a `cd`. Persistence: `schtasks //create` (Git Bash), `Register-ScheduledTask`, `reg import`,
  WMI event subscriptions, and the registry keys Windows runs at logon or with every `cmd` (`CurrentVersion\Run`,
  `User Shell Folders`, `UserInitMprLogonScript`, `Winlogon`, `Command Processor\AutoRun`). PowerShell given
  encoded code (`-EncodedCommand`, `-enc`, `-e`) is a bypass: nothing in it can be read. `setx HERMES_HOME`,
  `$env:HERMES_HOME =`, `set HERMES_HOME=` and `Set-Item Env:HERMES_HOME` borrow an identity.
- Everywhere:
  - a command that writes a protected path with a space in it, written in the command (`echo x >
    '~/Library/Application Support/...'`, `cp`, `tee`), is read whole; it was cut at the space. The same path
    reached through a `cd`, a variable or `$'...'` is not read: see the threat model;
  - `rm -r` of a folder that holds a protected path is blocked (deleting a parent of `~/.ssh` deletes `~/.ssh`).
- False match fixed: a file being written that contains `hermes_home=` or a Python variable `HERMES_HOME = ...` no
  longer hits the identity wall (the wall reads a shell assignment, `HERMES_HOME=`, with the variable's case outside
  Windows, where environment names are case-sensitive). A protocol-relative URL (`//cdn...`) in a file being written
  is not a path.
- A media path holding a NUL byte no longer raises on Python versions whose `realpath` accepts it.

## 0.2.3 — 2026-10-28

- Security (GHSA-mgf8-gh7g-q4rg): with `approvals_off: block` (the default), an action airlock sends for approval
  ran without approval in a `hermes -z` turn run by the gateway. Hermes marks such a turn unattended in the turn
  itself, not in `HERMES_YOLO_MODE`, so airlock did not see that nobody could approve. airlock now asks Hermes's
  own approval code why it would approve alone: `--yolo` read at startup, `/yolo`, a `hermes -z` turn,
  `approvals.mode: off` (a hosted room's policy too), and a cron job, `-q` run or webhook whose `approvals.*_mode`
  is `approve`. The environment and `config.yaml` remain the fallback for older Hermes. Reported by Cleiton
  Augusto.
- Same check, found while fixing it: a subagent run from the CLI with `delegation.subagent_auto_approve: true`
  answers Hermes's prompts itself; what airlock sends for approval in that subagent is now blocked too. The
  parent session still asks the owner.
- `approvals.cron_mode` is read as Hermes reads it (`off`, `allow` and `yes` approve too).

## 0.2.2 — 2026-10-26

- Attachments: `send_message` (and Yuanbao's `yb_send_dm`) turns a `MEDIA:<path>` in its text into an attachment.
  A file the agent may not read (credentials, `.env`, keys, another Hermes profile's data) could leave that way
  after a single approval; it is now blocked, in every conversation, whoever the recipient. Paths are read with
  Hermes's own reader (with the bare file paths Weixin also sends) and with airlock's own, on the message and again
  on the text left once tags are removed, since removing one can glue a new one together. If Hermes's reader
  cannot be loaded, airlock's own reader works alone and a warning goes to the log.
- The first 200,000 bytes of each attached text file are checked like the message: a recognized secret or
  airlock's private session marker inside an attachment is refused, the stop switch included. More than 20
  attached files, or paths too long to read, ask the owner, since not all of them are checked.
- Cloud metadata: a command, code, a page load or a third-party tool that names a cloud metadata service in the
  call itself (`169.254.169.254`, `metadata.google.internal`, the ECS, EKS, GCE, Alibaba and Tencent addresses, in
  decimal, hex, octal or IPv6 forms, behind `sudo`, `env`, `xargs`, pipes or `busybox` too) is a wall
  (`walls.cloud_metadata`, on by default). A command line whose every program only reads or files text (`grep`, a
  firewall rule, a commit message) may name it, and so may a file being written. It works on the call's own text,
  not on DNS, redirections or a script run later: see the threat model for what it cannot see and the server
  settings that close the rest.
- Commands hidden in backquotes or in a quoted `"$(...)"` are now read like any other (a comment or a heredoc with
  an apostrophe no longer hides them): after untrusted content, a download or a send hidden there asks the owner.
- A file written through the shell counts as written by the conversation: a redirection (`>`, `>>`, `1>`, `&>`),
  `tee`, a download (`curl -o`, `curl -O`, `wget`), also inside a substitution, `sh -c`, `eval` or a heredoc read by
  a shell. Run later in a tainted conversation, it asks the owner, as a file written with a file tool already did.
  Defining a git alias after untrusted content asks too (it runs a command later under another name).
- A file written in a sealed conversation is "run" only when it is the program, or the script an interpreter or a
  runner is given (`sh x.sh`, `python3 x.py`, `uv run x.py`, `awk -f x.awk`, `tsx x.ts`): `git add dates.py` after
  editing `dates.py` no longer asks.
- README: an ordinary session, recorded with a real model, and how often airlock asks in it.
- `destinations_follow` (by @ether-btc, #2): set it to `approve` and, after untrusted content, a bare page load or
  fetch (`browser_navigate`, `web_extract`...) of a host that content named asks the owner, even with no data in the
  URL. Off by default, so merely-followed links stay free; the default changes nothing.
- Not covered, documented in the threat model: attachments in the agent's final reply or a cron job's output, which
  make no tool call; binary formats (PDF, archives) are not opened.

## 0.2.1 — 2026-10-24

- Fixed a regular expression that could backtrack exponentially on a crafted command (`dig` followed by many
  `!==!`-like words), stalling the check of that call. Found by GitHub code scanning (CodeQL `py/redos`). Matching is
  unchanged; a regression test keeps it under a time bound.

## 0.2.0 — 2026-10-23

Defenses that catch an injection by its signature, whatever the command looks like:

- Secrets never leave: recognized key and token formats in a call that leaves the machine are blocked
  (`secrets_out`), in every conversation and whatever the approvals.
- Canary: a private marker in the agent's context every turn; seen in a tool call, the call is blocked and the
  conversation locked (`canary`).
- Destinations: after untrusted content, a call to a host or e-mail address that the content named is blocked
  (`destinations`); a named mail recipient asks the owner. The pages read themselves (the source, search results)
  and common hosts are not counted; a page that names thousands of addresses makes every address count.
- Circuit breaker: three refused calls in a tainted conversation lock it until the owner clears it (`breaker`).
- Unicode: compatibility forms folded (NFKC), invisible and direction-changing characters refused in commands,
  program names that mix lookalike letters (Cyrillic, Greek) with Latin ones, or use IPA, fullwidth or mathematical
  letters, refused. A name written in another script (`./отчёт.sh`) and ordinary punctuation (`…`, `，`) stay free.
- Code review fixes since 0.1.0: case-insensitive filesystems (macOS, Windows), oversized content, `rm -rf ~/*`,
  empty variables inside paths, a concurrency issue that could drop a taint.

## 0.1.0 — 2026-10-23

First public version.

- Taint: web, browser, MCP and plugin output, network reads in commands and code, untrusted paths, customer-facing
  platforms. Subagents inherit their parent's taint; a child's taint reaches its parent. Saved across restarts.
- Outbound categories with clean and tainted levels: message, network_write, publish, remote, install, persistence,
  delegation, browser_input, exfil_url, detach, written_script, unadmitted_tool, bypass.
- Walls: credential paths and secret file names, guard and configuration files, startup files, other profiles,
  forbidden words, commands that disable the guard or change identity, destructive deletions.
- Shell reading: quoting, heredocs, `sh -c`, `eval`, `find -exec`, inline code, decoding piped to interpreters,
  computed program names, aliases, wildcard program names, files written then executed.
- `hermes airlock` (status, check, demo, log, stop, resume, clear, policy) and `/airlock`.
- Observe mode, journal, stop switch, exact-call approval keys, fail-closed on internal errors.
