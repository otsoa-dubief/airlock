<p align="center"><img src="docs/images/banner.png" alt="airlock — guardrails for Hermes Agent. Once a conversation reads something untrusted, nothing leaves without you." width="100%"></p>

<p align="center">
  <a href="https://github.com/otsoa-dubief/airlock/actions/workflows/ci.yml"><img src="https://github.com/otsoa-dubief/airlock/actions/workflows/ci.yml/badge.svg" alt="tests"></a>
  <img src="https://img.shields.io/badge/Hermes%20Agent-%E2%89%A5%200.21.6-0A0E1A" alt="Hermes Agent ≥ 0.21.6">
  <img src="https://img.shields.io/badge/license-Apache--2.0-0A0E1A" alt="Apache-2.0">
  <img src="https://img.shields.io/badge/network-none-0A0E1A" alt="no network">
</p>

An agent that can read the web, read your mail and run commands can be talked into sending your data somewhere. The
words that do it are hidden in what it reads: a web page, an email, an issue, a tool's output. **airlock** checks
every tool call [Hermes Agent](https://github.com/NousResearch/hermes-agent) makes, remembers which conversations have
read untrusted content, and seals them: messages, uploads, pushes, posts and memory writes wait for your approval.
Reading, searching and drafting stay free.

<p align="center"><img src="docs/images/live-session.gif" alt="A real Hermes session with airlock: asked to summarize a pricing page and post the summary to a webhook, the agent reads the page (which hides instructions for AI assistants); the webhook post stops at Hermes's approval menu with airlock's reason; the owner denies it; the agent delivers the summary, sends nothing and flags the injection." width="100%"></p>

<p align="center"><sub>A real session, recorded, not simulated: a development build of Hermes Agent 0.22.2, airlock, <code>claude-haiku-5-5</code>. The
<a href="docs/images/src/session/pricing.html">pricing page</a> hides a note for AI assistants. Once the agent has read
it, the post to the webhook waits at Hermes's own approval menu; the owner picks Deny.</sub></p>

## What it does

- **Seals tainted conversations.** Web pages, browser snapshots, MCP and plugin tool output, `curl`/`git clone`
  reads, files in `~/Downloads` and (if you say so) messages from customers taint the conversation. From then on, a
  configurable set of actions needs a human: messages to anyone but you, network writes, pushes and deploys, memory
  and skill writes, scheduled jobs, browser clicks, URLs that could carry data out, handing work to another agent.
  Subagents inherit their parent's taint, and a child's findings taint the parent.
- **Walls that hold in every session.** Credentials (`~/.ssh`, `~/.aws`, `.env`, browser profiles, Hermes's own
  `auth.json`...), the guard itself and Hermes's configuration (readable, never writable by the agent), shell and
  login startup files, other Hermes profiles on the same machine, commands that would switch the guard or the
  approvals off, catastrophic deletions, a call that names the cloud metadata service handing out a server's credentials. A file
  behind a wall cannot be attached to a message sent with `send_message` either.
- **Reads commands the way the shell does.** Quotes, variables, `eval`, `base64 | sh`, `curl | bash`, process
  substitution, aliases, wildcard program names, `sh -c`, `find -exec`, heredocs, inline Python, Perl, Ruby and
  Node: a command that computes or hides what it runs is refused with a short note asking the agent to write it in
  clear. Everyday pipes (`curl ... | jq`, `... | python3 -c 'import json...'`, `| perl -pe 's/a/b/'`) stay free.
- **Catches an injection by its signature.** Secrets in a recognizable format (private keys, cloud, GitHub, OpenAI,
  Anthropic, Slack, Stripe tokens...) never leave in a call, whatever the conversation. A private marker sits in the
  agent's context: if it shows up in a tool call, the agent is copying out its own instructions, and the conversation
  is locked. After untrusted content, a call to an address that this content named is blocked outright. Three
  refused calls in a tainted conversation lock it until you review it. Program names spelled with lookalike letters
  (`ɡit`, Cyrillic `с`) and invisible characters are refused.
- **Refuses tools nobody admitted.** A tool from a third-party plugin or an MCP server is something airlock cannot
  read. It needs approval until you admit it in your policy, and its output taints the conversation unless you trust
  it.

Everything is local: no network call, no LLM call, no telemetry. Decisions, taints and approvals go to a journal in
the plugin's data directory. If airlock itself crashes on a call, that call is blocked, not waved through.

## Install

```bash
hermes plugins install otsoa-dubief/airlock/airlock --force --enable
hermes gateway restart        # if a gateway is running
```

Why `--force`: Hermes scans every plugin it installs, and airlock's policy lists the very things it guards against
(shell startup files, `crontab`, credential commands, exfiltration patterns). The scanner reports them as
`caution`, never `dangerous`, and asks for `--force` before installing a community plugin with that verdict. Read
the findings it prints. Once airlock is listed in the Hermes catalog, `hermes plugins install airlock` will need no
flag.

Then start a new session, and restart a running gateway so it loads the plugin. `hermes airlock status` shows what
is in force; `/plugins` in a session lists the plugins loaded.

Try it without risk first: put `mode: observe` in `~/.hermes/airlock.yaml`. airlock then never interferes and only
writes what it would have done to its journal (`hermes airlock log`).

## Try it without a model

`hermes airlock demo` plays a prompt-injection attempt against the policy in force on your machine. Nothing is
executed, journaled or tainted.

<p align="center"><img src="docs/images/demo.gif" alt="hermes airlock demo: an agent reads a pricing page hiding instructions; the conversation is sealed; sending the SSH key is blocked, planting a memory rule and leaking a token in a URL ask the owner, the disguised retry is blocked, the summary is written." width="100%"></p>

## An ordinary session

How often does airlock ask? A real session, not simulated: Hermes Agent 0.22.2 with airlock 0.2.2 in enforce mode,
`claude-haiku-5-5`, a small Python repository with one failing test. The task: *run the test suite; fix `dates.py`
so ISO dates with a time part parse (check the Python docs for `datetime.fromisoformat`); rerun the tests; commit
and push; tell me what changed.*

| # | The agent's call (each row is one tool call) | airlock |
|---|---|---|
| 1 | `git status && git branch && git remote -v && ls -la && find ...` | free |
| 2 | reads the Python docs page (`web_extract`) | free; the conversation is now sealed (untrusted content read) |
| 3 | `cat dates.py && cat test_dates.py && cat README.md && python3 -m pytest -q` | free |
| 4 | opens the same docs page in the browser | free |
| 5 | patches `dates.py` | free |
| 6 | `python3 -m pytest -q; git config user.name; ...` | free |
| 7 | `git status -sb && git log --oneline -3 && git diff --stat` | free |
| 8 | `git add dates.py && git commit ... && git push origin main` | **asks you**: publishes outside this machine |
| 9 | `git add dates.py && git commit ...` (the same, without the push) | free |

Nine calls, one question, at the moment code was about to leave the machine. Reading the web, editing files, running
tests and committing locally stay quiet, sealed conversation or not. The run was unattended (`hermes chat -q`), so
nobody could approve call 8 and it did not run: the agent said so, committed without pushing, and left the push to
the owner.

In an earlier run of the same task the agent wrote a command with a variable as its program
(`V=.../venv; $V/bin/python -m pytest`). airlock refused it as a computed command, the agent wrote the path in
clear on the next call, and the session went on. That refusal is the cost of reading commands the way the shell
does; it happens when an agent writes one, not on every task.

## How it decides

<p align="center"><img src="docs/images/how-it-works.png" alt="Clean conversation: work as usual, outbound actions ask you. After reading something untrusted, the conversation is sealed: memory, browser clicks, delegation, pushes, messages and data-carrying URLs ask you. Walls and bypasses are blocked in every conversation." width="100%"></p>

Each tool call gets the strictest of what applies:

| Category | Examples | Clean conversation | Tainted conversation |
|---|---|---|---|
| wall | `~/.ssh`, `.env`, the guard's files, `hermes config set`, `--yolo`, `rm -rf ~` | **block** | **block** |
| secret | a recognized key or token in a call that leaves the machine | **block** | **block** |
| canary | airlock's private context marker in any tool call (the conversation is then locked) | **block** | **block** |
| destination | a call to a host or address named by the untrusted content read | free | **block** |
| locked | anything outbound in a conversation locked by the canary or by 3 refused calls | **block** | **block** |
| bypass | `eval "$(...)"`, `base64 -d \| sh`, `$G push`, `/usr/bin/g?t push` | **block** | **block** |
| message | `send_message` to a third party, `mail`, Slack and Discord webhooks | asks you | asks you |
| network_write | `curl -d`, `curl -T`, `requests.post`, `nc host port`, SMTP | asks you | asks you |
| publish | `git push`, `gh pr create`, `npm publish`, `vercel --prod`, `kubectl apply` | asks you | asks you |
| remote | `ssh host cmd`, `scp`, `rsync host:` | asks you | asks you |
| install | installing a catalog plugin or connector from inside the session | asks you | asks you |
| detach | `nohup ... &`, `setsid`, `tmux new -d` | asks you | asks you |
| unadmitted_tool | a plugin or MCP tool not admitted in your policy | asks you | asks you |
| persistence | `memory` writes, `skill_manage`, cron jobs, `crontab`, `launchctl` | logged | asks you |
| delegation | `kanban_create`, another agent session (`hermes chat -q`) | free | asks you |
| browser_input | `browser_click`, `browser_type`, `browser_exec`, saved logins | free | asks you |
| exfil_url | a URL whose query, path or host name carries encoded data; after untrusted content, any network call from the shell or from code to a host you have not trusted | free | asks you |
| written_script | running a file this conversation wrote | free | asks you |

"Asks you" uses Hermes's own approval gate (`approve` in the policy): a prompt in the terminal, buttons on Telegram and other gateways. Where
nobody can answer (cron jobs, unattended runs), it fails closed. Approving "always" covers that exact call only,
never a family of calls.

Messages to your own home channels are not outbound. Everything in the table is a setting.

When nobody can approve (`--yolo`, `/yolo`, `hermes -z`, `approvals.mode: off`, a cron job, `-q` run or webhook set
to approve, a subagent under `delegation.subagent_auto_approve`), Hermes would let "asks you" actions through on its
own. airlock blocks them instead; set `approvals_off: follow` in your policy to let Hermes decide.

## Configure

Your policy lives in `~/.hermes/airlock.yaml` (per profile: `<HERMES_HOME>/airlock.yaml`). It is merged on top of
[the default policy](airlock/default_policy.yaml): mappings merge key by key, lists are appended. A broken file never weakens
the guard: airlock keeps the default and says why in `hermes airlock policy`.

```yaml
# ~/.hermes/airlock.yaml
taint:
  trusted_domains: [docs.python.org, internal.example.com]   # reading these does not taint
  platforms: [email, whatsapp]       # an agent that answers customers: their messages are untrusted from the start
tools:
  admitted_mcp_servers: [linear]     # you read what it does; its tools no longer need approval
  trusted_output: [linear]           # and its output does not taint
actions:
  publish: {clean: log, tainted: approve}    # a coding agent that pushes freely until it reads the web
walls:
  words: ['acme\s*corp']             # a name that must never appear in anything this agent writes or sends
```

More in [docs/policy.md](docs/policy.md) and [examples/policies](examples/policies).

## Commands

<p align="center"><img src="docs/images/check.png" alt="hermes airlock check: a commit is allowed, git push asks the owner, reading an SSH key is blocked, a computed command is blocked, a curl after untrusted content asks the owner." width="100%"></p>

| Command | What it does |
|---|---|
| `hermes airlock status` | Mode, policy file, stop switch, tainted conversations |
| `hermes airlock demo` | Plays a prompt-injection attempt against your policy; nothing is executed |
| `hermes airlock check "git push"` | Dry run: what airlock would do (`--tainted`, or `--args '{...}'` for any tool) |
| `hermes airlock log` | Last journal entries (`--type block`, `-n 50`) |
| `hermes airlock stop` / `resume` | Stop switch: every outbound action is blocked until you resume |
| `hermes airlock clear <session>` | Clear a conversation's taint after you reviewed what it read |
| `hermes airlock policy` | The merged policy in force, and any error in your file |
| `/airlock` in a conversation | This conversation's state; `/airlock clear` (owner only) lifts its taint |

The agent itself cannot run `resume` or `clear`, and cannot touch the stop switch file, the policy or the journal.

## What airlock does not do

airlock is a guard on what the agent asks its tools to do. It is one layer, not a sandbox.

- **It reads text.** A program already on disk (written by another route) and launched by name is out of reach of a
  text-level guard. Inside a tainted conversation, running a file the conversation wrote itself does need approval.
- **It does not inspect what an approved action carries.** Approving a push or a message approves its content. Read
  the approval prompt.
- **It cannot stop a human who approves everything.** Approvals are the point where you decide.
- **Environment variables are not walls.** A secret exported in the agent's environment can be printed
  (`printenv`). Keep secrets out of the agent's environment, or in Hermes's own secret store.
- **Signatures catch the common shapes.** Secret formats, the canary and named destinations are recognized in the
  forms an injection usually takes (encoded, split, quoted, in another script), not in every possible form. What they
  miss still meets the ordinary approval in a tainted conversation. Details in
  [docs/threat-model.md](docs/threat-model.md#what-stays-out-of-reach).
- **Some memory is per process.** The link between a subagent and its parent, and the list of files a conversation
  wrote, do not survive a restart. Taints do.
- **On Windows, it reads Git Bash.** Hermes's terminal on Windows is Git Bash, and airlock reads its commands
  and paths (`/c/...`, `C:\...`, `$USERPROFILE`). It does not read PowerShell or `cmd` syntax: a command run
  through `powershell -c` or `cmd //c` is only checked for the patterns it is known to use (recursive deletion,
  `schtasks`, the registry `Run` key). Paths on another machine (`\\host\share`) are refused. Write your own
  `secret_files` patterns with `/`: airlock compares every path in that form.
- **It runs inside Hermes.** For hard isolation, run the agent's terminal on an isolated backend (Docker, SSH) and
  keep your credentials where the agent's user cannot read them. airlock is built for Hermes's default in-process
  plugins: under `plugins.isolation: host` it cannot tell a third-party plugin's tools from Hermes's own, and
  `hermes airlock` commands are not available. See [docs/threat-model.md](docs/threat-model.md).

## What airlock reads and writes

- Reads your profile's `config.yaml` (your home channels, and whether approvals are switched off) and its own
  policy file.
- Reads directory listings to expand wildcards in commands (`cat ~/.ss*/*`), so a pattern cannot hide a protected
  path.
- Writes, in its data directory (`<HERMES_HOME>/plugin-data/airlock/`): a journal of decisions, taints and approvals
  (tool arguments included, truncated; `journal: {args: none}` to leave them out), the taint state, and the stop
  switch.
- Makes no network call and no LLM call, and runs no command.

## Tests

```bash
python -m pytest tests                       # unit tests and the attack corpus (tests/corpus.yaml)
scripts/test_in_hermes_image.sh              # catalog validation, plugin doctor and an end-to-end hook test in a
                                             # throwaway container of the official Hermes image
```

[tests/corpus.yaml](tests/corpus.yaml) lists every attack and every everyday command airlock is checked against,
with the expected decision. A fix or a new rule comes with its case there.

## Origin

airlock is the open version of the guard that runs the team of Hermes agents at
[Taskaway](https://taskaway.fr), where we deploy Hermes agents for small businesses. The rules specific to that
team are left out; what remains is what any Hermes install can use. Maintained by
[Otsoa Dubief](https://www.linkedin.com/in/otsoa-dubief/).

Hermes Agent is an open-source project by Nous Research. airlock is an independent plugin, not affiliated with or
endorsed by Nous Research.

## License

[Apache-2.0](LICENSE) · Copyright 2026 Otsoa Dubief. Redistributions keep the [NOTICE](NOTICE) file. Security issues: see [SECURITY.md](SECURITY.md).
