# Policy reference

airlock reads [default_policy.yaml](../airlock/default_policy.yaml), then your file, by default `<HERMES_HOME>/airlock.yaml`
(set another path with `plugins.entries.airlock.settings.policy_file` in `config.yaml`). Your file is merged on top:
mappings merge key by key, lists are appended. The file is reloaded when it changes; no restart needed.

A file that does not parse, or a pattern that does not compile, is reported by `hermes airlock policy` and in
Hermes's log. A file that does not parse is ignored as a whole: the default policy stays in force.

Placeholders in paths: `{home}`, `{hermes_home}` (the active profile), `{hermes_root}` (`~/.hermes`), `{plugin_dir}`,
`{policy_file}`, `{data_dir}` (airlock's journal, taint state and stop switch).

## `mode`

`enforce` (default) or `observe`. In observe mode airlock never blocks nor asks; it writes `would_block`,
`would_approve` and `would_log` entries to the journal. Use it to see what airlock would do on your real work before
you turn it on.

## `profiles`

Profiles airlock guards. Empty (default) means every profile where the plugin is enabled.

## `actions`

For each category, the level in a clean conversation and in a tainted one: `allow`, `log` (allowed and written to the
journal), `approve` (Hermes asks a human; fails closed where nobody can answer) or `block`.

```yaml
actions:
  publish: {clean: log, tainted: approve}
  unadmitted_tool: {clean: block, tainted: block}
```

Categories: `message`, `network_write`, `publish`, `remote`, `install`, `persistence`, `delegation`,
`browser_input`, `exfil_url`, `detach`, `written_script`, `unadmitted_tool`, `bypass`. Walls are not a category:
they always block.

## `secrets_out`, `canary`, `destinations`, `destinations_follow`, `breaker`

| Key | Default | Meaning |
|---|---|---|
| `secrets_out` | `block` | A recognized secret (private key, AWS, GitHub, GitLab, OpenAI, OpenRouter, Anthropic, DeepSeek, Groq, xAI, Perplexity, Slack, Stripe, Google, Telegram, Hugging Face, npm token, JWT) in a call that leaves the machine: `block` or `approve` |
| `canary` | `true` | A private marker in the agent's context every turn (stored in airlock's data directory). In a tool call, it blocks the call and locks the conversation |
| `destinations` | `block` | After untrusted content, a call that leaves to a host or address this content named: `block`, `approve` or `off`. Common hosts (GitHub, Google, PyPI...) and the pages read themselves (the source, search results) are not counted |
| `destinations_follow` | `allow` | A bare page load or fetch of a host the untrusted content named, with no data in the URL itself: `allow` keeps merely-followed links free, `approve` asks on every one |
| `breaker` | `3` | Refused calls in a tainted conversation before it is locked until the owner clears it; `0` never locks |

## `approvals_off`

`block` (default) or `follow`. When Hermes would approve without asking anyone (`--yolo`, `/yolo`, `hermes -z`,
`approvals.mode: off`, a cron job, `-q` run or webhook whose `approvals.*_mode` is `approve`, a subagent under
`delegation.subagent_auto_approve`), `block` turns every "asks you" into a block; `follow` lets Hermes
auto-approve it like its own prompts.

## `walls`

| Key | Meaning |
|---|---|
| `read_write` | Paths the agent may neither read nor write, with any tool or command |
| `write` | Paths the agent may read but never write (the guard, Hermes's config, startup files) |
| `secret_files` | Regular expressions on full paths: files that hold secrets wherever they are |
| `secret_files_except` | Paths that match `secret_files` but are not secrets (`.env.example`, design tokens) |
| `isolate_profiles` | `true` (default): another Hermes profile's directory is out of reach |
| `cloud_metadata` | `true` (default): a command, code, a page load or a third-party tool that names a cloud metadata service (`169.254.169.254`, `metadata.google.internal`...) in the call itself is refused: the service hands out the server's credentials. Free: messages, memory, web searches, session searches, delegated goals, scheduled prompts, files being written, and command lines whose every program only reads or files text (`grep`, `nft`, `iptables`, local `git` subcommands, `cd`), with no substitution and no option that runs another program (a pager, a preprocessor, an external diff). By name only: see the threat model for what it cannot see |
| `words` | Case-insensitive regular expressions that must never appear in any tool call (a command, a file being written, a message) |
| `commands` | `{id, pattern, reason}`: commands refused outright (switching the guard or approvals off, changing `HERMES_HOME`) |
| `destructive` | Patterns of catastrophic deletions |

Your file can add walls but not remove the default ones: lists are appended, and `disable` only reaches
`walls.commands` and `egress` ids. To narrow a default wall, edit your copy of the plugin, knowingly.

Paths are checked after resolving `~`, variables, symlinks and `..`, in the arguments of file tools, in message attachments
(`MEDIA:<path>`), in commands and code (including paths built in pieces: `os.path.join('~', '.ss' + 'h')`, `Path.home() / '.aws'`), and through
wildcards (`~/.ss*/id_*`).

## `egress`

Detectors of outbound actions: `{id, category, pattern}`, plus `match: raw` to match the raw command text instead of
what it runs. Patterns are matched against each simple command's words (a quoted text containing spaces, such as a
commit message, shows as `…`), the inside of `sh -c`, `eval`, `find -exec` and heredocs, inline code, literal argument
lists in Python (`["git", "push"]`), and the unmasked forms of all of these (quotes and string concatenations
removed).

Add your own:

```yaml
egress:
  - {id: stripe-api, category: network_write, pattern: '\bstripe\b[^\n;&|]*\s(charges|refunds|payouts)\s+create\b'}
```

## `persistence_paths`

Files that hold what the agent remembers or runs later (`memories/`, `skills/`, `cron/`, `SOUL.md`). Writing them
with a file tool or a command counts as `persistence`, like the `memory`, `skill_manage` and `cronjob_manage` tools.
Git hooks and the repository config (`.git/hooks/`, `.git/config`, `.husky/`) count too, wherever the repository is. Reading them is free.

## `tool_categories` and `read_actions`

Hermes tools by category (`send_message: message`, `memory: persistence`...), and the actions of a tool that only read
(`memory: [read, list]`). A tool listed here with a read action is not outbound.

## `taint`

| Key | Meaning |
|---|---|
| `enabled` | `true` by default |
| `source_tools` | Tools whose output taints the conversation (web, browser, X search, A2A, Discord...) |
| `source_patterns` | Commands and code that read from the network (`curl https://...`, `git clone`, `requests.get`...) |
| `trusted_domains` | Reading only from these domains (and their subdomains) does not taint |
| `untrusted_paths` | Reading files under these paths, with a file tool or a command, taints (`~/Downloads` by default) |
| `platforms` | Conversations on these platforms are tainted from their first message (customer-facing agents) |
| `ttl_hours` | A taint expires after this long without new untrusted reads (72 by default) |

A conversation's taint ends when the conversation is reset (`/new`), when it expires, or when the owner clears it
(`/airlock clear`, `hermes airlock clear <session>`). Taint is saved to disk: a restart does not clear it.

## `tools`

| Key | Meaning |
|---|---|
| `admitted_plugins` | Plugins whose tools you have read and accept |
| `admitted_mcp_servers` | MCP servers (names as in `mcp_servers`) whose tools you accept |
| `admitted_tools` | Single tools you accept |
| `trusted_output` | Admitted plugins, servers or tools whose output does not taint the conversation |

## `owner_channels`

Chats that belong to the owner: a `send_message` there is not outbound. `auto` (default) reads the home channels in
the profile's `config.yaml`; add `"platform:chat_id"` entries if needed.

## `journal`

`enabled` (default `true`), `args` (`full` writes the tool's arguments, truncated; `none` writes only names and
reasons), `max_mb` (the journal is rotated once past this size).

## `disable`

Ids of built-in `egress` detectors or `walls.commands` to switch off:

```yaml
disable: [hermes-chat, detach]
```
