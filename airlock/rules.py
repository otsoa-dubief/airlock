# Copyright 2026 Otsoa Dubief
# SPDX-License-Identifier: Apache-2.0
"""The decision: given a policy, a tool call and what airlock knows about the session, what happens.

Pure functions, no Hermes import: everything Hermes-specific is gathered by the plugin (``__init__.py``) and passed in
``Context``. Tested by tests/test_corpus.py (cases in tests/corpus.yaml) and tests/test_taint.py.
"""
from __future__ import annotations

import glob
import ipaddress
import itertools
import json
import os
import re
import stat
from dataclasses import dataclass, field
from urllib.parse import unquote, urlparse

from . import guards, shell

ORDER = {"allow": 0, "log": 1, "approve": 2, "block": 3}

COMMAND_TOOLS = {"terminal": "command", "execute_code": "code"}
FILE_READ_TOOLS = {"read_file", "search_files", "list_directory", "read_window_below"}
FILE_WRITE_TOOLS = {"write_file", "patch"}
PATCH_FILES = re.compile(r"^\*\*\*\s+(?:Update|Add|Delete|Move to)\s+File:\s*(.+)$", re.M)
URL = re.compile(r"https?://[^\s\"'`<>)\]}]+", re.I)
SCRIPT_EXT = re.compile(r"\.(sh|bash|zsh|py|pyw|js|mjs|cjs|ts|rb|pl|php|lua|ps1|command|bat|cmd)$|(^|/)(Makefile|"
                        r"Justfile|Rakefile|Dockerfile|[^/.]+)$", re.I)


NET_COMMAND = re.compile(r"(^|\n)(curl|wget|http|https|xh|xhs|nc|ncat|netcat|socat|telnet|dig|nslookup|host|drill|"
                         r"ping|ping6|traceroute|tracepath|mtr|whois|ftp|lftp|aria2c|lynx|w3m|links)\b", re.M)
NET_HOSTS = re.compile(r"(?:^|\n)(?:dig|nslookup|host|drill|ping|ping6|traceroute|tracepath|mtr|whois|nc|ncat|netcat|"
                       r"telnet)\b(?:\s+-\S+)*(?:\s+[^\s=-][^\s=]*=\S*)*\s+@?([A-Za-z0-9.-]+\.[A-Za-z]{2,})", re.M)
URL_OR_HOST_SUBST = re.compile(r"https?://[^\s\"']*(\$\(|`)|(\$\(|`)[^\s]*\.[A-Za-z]{2,}|"
                               r"\s(-d|--data[\w-]*|-H|--header|-F|--form)\s*([\"'])[^\"']*(\$\(|`)|"
                               r"\s(-d|--data[\w-]*|-H|--header|-F|--form)\s*[^\s\"']*(\$\(|`)")
BUILD_TOOLS = {"make", "gmake", "npm", "pnpm", "yarn", "bun", "npx", "pip", "pip3", "uv", "poetry", "pipx", "cargo",
               "gradle", "gradlew", "mvn", "just", "rake", "docker", "docker-compose", "podman", "tox", "nox",
               "pytest", "deno", "go"}
BUILD_FILES = {"Makefile", "makefile", "GNUmakefile", "package.json", "setup.py", "setup.cfg", "pyproject.toml",
               "Cargo.toml", "build.rs", "build.gradle", "build.gradle.kts", "pom.xml", "Justfile", "justfile",
               "Rakefile", "Dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
               "tox.ini", "noxfile.py", "conftest.py", "deno.json", "go.mod", ".npmrc", "requirements.txt"}


# Files git runs or reads commands from later: hooks, and the repository config (core.hooksPath, core.fsmonitor...).
GIT_HOOKS = re.compile(r"(^|/)\.git/(hooks(/|$)|config$)|(^|/)\.husky(/|$)")

TOOL_REASONS = {
    "message": "sends a message to someone other than the owner",
    "persistence": "writes what the agent remembers or runs later",
    "delegation": "hands work to another agent",
    "browser_input": "acts in the browser (click, type, run code, saved logins)",
    "install": "installs a plugin, skill or connector",
}


@dataclass
class Context:
    """What the plugin knows around a tool call."""
    cwd: str = ""
    home: str = shell.real(os.path.expanduser("~"))
    hermes_home: str = ""
    hermes_root: str = ""
    profile: str = "default"
    tainted: str | None = None              # what made the session untrusted, if anything
    origin: str | None = None               # "core", "plugin:<name>", "mcp:<server>", or None if unknown
    owners: set = field(default_factory=set)   # chat ids of the owner's own channels
    written: set = field(default_factory=set)  # files this session wrote (paths), to spot "write then run"
    stopped: bool = False                   # the kill switch is on
    canary: str | None = None               # the marker airlock puts in the agent's context; never in a tool call
    destinations: set = field(default_factory=set)  # hosts and addresses named by the untrusted content read
    attachments: object = None              # Hermes's own reading of a message's attachments (text -> paths), if loaded
    locked: str | None = None               # why this session is locked (canary seen, repeated refused attempts)


@dataclass
class Decision:
    level: str                              # allow, log, approve, block
    category: str
    reason: str
    rule: str = ""
    wall: bool = False

    def worse(self, other):
        return other if other and ORDER[other.level] > ORDER[self.level] else self


# --- Helpers ----------------------------------------------------------------------------------------------------

def under(path, root):
    if not path or not root:
        return False
    if path == root or path.startswith(root.rstrip("/") + "/"):
        return True
    # On a case-insensitive filesystem, ~/.SSH is ~/.ssh: fold case or the walls are bypassed by changing case.
    if shell.CASE_INSENSITIVE_FS:
        pl, rl = path.lower(), root.lower()
        return pl == rl or pl.startswith(rl.rstrip("/") + "/")
    return False


def _texts(value):
    """Every string inside a tool's arguments, dict keys included."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str):
                yield k
            yield from _texts(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _texts(v)


LOOPBACK = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
# Code that can reach the network, in any language Hermes can run. After untrusted content, its address, body or timing
# can carry data out, whatever the method.
CODE_NETWORK = re.compile(
    r"\b(urlopen|urlretrieve|Request\s*\(|requests\.|httpx\.|aiohttp|urllib3|http\.client|HTTPS?Connection|"
    r"socket\.(socket|create_connection)|smtplib|ftplib|telnetlib|xmlrpc|websockets?\b|paramiko|pycurl|"
    r"fetch\s*\(|XMLHttpRequest|axios|https?\.(request|get)\s*\(|require\(\s*[\"']https?[\"']\s*\)|"
    r"node:https?|net\.connect|Net::HTTP|open-uri|URI\.open|TCPSocket|LWP::|HTTP::Tiny|IO::Socket|"
    r"curl_exec|fsockopen|file_get_contents\s*\(\s*[\"']https?:|Invoke-WebRequest|Invoke-RestMethod)")
SHELL_NETWORK_RAW = re.compile(r"/dev/(tcp|udp)/|\bopenssl\s+s_client\b|\b(nc|ncat|netcat|socat|telnet)\b")


def _domain_trusted(url, pol):
    host = guards.hostname(url)
    return bool(host) and any(host == d or host.endswith("." + d) for d in pol.trusted_domains)


def _loopback(url):
    host = guards.hostname(url)
    if host in LOOPBACK or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_unspecified                             # 127.0.0.0/8, ::1, 0.0.0.0


def _local_host(host, pol):
    """True for a host (or the domain of an e-mail address) on this machine or in a trusted domain."""
    host = host.rpartition("@")[2]
    return _loopback("https://" + host) or _domain_trusted("https://" + host, pol)


def failed(result):
    """True if a tool result says the call failed before reading anything (structured error, nothing returned)."""
    data = result
    if isinstance(result, str):
        try:
            data = json.loads(result)
        except ValueError:
            return False
    if not isinstance(data, dict):
        return False
    if data.get("success") is False or data.get("ok") is False:
        return True
    if data.get("error") and not any(data.get(k) for k in ("content", "results", "output", "data", "text", "pages")):
        return True
    results = data.get("results")
    if isinstance(results, list) and results and all(isinstance(x, dict) and x.get("error") and not x.get("content")
                                                     for x in results):
        return True
    return False


def _profiles_root(ctx):
    return os.path.join(ctx.hermes_root, "profiles") if ctx.hermes_root else ""


def pretty(path, ctx):
    """A path as the user would write it (~ for the home directory)."""
    home = (ctx.home or "").rstrip("/")
    return "~" + path[len(home):] if home and under(path, home) else path


REMOTE = "a path on another machine (Windows network share or device path)"


def access_wall(path, pol, ctx, remote=True):
    """Reason if a path may be neither read nor written by the agent, else None. remote=False leaves a //host/share
    word alone (a protocol-relative URL in a file being written is not a path)."""
    if not path:
        return None
    return next((r for r in (_access_wall(p, pol, ctx, remote) for p in shell.twins(path, ctx.cwd)) if r), None)


def _access_wall(path, pol, ctx, remote):
    if remote and shell.remote_path(path):
        return REMOTE
    for root in pol.read_write:
        if under(path, root):
            return f"protected path ({pretty(root, ctx)})"
    if any(rx.search(path) for rx in pol.secret_files) and not any(rx.search(path) for rx in pol.secret_except):
        return "file that holds secrets"
    if pol.isolate_profiles and ctx.hermes_root:
        profiles = shell.normalize(_profiles_root(ctx))
        own = shell.normalize(ctx.hermes_home) if ctx.hermes_home else ""
        # The default profile lives at the root, which holds the other profiles: none of them is its own.
        mine = own and own != shell.normalize(ctx.hermes_root) and under(path, own)
        if under(path, profiles) and path != profiles and not mine:
            return "another Hermes profile's data"
    return None


def opened_wall(path, pol, ctx):
    """access_wall for a path a tool opens itself (file tools, attachments, the browser): on Windows any \\\\ path,
    a bare server name included, is refused, since opening it connects to that machine."""
    return REMOTE if shell.unc(path) else access_wall(path, pol, ctx)


def write_wall(path, pol, ctx):
    """Reason if a path may not be written by the agent (read is fine), else None."""
    if not path:
        return None
    if shell.unc(path):
        return REMOTE
    for p in shell.twins(path, ctx.cwd):
        for root in pol.write_only:
            if under(p, root):
                return f"guard, configuration or startup file ({pretty(root, ctx)}): readable, never written by the " \
                       "agent"
    return access_wall(path, pol, ctx)


def _protected_matcher(pol, ctx, cwd):
    """A predicate on raw text: does it name a path the agent may not write? Used by shell.writes_protected."""
    roots = pol.write_only + pol.read_write
    seen_raw, seen_path = {}, {}

    def path_protected(c):
        if c not in seen_path:
            seen_path[c] = any(any(under(p, r) for r in roots) or any(rx.search(p) for rx in pol.secret_files) or
                               bool(pol.isolate_profiles and ctx.hermes_root and
                                    access_wall(p, pol, ctx) == "another Hermes profile's data")
                               for p in shell.twins(shell.normalize(c, cwd), cwd))
        return seen_path[c]

    def protected(raw):
        raw = raw or ""
        if raw not in seen_raw:
            cands = [m.group(0) for m in shell.cited_paths().finditer(shell.fold(raw))]
            cands += [t for t in re.split(r"[\s\"'=;&|<>(),]+", raw) if t] + shell.quoted_words(raw) + [raw.strip()]
            seen_raw[raw] = any(path_protected(c) for c in dict.fromkeys(cands))
        return seen_raw[raw]
    protected.roots, protected.cwd = roots, cwd
    return protected


def leading_cd(text, cwd):
    """The working directory after a leading ``cd <path> &&`` (written in clear), else cwd."""
    m = re.match(r"^\s*cd\s+(\"[^\"$`\\]*\"|'[^']*'|[^\s;&|<>`$\\'\"()]+)\s*&&", text or "")
    return shell.normalize(m.group(1).strip("\"'"), cwd) if m else cwd


def exfil_url(url, pol):
    """True if a URL to an untrusted host could carry data out in its query, path or host name."""
    if _domain_trusted(url, pol) or _loopback(url):
        return False
    try:
        parsed = urlparse(url)
    except ValueError:                                        # https://[x: unreadable, so not vouched for
        return True
    rest = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")
    encoded = [t for t in re.findall(r"[A-Za-z0-9+=%_-]{40,}", unquote(rest))
               if re.search(r"\d", t) and re.search(r"[A-Za-z]", t)
               and not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", t)        # git or content hashes
               and not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+){3,}", t)]       # slugs (words-joined-by-dashes)
    host_labels = [lb for lb in (parsed.hostname or "").split(".")[:-2] if len(lb) >= 32]
    return len(parsed.query or "") > 200 or bool(encoded) or bool(host_labels)


def tool_urls(tool, args):
    urls = []
    for k in ("url", "urls", "image_url", "video_url", "query", "command", "code", "expression", "endpoint", "href",
              "link", "src"):
        v = args.get(k)
        for t in _texts(v):
            urls += URL.findall(t)
            if k in ("url", "urls", "image_url", "video_url", "href", "link", "src") and re.match(r"^[\w.-]+\.[a-z]{2,}(/|$)", t.strip(), re.I):
                urls.append("https://" + t.strip())
    if tool.startswith("browser_cdp"):
        urls += URL.findall(json.dumps(args.get("params") or {}, default=str))
    return urls


# Tools that turn a MEDIA:<path> in their text into an attachment (Hermes's extract_media), and the argument that
# lists more attachments.
ATTACHING_TOOLS = {"send_message", "yb_send_dm"}
MEDIA_TAG = re.compile(r"MEDIA:", re.I)
# Where Hermes may end an unquoted path: blanks, markup, punctuation, CJK and fullwidth forms (MEDIA_TAG_CLEANUP_RE).
HERMES_END = re.compile(r"[\s`\"'*_,;:)\]}\[\u3000-\u303f\uff00-\uffef]")
# Every place a path could end, wider still: a dot, "<" (a model's end token) or another MEDIA: right after it.
MEDIA_END = re.compile(r"[\s`\"'*_,;:.<)\]}\[\u3000-\u303f\uff00-\uffef]|MEDIA:", re.I)
SIMPLEX_MEDIA = re.compile(r"MEDIA:(\S+)")    # SimpleX reads the cleaned text again, raw (adapter.send)
# A tag as Hermes deletes it from the text it sends (path, then up to three marks and a dot): used to rebuild that
# text when Hermes's own reader is not available.
MEDIA_DELETED = re.compile(r"[`\"'*_]{0,3}MEDIA:\s*(\"[^\"\n]+\"|'[^'\n]+'|`[^`\n]+`|"
                           r"(?:[~/]|[A-Za-z]:[\\/]|\\\\)[^\s`\"'*_,;:)\]}\[]*)"
                           r"[`\"'*_]{0,3}\.?", re.I)
WIN_ROOT = re.compile(r"[A-Za-z]:[\\/]|\\\\")
MEDIA_MAX_ENDS = 300            # an unquoted path with more possible ends than this is not read: the call is refused
MEDIA_MAX_CANDIDATES = 5_000    # same for a message whose tags give more candidate paths than this (a decision is fast)
MEDIA_MAX_PATH = 4096           # longest path a system opens: nothing past it is read after a tag
MEDIA_PASSES = 3                # removing a tag can glue the text around it into a new tag: read the result again
ATTACHMENT_READ = 200_000       # bytes of each attached file checked for secrets and the context marker
ATTACHMENT_FILES = 20
_attached_cache = {}


def media_candidates(text):
    """(path, sure) for every file a message could attach, and whether a path was too long to read. Read wider than
    Hermes reads it: after each MEDIA: (and its blanks, line breaks included) to the end of that line, examples in
    code or quotes included. An unquoted path may hold spaces or stop at any punctuation (MEDIA:~/My Files/a.pdf,
    MEDIA:~/p/.env;x): every prefix that ends where a path could end is a candidate. The one that ends where Hermes
    ends it is sure; another counts when that file exists, as Hermes sends only existing files. Unquoted, only
    absolute and ~ paths count, as for Hermes; SimpleX's raw reading (MEDIA: then anything up to a blank) is added."""
    text = text or ""
    out, overflow = [(p, True) for p in SIMPLEX_MEDIA.findall(text)], False
    for m in MEDIA_TAG.finditer(text):
        if len(out) > MEDIA_MAX_CANDIDATES:
            overflow = True
            break
        seg = text[m.end():m.end() + MEDIA_MAX_PATH + 64].lstrip()
        seg = seg.split("\n", 1)[0].rstrip("\r")[:MEDIA_MAX_PATH]
        if not seg:
            continue
        close = seg.find(seg[0], 1) if seg[0] in "\"'`" else -1
        if close > 0:
            quoted = seg[1:close].strip()
            out += [(quoted, True), (quoted.rstrip(",.;:)}]"), True)]     # as Hermes's _normalize_media_tag_path
            continue
        seg = seg.lstrip("\"'`*_")
        drive = shell.WINDOWS and bool(WIN_ROOT.match(seg))             # C:\..., C:/... or \\host\...
        if not (seg.startswith(("~", "/")) or drive):
            continue
        start = 3 if drive and seg[1] == ":" else 1                     # the drive's own colon ends nothing
        ends = []
        for x in MEDIA_END.finditer(seg, start):
            if x.start():
                ends.append(x.start())
            if len(ends) > MEDIA_MAX_ENDS:
                overflow = True
                break
        first = HERMES_END.search(seg, start)
        sure = first.start() if first else len(seg)
        for end in dict.fromkeys(ends[:MEDIA_MAX_ENDS] + [sure, len(seg)]):
            out.append((seg[:end].rstrip(), end == sure))
    return [c for c in dict.fromkeys(out) if c[0]], overflow


def attachment_path(path, cwd):
    """A path as Hermes opens it: ~ expanded, never variables ($HOME stays a directory name), links resolved."""
    return shell.real(shell.joined(cwd, path))


def attached(args, ctx):
    """The files the call would attach (normalized), whether a path was too long to read, and whether Hermes's own
    reader was used. airlock's reading is joined with Hermes's when the plugin could load it (ctx.attachments), on
    the message and on the text Hermes leaves once its tags are removed, read again until it stops changing."""
    message = str(args.get("message") or "")
    key = (id(args), message, repr(args.get("media_files")), str(args.get("target")), ctx.cwd)
    if key in _attached_cache:
        return _attached_cache[key]
    texts, cands = [message], []
    for item in args.get("media_files") or []:                   # yb_send_dm: {"path": ...} or (path, is_voice)
        p = item.get("path") if isinstance(item, dict) else \
            item[0] if isinstance(item, (list, tuple)) and item else None
        if isinstance(p, str):
            cands.append((p, True))
    hermes = bool(ctx.attachments and message)
    bare = str(args.get("target") or "").lower().split(":", 1)[0] == "weixin"   # Weixin also sends bare paths
    if hermes:
        current = message
        for _ in range(MEDIA_PASSES):
            try:
                paths, cleaned = ctx.attachments(current, bare)
            except Exception:                                    # Hermes's reader failing leaves airlock's own
                hermes = False
                break
            cands += [(p, True) for p in paths]
            if cleaned == current:
                break
            texts.append(cleaned)
            current = cleaned
    if not hermes:
        current = message
        for _ in range(MEDIA_PASSES):
            cleaned = MEDIA_DELETED.sub("", current)
            if cleaned == current:
                break
            texts.append(cleaned)
            current = cleaned
    overflow = False
    for text in texts:
        found, over = media_candidates(text)
        cands += found
        overflow = overflow or over
    out = []
    for p, sure in dict.fromkeys(cands):
        try:
            joined = shell.joined(ctx.cwd, p)
            # The cheap test first: most candidates are not files. A \\\\ path is never tested (see shell.unc).
            if sure or shell.unc(joined) or os.path.lexists(joined):
                out.append(shell.real(joined))
        except ValueError:                                       # a NUL byte: no file can be opened by that name
            continue
    _attached_cache[key] = result = (list(dict.fromkeys(out)), overflow, hermes)
    return result


def attachment_texts(pol, tool, args, ctx):
    """The start of each attached file's text, so a secret or the context marker in an attachment is seen as in the
    message itself: the first ATTACHMENT_READ bytes of each regular file, as UTF-8 text (a PDF, an archive or UTF-16
    text is not decoded), and None when more than ATTACHMENT_FILES regular files are attached (not all are read).
    Files behind a wall stay unread (the wall refuses them first)."""
    if tool not in ATTACHING_TOOLS:
        return []
    out = []
    for path in attached(args, ctx)[0]:
        if opened_wall(path, pol, ctx):                          # never opened: refused, or another machine
            continue
        try:                                                     # non-blocking: a FIFO swapped in must not hang
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        except (OSError, ValueError):                           # ValueError: a NUL byte, no file has that name
            continue
        try:
            if stat.S_ISREG(os.fstat(fd).st_mode):
                if len(out) >= ATTACHMENT_FILES:
                    return None
                out.append(os.read(fd, ATTACHMENT_READ).decode("utf-8", "ignore"))
        except OSError:
            pass
        finally:
            os.close(fd)
    return out


# Cloud instance metadata services hand the machine's credentials to whoever asks from inside it: no agent needs
# them, and an injected one reading them is the first step of taking over the server. A command that names the
# address is refused unless every program that names it only reads or files text (grep, a firewall rule, a commit);
# other tools are refused when a URL host or an address argument is the service.
METADATA_IPS = {ipaddress.ip_address(a) for a in ("169.254.169.254", "169.254.170.2", "169.254.170.23",
                                                  "100.100.100.200", "fd00:ec2::254", "fd00:ec2::23", "fd20:ce::254")}
METADATA_DOTTED = {"metadata.google.internal", "metadata.goog", "metadata.azure.com", "instance-data.ec2.internal",
                   "metadata.tencentyun.com"}
METADATA_SHORT = {"metadata", "instance-data"}                # names only as the host of a URL
METADATA_TEXT = re.compile(r"(?<![\d.])(169[.-]254[.-]169[.-]254|169[.-]254[.-]170[.-]23?|100[.-]100[.-]100[.-]200)"
                           r"(?!\d)|fd00:ec2::(254|23)\b|fd20:ce::254\b|metadata\.google\.internal|metadata\.goog\b|"
                           r"metadata\.azure\.com|instance-data\.ec2\.internal|metadata\.tencentyun\.com", re.I)
METADATA_VARS = re.compile(r"\b(ECS_CONTAINER_METADATA_URI(_V4)?|AWS_CONTAINER_CREDENTIALS_(FULL|RELATIVE)_URI|"
                           r"AWS_CONTAINER_AUTHORIZATION_TOKEN(_FILE)?)\b")
URL_ANY_HOST = re.compile(r"\b[a-z][\w+.-]*://(?:[^@/\s\"'<>]*@)?(\[[^\]\s]+\]|[^/\s:?#\"'<>]+)", re.I)
# Programs that only read, print or file text: naming the address there reaches nothing. A command names it freely
# only when every program of the whole line is one of these (a pipe to curl is not), with no substitution.
METADATA_SAFE_VERBS = {"grep", "egrep", "fgrep", "rg", "echo", "printf", "cat", "head", "tail", "wc", "sort", "uniq",
                       "diff", "cut", "tr", "jq", "yq", "tee", "iptables", "ip6tables", "nft", "ufw", "pfctl",
                       "firewall-cmd", "git", "cd", "pushd", "popd", "true"}
# Options or settings that make a "safe" program run another one, or a redirection that opens a network socket.
METADATA_UNSAFE = re.compile(r"/dev/(tcp|udp)/|--ext-diff|--compress-program|--diff-program|--use-compress-program|"
                             r"--pager|--open-files-in-pager|--exec-path|--pre\b|(?:^|\s)-O|"
                             r"\bcore\.(pager|fsmonitor|sshcommand|editor|hookspath)\b|\balias\.", re.I)
GIT_SAFE = {"commit", "log", "diff", "show", "grep", "add", "status", "blame", "shortlog"}
GIT_GLOBAL_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env"}
SUBSTITUTION = re.compile(r"`|\$\(|[<>]\(")
# Tools that carry text, stored, searched or handed to someone: naming the address there reaches nothing.
NOT_REACHING = {"memory", "todo", "todo_list", "web_search", "x_search", "skill_manage", "session_search",
                "delegate_task", "clarify", "cronjob", "cronjob_manage", "send_message", "yb_send_dm", "discord"}


def _git_subcommand(words):
    """The subcommand of a git command line, global options skipped (git -C dir fetch, git -c k=v clone)."""
    w = list(words[1:])
    while w and w[0].startswith("-"):
        opt = w.pop(0)
        if opt in GIT_GLOBAL_VALUE and w:
            w.pop(0)
    return w[0] if w else ""


def _only_names(text):
    """True when every program of a command line only reads, prints or files text, so the metadata address it
    names reaches nothing: no substitution, no program outside METADATA_SAFE_VERBS anywhere in the line, git limited
    to local subcommands."""
    if SUBSTITUTION.search(text) or METADATA_UNSAFE.search(text):
        return False
    for view in dict.fromkeys([text] + shell.command_views(text)):
        for seg in shell.segments(view):
            w, raw = shell.command_words(seg), shell.words(seg)
            if w is None or raw is None:
                return False
            if not w:
                continue
            name = os.path.basename(w[0])
            if name not in METADATA_SAFE_VERBS or (name == "git" and (_git_subcommand(w) not in GIT_SAFE or
                                                                      "-c" in w or "--config-env" in w)):
                return False
            if re.match(r"^\w+=", (shell.tokens(seg) or [""])[0]):     # VAR=... before a program can change it
                return False
    return True


def _inet_aton(host):
    """An IPv4 address in the forms the C resolver accepts (2852039166, 0xa9fea9fe, 0251.0376.0251.0376, 169.16689662),
    without the socket module: a guard that reads text has no network import."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or not all(re.fullmatch(r"0x[0-9a-f]+|0[0-7]*|[1-9][0-9]*", p) for p in parts):
        return None
    nums = [int(p, 16) if p.startswith("0x") else int(p, 8) if len(p) > 1 and p.startswith("0") else int(p)
            for p in parts]
    *head, last = nums
    if any(n > 255 for n in head) or last >= 256 ** (4 - len(head)):
        return None
    value = last
    for i, n in enumerate(head):
        value += n << (8 * (3 - i))
    return ipaddress.ip_address(value)


def _metadata_address(token):
    host = token.strip("[]").lower().rstrip(".")
    if host in METADATA_DOTTED:
        return True
    try:
        ip = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        ip = _inet_aton(host)
    if ip is not None and getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    return ip in METADATA_IPS


def _braces(text, limit=20):
    """Texts with the shell's brace lists expanded (169.254.169.25{4,5}), a few at most."""
    out, todo = [], [text]
    while todo and len(out) < limit:
        t = todo.pop()
        m = re.search(r"\{([^{}\s]*,[^{}\s]*)\}", t)
        if not m:
            out.append(t)
            continue
        todo += [t[:m.start()] + part + t[m.end():] for part in m.group(1).split(",")][:limit]
    return out


def names_metadata(text):
    """True when a text names a metadata service: an address in any form a parser accepts, a dotted host, or a short
    name (metadata, instance-data) as the host of a URL. The bare word "metadata" is not an address."""
    for w in _braces(text) if "{" in text else [text]:
        if METADATA_TEXT.search(w):
            return True
        if any(h.strip("[]").lower().rstrip(".") in METADATA_SHORT or _metadata_address(h)
               for h in URL_ANY_HOST.findall(w)):
            return True
        for token in re.split(r"[\s\"'`<>()\[\]{},;|&=@/\\]+", w):
            host, _, port = token.rpartition(":")
            if _metadata_address(token) or (port.isdigit() and host and _metadata_address(host)):
                return True
    return False


def metadata_target(tool, args, texts):
    """True when the call can reach a cloud metadata service: a command that names it with a program that could reach
    the network, code that names it, or another tool whose URL host or address is the service. Writing a file that
    names it reaches nothing (running that file later is another call)."""
    if tool in NOT_REACHING or tool in FILE_WRITE_TOOLS:
        return False
    if tool in COMMAND_TOOLS or tool == "process_manage":
        text = command_text(tool, args)
        views = list(dict.fromkeys(guards.views([text]) + shell.command_views(text)))
        if not any(names_metadata(v) or METADATA_VARS.search(v) for v in views):
            return False
        return tool == "execute_code" or not _only_names(text)
    return any(names_metadata(v) for v in guards.views(texts))


# --- Walls ------------------------------------------------------------------------------------------------------

def walls(pol, tool, args, ctx):
    """Decision(block) if the call hits a wall, else None. Walls ignore taint and categories."""
    dump = "\n".join(_texts(args))
    for t in shell.variants(dump):
        for rx in pol.words:
            if rx.search(t):
                return Decision("block", "wall", f"forbidden word ({rx.pattern})", "walls.words", True)
    # A message, a note or a file may mention the address; a command, code, a page or a third-party tool that names
    # it may not run.
    if pol.cloud_metadata and tool not in FILE_READ_TOOLS and metadata_target(tool, args, list(_texts(args))):
        return Decision("block", "wall", "reaches the cloud metadata service, which hands out this server's "
                                         "credentials", "walls.cloud_metadata", True)
    cwd = ctx.cwd
    if tool in FILE_READ_TOOLS or tool in FILE_WRITE_TOOLS:
        paths = [args.get("path"), args.get("file_path"), args.get("dir"), args.get("directory")]
        if tool == "patch":
            paths += PATCH_FILES.findall(str(args.get("patch") or ""))
        for p in paths:
            if not p:
                continue
            n = shell.normalize(p, cwd)
            r = write_wall(n, pol, ctx) if tool in FILE_WRITE_TOOLS else opened_wall(n, pol, ctx)
            if r:
                return Decision("block", "wall", r, "walls.paths", True)
        if tool in FILE_WRITE_TOOLS:
            content = str(args.get("content") or args.get("patch") or args.get("new_string") or "")
            written = str(args.get("path") or args.get("file_path") or "")
            if content and not shell.as_named(written).lower().endswith((".md", ".txt", ".rst")):
                d = command_walls(pol, content, ctx, cwd, code=True, content=True)
                if d:
                    d.reason += " (in a file being written)"
                    return d
        return None
    if tool in COMMAND_TOOLS or tool == "process_manage":
        text = command_text(tool, args)
        if not text:
            return None
        if args.get("workdir"):
            cwd = shell.normalize(args["workdir"], cwd)
        return command_walls(pol, text, ctx, leading_cd(text, cwd), code=tool == "execute_code")
    if tool in ATTACHING_TOOLS:
        for p in attached(args, ctx)[0]:
            r = opened_wall(p, pol, ctx)
            if r:
                return Decision("block", "wall", f"attaches a file the agent may not read: {r}", "walls.paths", True)
        return None
    if tool.startswith("browser_"):
        for t in _texts(args):
            for u in re.findall(r"file:[^\s\"'`<>)\]]+", t, re.I):
                try:
                    r = opened_wall(shell.normalize(shell.file_url_path(u)), pol, ctx)
                except ValueError:
                    r = None
                if r:
                    return Decision("block", "wall", r, "walls.paths", True)
    return None


# Programs that run a file given after a subcommand (uv run x.py), after -f (awk -f x.awk), or as their first
# argument (tsx x.ts); interpreters (sh, python3, node...) are read by shell.is_interpreter.
SUBCOMMAND_RUNNERS = {"uv", "poetry", "pipenv", "bun", "deno", "go", "npm", "pnpm", "yarn", "hatch", "pdm"}
FILE_OPTION_RUNNERS = {"awk", "gawk", "mawk", "nawk", "make", "gmake", "sed"}
FILE_RUNNERS = {"tsx", "ts-node", "npx", "bunx", "uvx", "pipx", "busybox"}


def _ran_files(words):
    """The files a simple command runs: the program itself, the script an interpreter or a runner is given (sh x.sh,
    python3 x.py, uv run x.py, awk -f x.awk, tsx x.ts), not the arguments of other programs (git add x runs
    nothing)."""
    if not words:
        return []
    name, rest = os.path.basename(words[0]), list(words[1:])
    out = [words[0]]
    if name in FILE_OPTION_RUNNERS:
        out += [rest[i + 1] for i, a in enumerate(rest[:-1]) if a == "-f"]
        out += [a[2:] for a in rest if a.startswith("-f") and len(a) > 2]
        return out
    if name in SUBCOMMAND_RUNNERS and rest[:1] in (["run"], ["exec"], ["x"]):
        rest = rest[1:]
    elif not (shell.is_interpreter(name) or name in FILE_RUNNERS):
        return out
    args = [a for a in rest if not a.startswith("-")]
    if name == "busybox" and args:
        return out + _ran_files(args)
    return out + args[:1]


GIT_READ_ONLY = {"--get", "--get-all", "--get-regexp", "--unset", "--unset-all", "--list", "-l", "--remove-section",
                 "--show-origin", "--name-only"}
SHELL_REDIRECTION = re.compile(r"(?:\d+|&)?(?<![<>])>>?\|?[ \t]*([^\s;&|<>()`]+)")


def git_alias(text):
    """Why a command line defines or runs a git alias (a command run later, or now, under another name), or None:
    git config alias.x ... (not a read or an unset), git -c alias.x=... <subcommand>."""
    for seg in shell.segments(text):
        w = shell.command_words(seg) or []
        if not w or os.path.basename(w[0]) != "git":
            continue
        if any(a == "-c" and b.lower().startswith("alias.") for a, b in zip(w, w[1:])):
            return "runs a git alias defined on the command line"
        sub_args = w[w.index("config") + 1:] if "config" in w else []
        if _git_subcommand(w) == "config" and any(a.lower().startswith("alias.") for a in w) and \
                not any(a in GIT_READ_ONLY for a in w) and sub_args[:1] not in (["get"], ["list"]):
            return "defines a git alias, a command that runs later under another name"
    return None


def _downloads(words):
    """Files a curl or wget command line saves."""
    name, w = os.path.basename(words[0]), list(words[1:])
    remote = [os.path.basename(urlparse(u).path.rstrip("/")) or "index.html"
              for u in w if re.match(r"(?i)^(https?|ftp)://", u)]
    out, folder, named = [], "", False
    for i, a in enumerate(w):
        nxt = w[i + 1] if i + 1 < len(w) else ""
        if name == "curl":
            if a in ("-o", "--output") or re.fullmatch(r"-[a-zA-Z]*o", a):
                out.append(nxt)
            elif a.startswith("--output="):
                out.append(a.split("=", 1)[1])
            elif re.fullmatch(r"-o.+", a):
                out.append(a[2:])
            elif a in ("-O", "--remote-name", "--remote-name-all") or re.fullmatch(r"-[a-zA-Z]*O[a-zA-Z]*", a):
                named = True
            elif a == "--output-dir":
                folder = nxt
            elif a.startswith("--output-dir="):
                folder = a.split("=", 1)[1]
        else:
            if a in ("-O", "--output-document"):
                out.append(nxt)
            elif a.startswith("--output-document="):
                out.append(a.split("=", 1)[1])
            elif re.fullmatch(r"-O.+", a):
                out.append(a[2:])
            elif a in ("-P", "--directory-prefix"):
                folder = nxt
            elif a.startswith("--directory-prefix="):
                folder = a.split("=", 1)[1]
    if name == "wget" and out:
        folder = ""                                   # wget ignores -P when -O names the file
    if name == "wget" and not out:
        named = True
    if named:
        out += remote
    return [os.path.join(folder, f) if folder else f for f in out if f and f != "-"]


def _word_at(text, start):
    """The shell word that starts at `start`, quotes removed (> "run.sh" writes run.sh)."""
    out, quote = [], None
    for c in text[start:]:
        if quote:
            if c == quote:
                quote = None
            else:
                out.append(c)
        elif c in "'\"":
            quote = c
        elif c.isspace() or c in ";&|<>()`":
            break
        else:
            out.append(c)
    return "".join(out)


def shell_written(text, cwd, depth=0):
    """Files a command line writes through the shell, so that running one later counts as running a file this
    conversation wrote: redirections (> f, >> f, 1> f, &> f), tee, a download's output (curl -o f, curl -O,
    wget), and the same inside substitutions, sh -c strings, eval and heredocs read by a shell."""
    if depth > 3 or not text:
        return []
    p, out = shell.parse(text), []
    for seg in p.segments:
        targets = [_word_at(seg, m.start(1)) for m in SHELL_REDIRECTION.finditer(shell.unquoted(seg))]
        w = shell.command_words(seg) or []
        name = os.path.basename(w[0]) if w else ""
        if name == "tee":
            targets += [a for a in w[1:] if not a.startswith("-")]
        if name in ("curl", "wget"):
            targets += _downloads(w)
        if name == "eval":
            out += shell_written(" ".join(w[1:]), cwd, depth + 1)
        elif name in shell.REEVALUATING_SHELLS:
            for j, a in enumerate(w[1:-1], 1):
                if re.fullmatch(r"-[a-zA-Z]*c[a-zA-Z]*", a):
                    out += shell_written(w[j + 1], cwd, depth + 1)
                    break
        out += [shell.normalize(f, cwd) for f in targets if f and not f.startswith(("/dev/", "&"))]
    for body in shell.substitution_bodies(text):
        out += shell_written(body, cwd, depth + 1)
    for k, quoted, body in p.heredocs:
        if k < len(p.segments) and shell.verb(p.segments[k]) in shell.REEVALUATING_SHELLS:
            out += shell_written(body, cwd, depth + 1)
    return list(dict.fromkeys(out))


def command_text(tool, args):
    if tool in COMMAND_TOOLS:
        return str(args.get(COMMAND_TOOLS[tool]) or "")
    if tool == "process_manage" and str(args.get("action") or "") in ("write", "submit", "send", "stdin"):
        return str(args.get("data") or "")
    return ""


def command_walls(pol, text, ctx, cwd, code=False, content=False):
    for t in shell.variants(text):
        for cid, rx, reason in pol.commands:
            if rx.search(t):
                return Decision("block", "wall", reason, f"walls.commands.{cid}", True)
        for rx in pol.destructive:
            if rx.search(t):
                return Decision("block", "wall", "destructive deletion (home, root, repository or Hermes data)",
                                "walls.destructive", True)
    r = shell.find_cited_path(text, cwd, lambda p: access_wall(p, pol, ctx, remote=not content))
    if not r:
        for word in (shell.code_strings(text) if code else []) + shell.bare_words(text):
            paths = [shell.normalize(word, cwd)]
            pattern = shell.joined(cwd, word)
            if shell.GLOB_CHARS.search(word) and not shell.unc(pattern):
                paths += [shell.real(p) for p in itertools.islice(glob.iglob(pattern), 200)]
            r = next((x for x in (access_wall(p, pol, ctx, remote=not content) for p in paths) if x), None)
            if r:
                break
    if r:
        return Decision("block", "wall", r, "walls.paths", True)
    protected = _protected_matcher(pol, ctx, cwd)
    if shell.writes_protected(text, protected):
        return Decision("block", "wall", "writes a guard, configuration, startup or protected file "
                                         "(read is fine, writing is the owner's job)", "walls.write", True)
    return None


# --- Outbound actions -------------------------------------------------------------------------------------------

def _is_read_action(pol, tool, args):
    reads = pol.read_actions.get(tool)
    if not reads:
        return False
    acts = [args.get("action")] if args.get("action") else []
    for op in args.get("operations") or []:
        if isinstance(op, dict):
            acts.append(op.get("action") or op.get("op"))
    return bool(acts) and all(str(a) in reads for a in acts)


NOT_OUTBOUND_MESSAGE_ACTIONS = {"list", "react", "unreact"}


def _message_to_owner(args, ctx):
    """True when a send_message call leaves nothing with anyone but the owner (listing, reacting, or the owner's
    own channels). Any other action (send, forward, reply, edit...) to another chat is outbound."""
    if str(args.get("action") or "send").strip().lower() in NOT_OUTBOUND_MESSAGE_ACTIONS:
        return True
    target = str(args.get("target") or "").strip()
    if not target or ":" not in target:
        return True                       # a bare platform name is the profile's home channel
    chat = target.split(":")[1]
    return chat in ctx.owners or target in ctx.owners


def categories(pol, tool, args, ctx):
    """[(category, reason, rule)] of the outbound actions in a tool call."""
    found = []
    cat = pol.tool_categories.get(tool)
    if cat and not _is_read_action(pol, tool, args):
        if not (tool == "send_message" and _message_to_owner(args, ctx)):
            found.append((cat, f"{TOOL_REASONS.get(cat, cat.replace('_', ' '))}", f"tool_categories.{tool}"))
    if tool == "browser_console" and args.get("expression"):
        found.append(("browser_input", "browser_console runs code in the page", "tool.browser_console"))
    if tool == "discord" and not _is_read_action(pol, tool, args):
        found.append(("message", f"discord {args.get('action') or ''}".strip(), "tool.discord"))
    text = command_text(tool, args)
    views = []
    if tool == "execute_code":
        views = [text] + shell.argv_literals(text)
    elif text:
        views = shell.command_views(text)
    elif tool == "browser_exec":
        views = [str(args.get("code") or "")]
    if views:
        joined = "\n".join(views)
        raw = [text or str(args.get("code") or "")]
        for rid, cat, rx, on in pol.egress:
            for t in dict.fromkeys(raw + [shell.unmask(raw[0])] if on == "raw" else
                                   [joined] + [shell.unmask(v) for v in views]):
                if rx.search(t):
                    found.append((cat, _describe(rid, rx, t, cat), f"egress.{rid}"))
                    break
    if pol.persistence_paths:
        hit = None
        if tool in FILE_WRITE_TOOLS:
            for p in [args.get("path"), args.get("file_path")] + PATCH_FILES.findall(str(args.get("patch") or "")):
                n = shell.normalize(p, ctx.cwd) if p else ""
                if n and (any(under(n, r) for r in pol.persistence_paths) or GIT_HOOKS.search(n)):
                    hit = pretty(n, ctx)
        elif text:
            roots = pol.persistence_paths
            cwd = leading_cd(text, ctx.cwd)

            def persistent(raw):
                cands = [m.group(0) for m in shell.cited_paths().finditer(shell.fold(raw or ""))]
                cands += [t for t in re.split(r"[\s\"'=;&|<>(),]+", raw or "") if t] + shell.quoted_words(raw) + \
                    [(raw or "").strip()]
                return any(any(under(n, r) for r in roots) or bool(GIT_HOOKS.search(n))
                           for c in cands for n in shell.twins(shell.normalize(c, cwd), cwd))
            if shell.writes_protected(text, persistent):
                hit = "the agent's memory, skills or scheduled jobs"
        if hit:
            found.append(("persistence", f"writes {hit} directly", "persistence_paths"))
    if tool in FILE_WRITE_TOOLS and ctx.tainted:
        content = str(args.get("content") or args.get("patch") or args.get("new_string") or "")
        path = str(args.get("path") or args.get("file_path") or "")
        if content and SCRIPT_EXT.search(shell.as_named(path)):
            for rid, cat, rx, _ in pol.egress:
                if rx.search(content) or rx.search(shell.unmask(content)):
                    found.append((cat, f"a script that {_describe(rid, rx, content, cat)}", f"egress.{rid}"))
                    break
    if text and ctx.tainted and tool != "execute_code":
        cwd = leading_cd(text, shell.normalize(args["workdir"], ctx.cwd) if args.get("workdir") else ctx.cwd)
        written = ctx.written | set(shell_written(text, cwd))     # written earlier, or earlier in this same line
        ran = [a for seg in shell.segments(text) for a in _ran_files(shell.command_words(seg) or [])]
        hit = next((a for a in ran if shell.normalize(a, cwd) in written), None) if written else None
        if hit:
            found.append(("written_script", f"runs {hit}, a file written in this session after reading untrusted "
                                            "content", "written_then_run"))
    alias = git_alias(text) if text else None
    if alias:
        found.append(("persistence", alias, "git_alias"))
    for u in tool_urls(tool, args):
        if exfil_url(u, pol):
            found.append(("exfil_url", f"URL that could carry data out ({u[:60]})", "exfil_url"))
            break
    if ctx.tainted and (text or tool == "browser_exec"):
        code_text = text or str(args.get("code") or "")
        code_views = code_text if tool == "execute_code" else "\n".join(shell.command_views(code_text))
        # Every line that reaches the network must name a local or trusted address in clear: a loopback URL on one
        # line does not vouch for an address built at run time on another ('https://' + host, os.environ['X']).
        net_lines = [ln for ln in (code_views + "\n" + code_text).splitlines()
                     if CODE_NETWORK.search(ln) or SHELL_NETWORK_RAW.search(ln)]
        local_only = bool(net_lines) and all(
            URL.findall(ln) and all(_loopback(u) or _domain_trusted(u, pol) for u in URL.findall(ln))
            and "://" not in URL.sub("", ln) for ln in net_lines)
        if net_lines and not local_only \
                and not any(f[0] == "exfil_url" for f in found):
            found.append(("exfil_url", "code that reaches the network after untrusted content (its address, body or "
                                       "timing can carry data)", "code_network_tainted"))
    if text and tool != "execute_code":
        views = "\n".join(shell.command_views(text))
        if NET_COMMAND.search(views) and re.search(r"\$\(|`", text) and URL_OR_HOST_SUBST.search(text):
            found.append(("network_write", "a network call whose address or data is computed by the shell",
                          "computed_request"))
        if ctx.tainted:
            hosts = [h for h in NET_HOSTS.findall(views)] + URL.findall(text)
            untrusted = [h for h in hosts if not _domain_trusted(h if "://" in h else "https://" + h, pol)
                         and not _loopback(h)]
            if NET_COMMAND.search(views) and untrusted and not any(f[0] == "exfil_url" for f in found):
                host = guards.hostname(untrusted[0]) or untrusted[0]
                found.append(("exfil_url", f"network call to {host} after untrusted content (the address can carry "
                                           "data)",
                              "shell_network_tainted"))
    if text and ctx.tainted and ctx.written:
        builders = [v for v in (shell.verb(s) for s in shell.segments(text)) if v in BUILD_TOOLS]
        configs = [p for p in ctx.written if os.path.basename(p) in BUILD_FILES]
        if builders and configs:
            found.append(("written_script", f"{builders[0]} reads {pretty(configs[0], ctx)}, written in this "
                                            "session after reading untrusted content", "written_build_file"))
    if ctx.origin and ctx.origin != "core" and not admitted(pol, tool, ctx.origin):
        found.append(("unadmitted_tool", f"{tool} comes from {ctx.origin.replace(':', ' ')}, which airlock cannot "
                                         "read and nobody admitted", "tools.unadmitted"))
    return found


CATEGORY_PHRASES = {
    "publish": "publishes outside this machine",
    "network_write": "sends data over the network",
    "remote": "acts on another machine",
    "message": "sends a message",
    "persistence": "sets something to run or be remembered later",
    "delegation": "hands work to another agent",
    "detach": "starts a process that outlives the conversation",
}


def _describe(rid, rx, text, cat=""):
    m = rx.search(text)
    snippet = re.sub(r"\s+", " ", m.group(0)).strip()[:60] if m else rid
    return f"{CATEGORY_PHRASES[cat]} ({snippet})" if cat in CATEGORY_PHRASES else snippet


def admitted(pol, tool, origin):
    if tool in pol.admitted_tools:
        return True
    kind, _, name = (origin or "").partition(":")
    if kind == "plugin":
        return name.replace("_", "-") in pol.admitted_plugins
    if kind == "mcp":
        return name in pol.admitted_mcp
    return kind == "core"


# --- Taint sources ----------------------------------------------------------------------------------------------

def taint_source(pol, tool, args, ctx):
    """Short description of the untrusted content this call brings into the session, or None."""
    if not pol.taint_enabled:
        return None
    args = args if isinstance(args, dict) else {}
    if ctx.origin and ctx.origin != "core":
        kind, _, name = ctx.origin.partition(":")
        if tool not in pol.trusted_output and name.replace("_", "-") not in pol.trusted_output:
            return f"{tool} ({ctx.origin})"
    urls = tool_urls(tool, args)
    if tool in pol.source_tools:
        if urls and all(_domain_trusted(u, pol) for u in urls):
            return None
        target = urls[0] if urls else str(args.get("query") or args.get("action") or "")
        return f"{tool} {target}".strip()[:120]
    if tool == "vision_analyze" and urls:
        return f"vision_analyze {urls[0]}"[:120]
    if tool in FILE_READ_TOOLS:
        p = shell.normalize(args.get("path") or args.get("file_path") or "", ctx.cwd)
        if any(under(p, r) for r in pol.untrusted_paths):
            return f"{tool} {p}"[:120]
        return None
    text = command_text(tool, args) or (str(args.get("code") or "") if tool == "browser_exec" else "")
    if text and pol.untrusted_paths:
        hit = shell.find_cited_path(text, ctx.cwd, lambda p: p if any(under(p, r) for r in pol.untrusted_paths)
                                    else None)
        if hit:
            return f"{tool} {hit}"[:120]
    if text:
        views = "\n".join(shell.command_views(text)) if tool != "execute_code" else text
        if any(rx.search(views) for rx in pol.source_patterns):
            cmd_urls = URL.findall(text)
            if cmd_urls and all(_domain_trusted(u, pol) for u in cmd_urls):
                return None
            return (cmd_urls[0] if cmd_urls else "network read by a command")[:120]
    return None


# --- Decision ---------------------------------------------------------------------------------------------------

MAX_CHECKED = 200_000   # characters: beyond this, a call is not read in full (a decision must stay fast)
CONTENT_KEYS = ("content", "patch", "new_string", "old_string")


def _oversized(pol, tool, args, ctx, size):
    """A call too long to read in full. Padding must never turn a wall into a mere approval: a command or code that
    long is refused, and a file tool still gets its path walls and the start of its content checked; only the
    content past the limit goes unread (padding it after a protected-path command no longer lowers the wall)."""
    if tool in FILE_READ_TOOLS or tool in FILE_WRITE_TOOLS:
        scan = {k: (v[:MAX_CHECKED] if k in CONTENT_KEYS and isinstance(v, str) else v) for k, v in args.items()}
        d = walls(pol, tool, scan, ctx)
        if d:
            return d
        if tool in FILE_WRITE_TOOLS and (ctx.tainted or ctx.stopped):
            level = "block" if ctx.stopped else "approve"
            return Decision(level, "bypass", f"file content too long to check ({size} characters), written after "
                                             "reading untrusted content", "size")
        return None
    return Decision("block", "bypass", f"arguments too long to check ({size} characters): split the work into "
                                       "smaller steps", "size")




OUTBOUND = {"message", "network_write", "publish", "remote", "exfil_url", "install", "delegation"}
SEARCH_TOOLS = {"web_search", "x_search", "web_extract", "browser_navigate", "vision_analyze", "video_analyze"}
# Tools whose arguments go to an outside service whatever they name (a search engine, a model, a voice).
PROVIDER_TOOLS = SEARCH_TOOLS - {"browser_navigate"} | {"image_generate", "text_to_speech"}
# Programs that only read or print what they are given: an address in their arguments is text, not a destination.
LOCAL_PROGRAMS = shell.PURE_READERS - {"awk", "gawk", "mawk", "nawk"}           # gawk opens /inet/tcp sockets


def decide(pol, tool, args, ctx):
    """The worst Decision for a tool call, or None when nothing applies. Commands are judged as the shell reads them
    (raw text); secrets, the canary and destinations are looked for in every form the values take."""
    tool = str(tool or "")
    args = args if isinstance(args, dict) else {}
    shell.new_decision()
    guards.new_decision()
    _attached_cache.clear()
    texts = list(_texts(args))
    size = sum(len(t) for t in texts)
    if size > MAX_CHECKED and tool not in FILE_READ_TOOLS and tool not in FILE_WRITE_TOOLS:
        return _oversized(pol, tool, args, ctx, size)            # refused unread, and fast: no scan of megabytes
    # The context marker leaving in a tool call means the agent is copying out its own instructions or history.
    if ctx.canary and guards.carries_canary(texts, ctx.canary):
        return Decision("block", "canary", "this call carries airlock's private session marker: the agent is copying "
                                           "its own context out, which only an injected instruction asks for",
                        "canary", True)
    attach = _attachments(pol, tool, args, ctx)
    if attach and attach.category == "canary":
        return attach
    d = _decide(pol, tool, args, ctx, texts)
    if attach and ctx.stopped:
        attach = Decision("block", attach.category, f"{attach.reason}; the airlock stop switch is on", attach.rule)
    if attach and (d is None or ORDER[attach.level] >= ORDER[d.level]):
        d = attach
    if ctx.locked and (d is None or d.level != "block"):
        reaches_out = d is not None or tool in SEARCH_TOOLS or tool in PROVIDER_TOOLS or _third_party(ctx) or any(
            not _loopback(u) and not _domain_trusted(u, pol) for u in tool_urls(tool, args))
        if reaches_out:
            return Decision("block", d.category if d else "locked", f"this conversation is locked ({ctx.locked}); "
                            "the owner must review it before anything leaves", "locked")
    return d


def secret_decision(hit, pol, where=""):
    """The decision for a recognized secret leaving: block for a strong format under secrets_out: block, else ask."""
    name, strong = hit
    level = "block" if strong and pol.secrets_out == "block" else "approve"
    article = "an" if name[0] in "AEIOUx" or name.startswith("npm") else "a"      # an AWS, an xAI, an npm
    return Decision(level, "secret", f"{where}{article} {name} would leave the machine in clear; secrets go through "
                                     "an environment variable or the tool's own login, never in a call",
                    "secret", level == "block")


def _attachments(pol, tool, args, ctx):
    """The context marker or a recognized secret inside an attached file, judged as if it were in the message. Each
    file is read on its own (a big first file does not hide the next one)."""
    texts = attachment_texts(pol, tool, args, ctx)
    if texts is None:
        return Decision("approve", "message", f"more than {ATTACHMENT_FILES} files attached: their content is not all "
                                              "checked for secrets", "attachments")
    if ctx.canary and texts and guards.carries_canary(texts, ctx.canary):
        return Decision("block", "canary", "an attached file carries airlock's private session marker: the agent "
                                           "is sending its own context out", "canary", True)
    hit = guards.find_secret(texts) if texts else None              # a strong format in any file before a weak one
    if hit:
        return secret_decision(hit, pol, "an attached file holds a secret: ")
    if attached(args, ctx)[1]:
        return Decision("approve", "message", "attachment paths too long or too many to check: put each MEDIA: path "
                                              "on its own line", "attachments")
    return None


def _third_party(ctx):
    """A plugin or MCP tool: airlock cannot see where it sends what it is given."""
    return bool(ctx.origin) and ctx.origin != "core"


def _local_only(tool, args, texts, found, pol):
    """True when the call can only reach this machine or trusted hosts: a command, code or a page load (other tools
    send their arguments to a service, whatever URL they name) that names at least one URL, every URL and every other
    address it names (mail recipient, ssh or scp host, network command's host) loopback or trusted, and no channel
    without a URL (a message, a remote shell, the page open in the browser, an agent)."""
    if tool not in COMMAND_TOOLS and tool not in ("process_manage", "browser_navigate"):
        return False
    if any(c in ("message", "remote", "browser_input", "delegation") for c, _, _ in found):
        return False
    urls = tool_urls(tool, args) + [u for t in texts for u in URL.findall(t)]
    if not urls or not all(_loopback(u) or _domain_trusted(u, pol) for u in urls):
        return False
    return all(_local_host(a, pol) for a in guards.call_addresses(texts))


def _program_words(text):
    """The program of every simple command (its name, not its directory), those run by sh -c, eval, find -exec and
    xargs included."""
    return [os.path.basename(line.split(" ", 1)[0]) for line in shell.command_views(text, code=False)]


def _address_texts(pol, tool, args, texts):
    """Where a call's addresses are looked for. A message goes to its target: a link in its text is not where it goes.
    A command is read as the shell runs it, its variables substituted: a quoted text with spaces (a commit message, an
    echo), a heredoc that no interpreter reads and the arguments of grep or echo are prose, not addresses. A task handed
    to another agent names no address: that agent inherits the conversation's addresses. Other arguments are read as
    is."""
    if tool == "send_message":
        return [str(args.get("target") or "")]
    if pol.tool_categories.get(tool) == "delegation":
        return []
    text = command_text(tool, args)
    if tool != "terminal" or not text:
        return texts
    p = shell.parse(text)
    prose = {b for k, _, b in p.heredocs if k < len(p.segments) and not shell.is_interpreter(shell.verb(p.segments[k]))}
    views = [v for v in dict.fromkeys(shell.command_views(text) + shell.command_views(shell.substitute_vars(text)))
             if v not in prose and os.path.basename(v.split(" ", 1)[0]) not in LOCAL_PROGRAMS]
    return [t for t in texts if t != text] + views          # cat <<EOF notes, grep and echo name, never reach


def _decide(pol, tool, args, ctx, texts):
    size = sum(len(t) for t in texts)
    if size > MAX_CHECKED:
        return _oversized(pol, tool, args, ctx, size)
    d = walls(pol, tool, args, ctx)
    if d:
        return d
    worst = None
    text = command_text(tool, args)
    if text:
        reason = (guards.disguised_command(text, _program_words(text)) if tool != "execute_code" else
                  ("characters that reorder or hide text in code" if guards.REORDERING.search(text) else None)) or \
            shell.bypass(text, code=tool == "execute_code")
        if reason:
            worst = Decision(pol.action("bypass", bool(ctx.tainted)), "bypass", reason, "bypass")
    if tool in FILE_WRITE_TOOLS and ctx.tainted:
        content = str(args.get("content") or "")
        path = str(args.get("path") or args.get("file_path") or "")
        if content and SCRIPT_EXT.search(shell.as_named(path)) and shell.bypass(content) and \
                not shell.as_named(path).lower().endswith(".py"):
            worst = Decision(pol.action("bypass", True), "bypass", "a script that computes or hides what it runs, "
                             "written after reading untrusted content", "bypass.written")
    found = categories(pol, tool, args, ctx)
    run = text or (str(args.get("code") or "") if tool == "browser_exec" else "")
    addresses = guards.call_addresses(_address_texts(pol, tool, args, [run])) if run else []
    if ctx.tainted and run and not any(c == "exfil_url" for c, _, _ in found):
        # Whatever the program (a renamed curl, pip install from a URL, git clone): after untrusted content, a command
        # that names a remote address can carry data out or bring code in.
        remote = [a for a in addresses if "@" not in a and not _local_host(a, pol)]
        if remote:
            found.append(("exfil_url", f"a command that reaches {remote[0]} after untrusted content", "remote_address"))
    # A secret leaving and an address named by the untrusted content are signals, not verdicts: they join the other
    # decisions (the worst wins, the stop switch still blocks); on a tie their reason is the more precise one.
    secret = destination = None
    outbound = any(c in OUTBOUND or c == "browser_input" for c, _, _ in found) or tool in SEARCH_TOOLS \
        or tool in PROVIDER_TOOLS or tool == "send_message" or _third_party(ctx) or bool(tool_urls(tool, args)) \
        or any(not _local_host(a, pol) for a in addresses)                  # dig <token>.host, nc host 4444
    if outbound and not _local_only(tool, args, texts, found, pol):
        hit = guards.find_secret(texts)
        if hit:
            secret = secret_decision(hit, pol)
    if ctx.tainted and ctx.destinations and pol.destinations != "off":
        named = guards.named_destination(_address_texts(pol, tool, args, texts), ctx.destinations,
                                         ignore=lambda h: _local_host(h, pol))
        if named:
            address, mail = named
            sends = any(c in OUTBOUND for c, _, _ in found)
            carries = sends or text or tool == "browser_exec" or any(
                "?" in u or ("#" in u and "=" in u.split("#", 1)[1]) for u in tool_urls(tool, args))
            follow = pol.destinations_follow == "approve" and bool(tool_urls(tool, args))
            if carries or follow:
                if carries:
                    level = "approve" if (mail or not sends or pol.destinations == "approve") else "block"
                else:
                    level = "approve"
                destination = Decision(level, "destination", f"reaches {address}, an address named by the untrusted "
                                                             f"content this conversation read: the signature of an "
                                                             f"injected instruction. If it is legitimate, the owner can "
                                                             f"trust the domain or clear the conversation",
                                       "destination", level == "block")
    for cat, reason, rule in found:
        level = pol.action(cat, bool(ctx.tainted))
        d = Decision(level, cat, reason, rule)
        worst = d if worst is None else worst.worse(d)
    for signal in (destination, secret):
        if signal and (worst is None or ORDER[signal.level] >= ORDER[worst.level]):
            worst = signal
    if ctx.stopped and (found or secret or destination):
        first = worst if worst and worst.level != "allow" else Decision("allow", found[0][0], found[0][1], found[0][2])
        worst = Decision("block", first.category, f"{first.reason}; the airlock stop switch is on", first.rule)
    if worst and worst.level == "allow":
        return None
    return worst


def message(decision, ctx, taint_source_text=None):
    """What the agent reads when a call is blocked or waits for approval."""
    if decision.wall:
        return (f"BLOCKED by airlock: {decision.reason}. This is a wall: do not retry or rephrase. "
                "If it is truly needed, tell the user what you need and why.")
    if decision.category == "bypass" and decision.level == "block":
        return (f"BLOCKED by airlock: {decision.reason}. airlock does not run what it cannot read. If this command is "
                "part of the user's task, write it plainly: it will be checked like any other.")
    why = f"this conversation read untrusted content ({taint_source_text}), which can hide instructions; " \
        if taint_source_text else ""
    if decision.level == "block":
        return (f"BLOCKED by airlock: {decision.reason}. {why.capitalize()}nothing of this kind leaves without the "
                "owner. Prepare it, and say in your answer what should be sent and where: the owner will do it.")
    return f"airlock: {decision.reason}. {why.capitalize()}the owner approves this action before it runs."
