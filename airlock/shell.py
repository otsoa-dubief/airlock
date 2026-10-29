# Copyright 2026 Otsoa Dubief
# SPDX-License-Identifier: Apache-2.0
"""Reading shell commands and inline code the way the shell would, and spotting the ways a command can hide what it
runs.

Every function here is pure: it reads text and returns a reason (str) or None. Nothing is executed. The parser is
deliberately conservative: when a command cannot be read with confidence, callers treat it as suspicious rather than
as safe.

Known limit, by design: a file that already exists on disk (written earlier by another route) and is then launched by
name (``python3 x.py``) is out of reach of a text-level guard. airlock closes the routes that *compute or hide* what
they execute inside the command itself, and the routes that write the guard's own files.
"""
from __future__ import annotations

import ast
import functools
import glob
import itertools
import os
import posixpath
import re
import shlex
import sys
from dataclasses import dataclass, field

# Credentials and guard paths are matched by prefix (rules.under) and by name (walls.secret_files). On a
# case-insensitive filesystem (macOS, Windows) ``cat ~/.SSH/ID_RSA`` reads ~/.ssh/id_rsa, so the match must
# fold case too, or every path wall is bypassed by changing the case of a letter.
CASE_INSENSITIVE_FS = sys.platform in ("darwin", "win32")

# On Windows every path is compared in one canonical form, with forward slashes (see real()). A test may set this
# flag on another system to exercise the Windows reading; it is read at call time.
WINDOWS = sys.platform == "win32"

# --- Parsing ----------------------------------------------------------------------------------------------------

HEREDOC_START = re.compile(r"<<(-?)\s*(?:'([^'\n]*)'|\"([^\"\n]*)\"|\\?([A-Za-z_]\w*))")


@dataclass
class Parsed:
    """A command line as the shell splits it.

    segments: simple commands, split outside quotes on ; & | ( ) and newlines (heredoc bodies and comments removed).
    heredocs: (segment index, quoted delimiter?, body).
    evaluated: a $ or ` the shell evaluates (outside single quotes and quoted heredocs).
    substitution: a $( or ` the shell evaluates (a computed command).
    ambiguous: $'...' quoting or a backslash outside quotes, or unbalanced quotes: our reading could differ from the
        shell's, so no exemption may rely on it.
    piped: for each segment, True if it reads the output of a | .
    """
    segments: list = field(default_factory=list)
    heredocs: list = field(default_factory=list)
    evaluated: bool = False
    substitution: bool = False
    ambiguous: bool = False
    piped: list = field(default_factory=list)


def parse(text: str) -> Parsed:
    """Cached: the same command is read by several rules. Callers must not modify the result."""
    return _parse(text or "")


@functools.lru_cache(maxsize=1024)
def _parse(text: str) -> Parsed:
    p = Parsed()
    cur, pending = [], []
    quote, i, n = None, 0, len(text)
    next_piped = [False]

    def cut(pipe=False):
        p.segments.append("".join(cur).strip())
        p.piped.append(next_piped[0])
        next_piped[0] = pipe
        cur.clear()

    while i < n:
        c = text[i]
        if quote == "$'":                          # ANSI-C quoting: \ escapes the next character, \' included
            if c == "\\" and i + 1 < n:
                cur.append(text[i:i + 2])
                i += 2
                continue
            quote = None if c == "'" else quote
            cur.append(c)
            i += 1
            continue
        if quote == "'":
            quote = None if c == "'" else quote
            cur.append(c)
            i += 1
            continue
        if quote == '"':
            if c == "\\" and i + 1 < n:
                cur.append(text[i:i + 2])
                i += 2
                continue
            if c == '"':
                quote = None
            elif c == "$":
                p.evaluated = True
                p.substitution = p.substitution or text[i + 1:i + 2] == "("
            elif c == "`":
                p.evaluated = p.substitution = True
            cur.append(c)
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            if text[i + 1] != "\n":
                p.ambiguous = True
                cur.append(text[i:i + 2])
            i += 2
            continue
        if c == "$" and text[i + 1:i + 2] == "'":
            p.ambiguous = p.evaluated = True
            quote = "$'"
            cur.append("$'")
            i += 2
            continue
        if c in "'\"":
            quote = c
        elif c == "$":
            p.evaluated = True
            p.substitution = p.substitution or text[i + 1:i + 2] == "("
        elif c == "`":
            p.evaluated = p.substitution = True
        elif c == "#" and (not cur or cur[-1] in " \t"):
            end = text.find("\n", i)
            i = n if end < 0 else end
            continue
        elif c == "<" and text.startswith("<<", i) and not text.startswith("<<<", i) and text[i - 1:i] != "<":
            m = HEREDOC_START.match(text, i)
            if m:
                quoted = m.group(2) is not None or m.group(3) is not None or text[m.start(4) - 1:m.start(4)] == "\\"
                pending.append((len(p.segments), quoted, m.group(2) or m.group(3) or m.group(4) or "", m.group(1) == "-"))
                cur.append(m.group(0))
                i = m.end()
                continue
        elif c == "\n":
            cut()
            i += 1
            for k, quoted, delim, tabs in pending:
                body = []
                while i < n:
                    j = text.find("\n", i)
                    j = n if j < 0 else j
                    line, i = text[i:j], j + 1
                    if (line.lstrip("\t") if tabs else line) == delim:
                        break
                    body.append(line)
                b = "\n".join(body)
                p.heredocs.append((k, quoted, b))
                if not quoted and re.search(r"[$`]", b):
                    p.evaluated = True
                    p.substitution = p.substitution or bool(re.search(r"\$\(|`", b))
            pending = []
            continue
        elif c in ";|()" or (c == "&" and not (cur and cur[-1] in "<>") and text[i + 1:i + 2] != ">"):
            if not (c == "|" and cur and cur[-1] == ">"):      # >| is a redirection, not a pipe
                cut(c == "|" and text[i + 1:i + 2] != "|" and text[i - 1:i] != "|")
                i += 1
                continue
        cur.append(c)
        i += 1
    cut()
    p.heredocs += [(k, quoted, "") for k, quoted, _, _ in pending]
    p.ambiguous = p.ambiguous or quote is not None
    return p


def segments(text: str) -> list:
    """Simple commands of a command line (quote-aware)."""
    return [s for s in parse(text).segments if s]


def words(segment: str):
    """Words of a simple command (shlex), with assignments and redirections removed; None if unreadable."""
    w = _words(segment)
    return None if w is None else list(w)


@functools.lru_cache(maxsize=4096)
def _words(segment: str):
    try:
        raw = shlex.split(segment)
    except ValueError:
        return None
    out, skip = [], False
    for a in raw:
        if skip:
            skip = False
        elif re.match(r"^\d*(<|>|>>|&>|<&|>&|<<|<<-|<<<)$", a):
            skip = True
        elif not re.match(r"^\d*[<>]", a):
            out.append(a)
    while out and re.match(r"^\w+=", out[0]):
        out = out[1:]
    return tuple(out)


def tokens(segment: str):
    try:
        return shlex.split(segment)
    except ValueError:
        return None


LAUNCH_PREFIXES = {"command", "exec", "nohup", "time", "env", "builtin", "nice", "caffeinate", "sudo", "doas",
                   "stdbuf", "timeout", "xargs", "unbuffer", "chronic", "ionice", "taskset"}
PREFIX_VALUE_OPTIONS = {"-u", "-C", "-n", "-P", "-S", "-g", "-i", "-o", "-e", "-k", "-s", "-L"}
SHELL_KEYWORDS = {"do", "then", "else", "elif", "if", "while", "until", "!", "{", "}", "done", "fi", "time"}


def command_words(segment: str):
    """Words of a simple command with shell keywords and launch prefixes (env, nohup, sudo, timeout...) removed, so
    that the first word is the program that actually runs. None if unreadable."""
    w = words(segment)
    if w is None:
        return None
    while w and w[0] in SHELL_KEYWORDS:
        w = w[1:]
    while w and os.path.basename(w[0]) in LAUNCH_PREFIXES:
        prefix = os.path.basename(w[0])
        w = w[1:]
        while w and (w[0].startswith("-") or re.match(r"^\w+=", w[0])):
            a = w.pop(0)
            if a in PREFIX_VALUE_OPTIONS and w:
                w.pop(0)
        if prefix == "timeout" and w and re.match(r"^\d+(\.\d+)?[smhd]?$", w[0]):
            w = w[1:]
    return w


def verb(segment: str) -> str:
    w = command_words(segment)
    return os.path.basename(w[0]) if w else ""


# --- Unmasking --------------------------------------------------------------------------------------------------

ANSI_C = re.compile(r"\$'((?:[^'\\]|\\.)*)'")
CONCAT = re.compile(r"[\"']\s*\+\s*[\"']")


def unmask(text: str) -> str:
    """The text without shell tricks: $'...' decoded, string concatenations joined, quotes and backslashes removed.
    A safety net for pattern matching, not a parser: ``g'i't p"u"sh`` becomes ``git push``."""
    def ansi(m):
        try:
            return m.group(1).encode("latin-1", "backslashreplace").decode("unicode_escape")
        except UnicodeDecodeError:
            return m.group(1)
    t = ANSI_C.sub(ansi, text or "")
    t = CONCAT.sub("", t)
    return re.sub(r"[\"'`\\\\]", "", t)


# Folders Windows names by a variable (Git Bash: $APPDATA; cmd: %APPDATA%; code: os.environ["APPDATA"]).
WIN_FOLDERS = re.compile(r"\$\{(APPDATA|LOCALAPPDATA)\}|\$(APPDATA|LOCALAPPDATA)(?!\w)|%(APPDATA|LOCALAPPDATA)%|"
                         r"(?P<code>os\.environ\[\s*[\"'](APPDATA|LOCALAPPDATA)[\"']\s*\]|"
                         r"(?:os\.environ\.get|(?:os\.)?getenv)\(\s*[\"'](APPDATA|LOCALAPPDATA)[\"']\s*\))", re.I)


def _win_folder(m):
    name = next(g for g in m.groups()[::-1] if g and g.upper() in ("APPDATA", "LOCALAPPDATA")).upper()
    value = os.environ.get(name)
    if not value:
        return m.group(0)
    value = value.replace("\\", "/")
    return f'"{value}"' if m.group("code") else value      # a quoted string in code, so 'x' + "/y" folds


def fold(text: str) -> str:
    """Path fragments joined back together: 'sec'+'rets', Path.home()/'.ssh', os.path.join('~', '.aws'), m[a]in,
    empty quotes. Used to find a protected path written in pieces."""
    t = text or ""
    t = re.sub(r"__import__\(\s*[\"']os[\"']\s*\)", "os", t)
    t = re.sub(r"Path\.home\(\)|(os\.)?path\.expanduser\(\s*[\"']~/?[\"']\s*\)|"
               r"os\.environ\[\s*[\"'](HOME|USERPROFILE)[\"']\s*\]|"
               r"os\.environ\.get\(\s*[\"'](HOME|USERPROFILE)[\"']\s*\)|"
               r"(os\.)?getenv\(\s*[\"'](HOME|USERPROFILE)[\"']\s*\)|\$\{(HOME|USERPROFILE)\}|"
               r"\$\{?HOMEDRIVE\}?\$\{?HOMEPATH\}?|%HOMEDRIVE%%HOMEPATH%|\$(HOME|USERPROFILE)(?!\w)|%USERPROFILE%",
               "~", t)
    if WINDOWS:
        t = WIN_FOLDERS.sub(_win_folder, t)
    t = re.sub(r"\.joinpath\(\s*[\"']", "/'", t)
    t = re.sub(r"(os\.)?path\.join\(([^()\n]*)\)",
               lambda m: re.sub(r"[\"']\s*,\s*[\"']", "/", re.sub(r"^\s*~\s*,\s*[\"']", "~/", m.group(2))), t)
    t = re.sub(r"[\"']\s*\+\s*[\"']", "", t)
    t = re.sub(r"(~|[\"'])\s*\)?\s*/\s*\(?\s*[\"']", lambda m: ("~" if m.group(1) == "~" else "") + "/", t)
    t = re.sub(r"/\s*\(?\s*[\"']", "/", t)
    t = re.sub(r"\"\"|''", "", t)
    return re.sub(r"\[([\w.-])\]", r"\1", t)


def substitute_vars(text: str) -> str:
    """The text where ``P=<value>`` later replaces $P and ${P} (``P=~/.ssh && cat $P/id_rsa``)."""
    values = dict(re.findall(r"(?:^|[\s;&|(])([A-Za-z_]\w*)=([^\s;&|()]+)", text or ""))
    if not values:
        return text
    return re.sub(r"\$\{?([A-Za-z_]\w*)\}?", lambda m: values.get(m.group(1), m.group(0)).strip("\"'"), text)


EMPTY_VAR = re.compile(r"\$\{?[A-Za-z_]\w*\}?")


def variants(text: str) -> list:
    """The text and its unmasked, folded and variable-substituted forms (deduplicated, original first).

    One form collapses every still-unresolved ``$VAR``/``${VAR}`` to nothing: an unset variable expands to the
    empty string in the shell, so ``cat ~/.a${X}ws/credentials`` reads ~/.aws/credentials and must hit the wall."""
    subv = substitute_vars(text)
    blanked = EMPTY_VAR.sub("", subv)
    out = []
    for t in (text, unmask(text), fold(text), subv, fold(subv), blanked, fold(blanked)):
        if t and t not in out:
            out.append(t)
    return out


# --- Paths cited in a command -----------------------------------------------------------------------------------

CITED_PATH = re.compile(r"(?<![\w:/.~-])(~|\.{1,2}/|/)[^\s\"'`;&|<>(),]*")
# On Windows a path also starts with a drive (C:/, C:\) or a share (\\host); Git Bash's /c/... is already a "/".
CITED_PATH_WIN = re.compile(r"(?<![\w:/.~\\-])(~|\.{1,2}/|/|[A-Za-z]:[\\/]|\\\\|\\(?=\w))[^\s\"'`;&|<>(),]*")


def cited_paths():
    """The pattern of a path cited in a command, for the system airlock runs on."""
    return CITED_PATH_WIN if WINDOWS else CITED_PATH


GLOB_CHARS = re.compile(r"[*?\[]")


_normalized = {}


def new_decision():
    """Forget resolved paths: symlinks and the environment can change between two tool calls, not within one."""
    _normalized.clear()


_MISSING = object()


def normalize(path, cwd=None) -> str:
    """Cached for the current decision only (see new_decision). The resolved value is returned from a local,
    never re-read from the dict: another thread's new_decision() can clear the cache between the store and the
    read (the cache is process-global), and a KeyError there would be swallowed by post_tool_call and drop a taint."""
    key = (str(path) if path else "", cwd or "", WINDOWS)
    val = _normalized.get(key, _MISSING)
    if val is _MISSING:
        if len(_normalized) > 20000:
            _normalized.clear()
        val = _normalize(key[0], key[1])
        _normalized[key] = val
    return val


def _normalize(path, cwd) -> str:
    if not path:
        return ""
    path = os.path.expanduser(os.path.expandvars(str(path).strip()))
    if WINDOWS:
        path = win_canon(path)
    if not os.path.isabs(path) and cwd:
        path = os.path.join(cwd, path)
    return real(path)


# --- Windows paths ----------------------------------------------------------------------------------------------
# Windows names one file in many ways that a prefix test on "/" never sees (GHSA-w8j8-5ph5-rrff): backslashes,
# Git Bash's /c/... (Hermes's terminal is Git Bash, and its file tools translate /c/, /cygdrive/c/ and /mnt/c/),
# the \\?\ and \\.\ device prefixes, the local administrative share \\localhost\C$\, NTFS streams
# (file::$DATA, dir::$INDEX_ALLOCATION) and trailing dots or spaces, which Win32 drops (".env." opens .env).
# win_canon() folds them into one form, C:/Users/x/..., before and after the link resolution of real().

MSYS_DRIVE = re.compile(r"^/(?:(?:(?:proc/)?cygdrive|mnt)/)?([a-zA-Z])(?=/|$)")
# Git Bash mounts its /tmp on the user's temp folder (fstab "usertemp"): a junction made there leads anywhere.
MSYS_TMP = re.compile(r"^/tmp(?=/|$)", re.I)


@functools.lru_cache(maxsize=32)
def _drive_exists(letter: str) -> bool:
    """On Windows, whether a drive exists (Git Bash reads /x as the drive X: only then, else as a folder of its own
    root). Elsewhere, as when a test reads Windows paths on another system, every letter is a drive."""
    if os.name != "nt":
        return True
    return os.path.exists(letter.upper() + ":\\")


@functools.lru_cache(maxsize=1)
def _git_root() -> str:
    """The folder Git Bash calls /, from the bash Hermes runs (empty when unknown or outside Windows)."""
    if os.name != "nt":
        return ""
    try:
        from tools.environments.local import _find_bash
        bash = _find_bash()
    except Exception:
        import shutil
        bash = shutil.which("bash") or ""
    parts = os.path.realpath(bash).replace("\\", "/").split("/") if bash else []
    for k in range(len(parts) - 1, 0, -1):
        if parts[k].lower() == "bin":
            root = "/".join(parts[:k - 1] if k >= 2 and parts[k - 1].lower() == "usr" else parts[:k])
            return root if re.match(r"[A-Za-z]:/", root) else ""
    return ""
WIN_DEVICE = re.compile(r"^(?://[?.]/|/\?\?/)(?:(UNC)/|([a-zA-Z]:))", re.I)   # \\?\, \\.\ and NT's \??\
WIN_SHARE = re.compile(r"^//([^/]+)/([a-zA-Z])\$(?=/|$)")
# //host/share/... (a bare //word is how Git Bash passes a /switch to cmd or schtasks, not a share).
WIN_REMOTE = re.compile(r"//[^/]+/[^/]")
LOCAL_HOSTS = {"localhost", ".", "::1", "[::1]", "0:0:0:0:0:0:0:1"}


def _local_host(name: str) -> bool:
    n = name.lower().rstrip(".")
    return n in LOCAL_HOSTS or bool(re.fullmatch(r"127(\.\d{1,3}){3}", n)) or n in _machine_names()


@functools.lru_cache(maxsize=1)
def _machine_names():
    """This machine's own names, read once and without any DNS query (a lookup per path would let a message slow
    every decision down)."""
    names = set()
    try:
        import socket
        names.add(socket.gethostname().lower())
    except Exception:
        pass
    for var in ("COMPUTERNAME", "HOSTNAME"):
        if os.environ.get(var):
            names.add(os.environ[var].lower())
    return names


def win_canon(path: str) -> str:
    """A Windows path in airlock's canonical form, by text only (nothing is opened): forward slashes, Git Bash
    drives and device prefixes translated, a local administrative share turned back into its drive, NTFS streams
    and trailing dots or spaces removed from every component. A remote share stays //host/share/...."""
    p = re.sub(r"^/{2,}", "//", str(path).replace("\\", "/"))   # \\\\host is \\host to Windows
    m = WIN_DEVICE.match(p)
    if m:
        p = "/" + p[m.end() - 1:] if m.group(1) else p[m.start(2):]
    elif p.startswith("/??/"):
        p = "//?/" + p[4:]                                      # \??\GLOBALROOT...: a device path, refused
    if p.startswith("/") and not p.startswith("//"):
        p = posixpath.normpath(p)                               # Git Bash reads /c/../c/x as /c/x before its mounts
    m = MSYS_TMP.match(p)
    if m and os.environ.get("TEMP"):
        p = os.environ["TEMP"].replace("\\", "/") + p[m.end():]
    m = MSYS_DRIVE.match(p)
    if m and (m.group(0) != "/" + m.group(1) or _drive_exists(m.group(1))):
        p = m.group(1).upper() + ":" + (p[m.end():] or "/")      # /c is the root of C:, not C:'s cwd
    elif p.startswith("/") and not p.startswith("//") and _git_root():
        p = _git_root() + p                                     # Git Bash's / is Git's own folder
    m = WIN_SHARE.match(p)
    if m and _local_host(m.group(1)):
        p = m.group(2).upper() + ":" + p[m.end():]
    if p.startswith("//"):
        root, rest = "//", p[2:]
    elif re.match(r"[a-zA-Z]:", p):
        root, rest = p[:2].upper(), p[2:]
    else:
        root, rest = "", p
    lead = "/" if rest.startswith("/") and root != "//" else ""
    parts = []
    for part in rest.split("/"):
        if part not in ("", ".", ".."):
            part = part.split(":", 1)[0].rstrip(". ") or "."
        if part:                                                 # a//b is a/b
            parts.append(part)
    return root + lead + "/".join(parts) + ("/" if rest.endswith("/") and parts else "")


def remote_path(path) -> bool:
    """True on Windows for a path that names another machine (\\\\host\\share, or a device namespace left over):
    resolving it, listing it or testing that it exists would already open a network connection (SMB or WebDAV),
    and with it send the user's NTLM credentials, before anyone approved anything."""
    return WINDOWS and bool(WIN_REMOTE.match(win_canon(str(path or ""))))


def as_named(path) -> str:
    """A path as Windows reads its name, for tests on the name (extension, folder): canonical and lower case, so
    run.PS1, run.sh. and run.sh::$DATA are the scripts they are. Unchanged elsewhere."""
    return win_canon(str(path or "")).lower() if WINDOWS else str(path or "")


def file_url_path(url) -> str:
    """The local path a file: URL opens. On Windows: file:///C:/x and file://localhost/C|/x are C:/x,
    file://localhost/C$/x is C:/x too (the local administrative share), and file://host/... or file:////host/...
    name another machine (//host/...)."""
    from urllib.parse import unquote, urlparse
    u = urlparse(url)
    path = unquote(u.path)
    if not WINDOWS:
        return path
    m = re.match(r"/*([a-zA-Z])[:|](.*)", path, re.S)
    if m and (not u.netloc or _local_host(u.netloc)):
        return m.group(1) + ":" + m.group(2)
    return win_canon("//" + u.netloc + path) if u.netloc else path


def joined(cwd, path) -> str:
    """path, ~ expanded (never variables), read from cwd when relative, in the canonical form on Windows; links are
    not resolved (see real())."""
    path = os.path.expanduser(str(path).strip())
    if WINDOWS:
        path = win_canon(path)
    if cwd:
        return os.path.join(cwd, path)
    return path if WINDOWS else os.path.join("/", path)


def twins(path, cwd=None) -> list:
    """The path, and on Windows the other file a path with no drive can name. Git Bash (Hermes's terminal, and its
    file tools on Windows) reads /x/y in Git's own folder; Python and Windows read it on the current drive. A wall
    must hold for both."""
    out = [path]
    root = _git_root() if WINDOWS and path else ""
    if root and (path == root or path.startswith(root + "/")):
        for where in (cwd, os.getcwd()):                        # the task's drive, and the process's
            drive = os.path.splitdrive(str(where or ""))[0].replace("\\", "/").upper()
            twin = (drive or root[:2]) + (path[len(root):] or "/")
            if twin not in out:
                out.append(twin)
    return out


def unc(path) -> bool:
    """True on Windows for any path that starts with \\\\ once read: such a path is never opened, listed or
    resolved to decide (a server name alone already makes Windows look for the machine)."""
    return WINDOWS and win_canon(str(path or "")).startswith("//")


def real(path) -> str:
    """os.path.realpath, in the canonical form on Windows. Never touches the disk for a remote path."""
    if not WINDOWS:
        return os.path.realpath(path)
    p = win_canon(str(path))
    if p.startswith("//"):
        return p
    return win_canon(os.path.realpath(p))


def bare_words(text: str) -> list:
    """Words of every simple command that could name a file relative to the working directory (``cat .env``,
    ``--file=config/credentials.json``), including commands inside $(...), sh -c and find -exec."""
    out = {}
    for t in variants(text or ""):
        for line in dict.fromkeys(list(parse(t).segments) + command_views(t)):
            w = words(line) if line else None
            for a in (w if w is not None else line.split()):
                a = a.split("=", 1)[1] if a.startswith("-") and "=" in a else a
                if a and a not in out and not a.startswith("-") and not re.search(r"[$`{}]", a):
                    out[a] = True
    return list(out)


def code_strings(code: str) -> list:
    """String literals of code that could be a path (no spaces)."""
    return [m.group(2) for m in re.finditer(r"([\"'])([^\"'\s\n]{1,300})\1", code or "")]


def find_cited_path(text: str, cwd, check):
    """First reason returned by ``check(normalized_path)`` for a path cited in the text, in clear, folded, behind a
    variable or through wildcards (each wildcard prefix is expanded: ``~/.ss*/id_*`` finds ~/.ssh). None otherwise."""
    seen = set()
    for t in variants(text or ""):
        for m in cited_paths().finditer(t):
            c = m.group(0).rstrip(".")
            if not c or c in seen or c in ("/", "~", "./", "../"):
                continue
            seen.add(c)
            reason = check(normalize(c, cwd))
            if reason:
                return reason
            if GLOB_CHARS.search(c):
                parts = normalize(c, cwd).split("/")
                for k in range(1, len(parts) + 1):
                    if not GLOB_CHARS.search(parts[k - 1]):
                        continue
                    if unc("/".join(parts[:k])):
                        break
                    for found in itertools.islice(glob.iglob("/".join(parts[:k])), 200):
                        reason = check(real(found))
                        if reason:
                            return f"{reason} (matched through wildcards)"
    return None


# --- Writes -----------------------------------------------------------------------------------------------------

REDIRECTION = re.compile(r"(?<![<>&\d])>>?\|?\s*[\"']?([^\s;&|<>\"']+)")
WRITE_VERBS = {"mv", "rm", "unlink", "truncate", "chmod", "chown", "chflags", "touch", "shred", "tee", "patch",
               "xattr", "setfacl", "mkdir", "rmdir", "ln"}
COPY_VERBS = {"cp", "install", "rsync", "ditto", "scp"}
GIT_WRITE = re.compile(r"\bgit\b[^\n;&|]*\b(checkout|restore|apply|am|mv|rm|stash|revert|cherry-pick|reset|"
                       r"update-index|read-tree|update-ref|clean)\b")
IN_PLACE = re.compile(r"\b(sed|gsed|perl|ruby)\b[^\n;&|]*\s-[a-zA-Z]*i|\bfind\b[^\n;&|]*\s-(delete|exec|execdir|ok)\b")
CODE_WRITE_CALL = re.compile(r"(\bopen|\bPath|\bos\.(?:remove|unlink|rename|replace|symlink|link|chmod|truncate|rmdir|"
                             r"removedirs|makedirs|mkdir)|\bshutil\.\w+|\bfs\.\w+)\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)"
                             r"\s*(\.\s*\w+)?")
WRITE_MODE = re.compile(r"[\"'][rwabt+]*[wax][rwabt+]*[\"']")
PATH_WRITE_METHODS = {"write_text", "write_bytes", "unlink", "rename", "replace", "symlink_to", "hardlink_to", "touch",
                      "chmod", "rmdir", "mkdir", "open"}
PATH_WRITE_METHOD = re.compile(r"\.\s*(write_text|write_bytes|unlink|touch|rename|replace|chmod|symlink_to|"
                               r"hardlink_to|rmdir|mkdir)\s*\(")
TEMP_TARGET = re.compile(r"^[\"']?(/tmp/|/private/tmp/|/var/folders/|\$TMPDIR)")


def writes_protected(text: str, protected) -> bool:
    """True if a command writes, moves or deletes a target for which ``protected(raw_target_text)`` is true.
    ``protected`` receives raw text (a word, a code argument list), and must decide by matching it. Reading,
    searching, running or copying a protected file elsewhere stays allowed."""
    if not text:
        return False
    for t in variants(text):
        if _writes_shell(t, protected) or writes_protected_code(t, protected):
            return True
    return False


def _holds_protected(directory, protected):
    """True if a directory contains a protected path (extracting an archive into ~ can drop a ~/.zshrc)."""
    roots = getattr(protected, "roots", None)
    if not roots or TEMP_TARGET.match(directory or ""):
        return False
    for d in twins(normalize(directory, getattr(protected, "cwd", None)), getattr(protected, "cwd", None)):
        if any(r == d or r.startswith(d.rstrip("/") + "/") for r in roots):
            return True
        if CASE_INSENSITIVE_FS:
            dl = d.lower()
            if any(r.lower() == dl or r.lower().startswith(dl.rstrip("/") + "/") for r in roots):
                return True
    return False


def quoted_words(text: str) -> list:
    """Every shlex word of a text, redirection signs removed (> 'a b/c' gives a b/c): a path with a space stays
    whole. Empty when the text cannot be split."""
    try:
        return [w.lstrip("0123456789&<>|") for w in shlex.split(text or "")]
    except ValueError:
        return []


def redirect_targets(segment: str) -> list:
    """The files a command line redirects its output to, read as the shell does (quotes keep spaces)."""
    out = REDIRECTION.findall(segment)
    try:
        raw = shlex.split(segment, posix=True)
    except ValueError:
        return out
    for i, w in enumerate(raw):
        m = re.fullmatch(r"[\d&]?>>?\|?(.*)", w, re.S)
        if m:
            target = m.group(1) or (raw[i + 1] if i + 1 < len(raw) else "")
            if target:
                out.append(target)
    return out


WIN_SHELLS = {"cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"}
WIN_DELETE_VERBS = {"rd", "rmdir", "del", "erase", "remove-item", "ri", "rm"}


WIN_CD_VERBS = {"cd", "chdir", "set-location", "sl", "pushd"}


def _windows_shell_deletes(w, protected) -> bool:
    """True if cmd or PowerShell is told to delete a protected path, or (recursively) a folder that holds one:
    cmd //c 'rd /s /q C:\\Users\\me', powershell -c 'Remove-Item -Recurse $env:USERPROFILE', a -Path: argument, a
    folder piped in (Get-ChildItem X | Remove-Item -Recurse) or reached by a cd before. airlock does not parse these
    shells; their deletion words are read in the text they are given."""
    if not w or os.path.basename(w[0].replace("\\", "/")).lower() not in WIN_SHELLS:
        return False
    text = re.sub(r"\$env:(\w+)", r"%\1%", " ".join(w[1:]), flags=re.I)
    text = re.sub(r"(?i)(^|\s)-(literal)?path:", r"\1", text)          # -Path:C:\x is the target C:\x
    toks = [t.strip("\"'") for t in re.findall(r'"[^"]*"|\'[^\']*\'|[^\s;&|]+', text)]

    def is_flag(a):                                             # -Recurse, -fo; cmd's /s, //q, /a:h
        return bool(re.fullmatch(r"-\w[\w-]*|//?[a-z?](:\S*)?", a, re.I))

    def expand(a):
        a = re.sub(r"%(\w+)%", lambda m: os.environ.get(m.group(1), m.group(0)), a)
        return os.path.expanduser(os.path.expandvars(a))

    base, seen = None, []
    for k, t in enumerate(toks):
        low = t.lower()
        if low in WIN_CD_VERBS:
            nxt = [a for a in toks[k + 1:k + 3] if not is_flag(a)]
            if nxt:
                base = expand(nxt[0])
            continue
        if low not in WIN_DELETE_VERBS:
            seen.append(t)
            continue
        args = []
        for a in toks[k + 1:]:
            if a.lower() in WIN_DELETE_VERBS or a.lower() in WIN_CD_VERBS:
                break
            args.append(a)
        flags = [a.lower() for a in args if is_flag(a)]
        recursive = any(re.fullmatch(r"//?s|-r\w*", f) for f in flags)
        targets = [a for a in args if not is_flag(a)] or [a for a in seen if not is_flag(a)]   # piped in
        for a in targets:
            target = re.sub(r"[\\/]+\*?$", "", re.sub(r"[\\/]?\*$", "", expand(a))) or (base or a)
            if base and not re.match(r"[A-Za-z]:|[\\/~]", target):
                target = os.path.join(base, target)
            if _guarded(target, protected) or (recursive and _holds_protected(target, protected)):
                return True
        seen = []
    return False


def _guarded(target, protected):
    return bool(target) and not TEMP_TARGET.match(target) and protected(target)


def _writes_shell(text, protected):
    for seg in segments(text):
        dest = extraction_target(seg)
        if dest is not None and (_guarded(dest, protected) or _holds_protected(dest, protected)):
            return True
        w = command_words(seg) or []
        if w and os.path.basename(w[0]) in ("rm", "rmdir") and \
                any(re.fullmatch(r"-[a-zA-Z]*[rR][a-zA-Z]*|--recursive", a) for a in w[1:]) and \
                any(_holds_protected(a, protected) for a in w[1:] if not a.startswith("-")):
            return True                                          # rm -r of a folder that holds a protected path
        if _windows_shell_deletes(w, protected):
            return True
        if not protected(seg):
            continue
        if any(_guarded(t, protected) for t in redirect_targets(seg)):
            return True
        if IN_PLACE.search(seg) or GIT_WRITE.search(seg):
            return True
        w = command_words(seg) or []
        v = os.path.basename(w[0]) if w else ""
        if v in WRITE_VERBS:
            return True
        if v == "dd" and any(a.startswith("of=") and protected(a) for a in w):
            return True
        if v in COPY_VERBS:
            args = [a for a in w[1:] if not a.startswith("-")]
            dest = next((w[i + 1] for i, a in enumerate(w[:-1]) if a in ("-t", "--target-directory")), None)
            if _guarded(dest or (args[-1] if args else ""), protected):
                return True
    return False


ARCHIVERS = {"tar", "gtar", "bsdtar", "unzip", "7z", "7za", "7zr", "cpio", "pax", "ar", "unrar", "gunzip", "bunzip2",
             "unxz", "ditto"}


def extraction_target(seg: str):
    """The directory an archive is extracted into (raw text, "." for the working directory), or None if the command
    does not extract an archive."""
    w = command_words(seg) or []
    if w and os.path.basename(w[0]) == "busybox":
        w = w[1:]
    if not w:
        return None
    v, args = os.path.basename(w[0]), w[1:]
    if v not in ARCHIVERS:
        return None
    if v in ("tar", "gtar", "bsdtar"):
        first = args[0] if args else ""
        if not ("--extract" in args or "--get" in args or re.fullmatch(r"-?[a-zA-Z]*x[a-zA-Z]*", first)
                or any(re.fullmatch(r"-[a-zA-Z]*x[a-zA-Z]*", a) for a in args)):
            return None
        for i, a in enumerate(args):
            if a in ("-C", "--directory") and i + 1 < len(args):
                return args[i + 1]
            if a.startswith("--directory="):
                return a.split("=", 1)[1]
        return "."
    if v == "unzip":
        return args[args.index("-d") + 1] if "-d" in args[:-1] else "."
    if v in ("7z", "7za", "7zr"):
        if not args or args[0] not in ("x", "e"):
            return None
        return next((a[2:] for a in args if a.startswith("-o")), ".")
    if v == "cpio":
        if not any(re.fullmatch(r"-[a-zA-Z]*i[a-zA-Z]*", a) or a == "--extract" for a in args):
            return None
        return args[args.index("-D") + 1] if "-D" in args[:-1] else "."
    if v == "pax":
        return "." if any(re.fullmatch(r"-[a-zA-Z]*r[a-zA-Z]*", a) for a in args) else None
    if v == "ar":
        return "." if args and "x" in args[0] else None
    if v == "ditto":
        return None                                       # handled as a copy verb
    return "."


EXTRACT_CALL = re.compile(r"\.(extractall|extract|unpack_archive)\s*\(|shutil\.unpack_archive\s*\(")


def writes_protected_code(code: str, protected) -> bool:
    """Same check for code (python -c, execute_code, a script being written): a call that writes, moves or deletes a
    protected path cited in its own arguments, directly or through a ``p = Path(...)`` variable."""
    if not code or not protected(code):
        return False
    for m in re.finditer(r"\b(\w+)\s*=\s*(?:\w+\.)*Path\s*\(([^)\n]*)\)", code):
        v = re.escape(m.group(1))
        if protected(m.group(2)) and re.search(
                rf"\b{v}\s*\.\s*(write_text|write_bytes|unlink|touch|rename|replace|chmod|symlink_to|hardlink_to|"
                rf"rmdir|mkdir)\s*\(|\b{v}\s*\.\s*open\s*\(\s*[\"'][wax+]|\bopen\s*\(\s*{v}\s*,\s*[\"'][^\"']*[wax+]|"
                rf"\b(shutil\.\w+|os\.(remove|unlink|rename|replace))\s*\([^)\n]*\b{v}\b", code):
            return True
    for stmt in re.split(r"[;\n]", code):
        if EXTRACT_CALL.search(stmt) and (protected(stmt) or protected(fold(stmt))):
            return True
        for m in PATH_WRITE_METHOD.finditer(stmt):
            if protected(stmt[:m.start()]) or protected(fold(stmt[:m.start()])):
                return True
    for m in CODE_WRITE_CALL.finditer(code):
        fn, args, then = m.group(1), m.group(2), (m.group(3) or "").lstrip(". ")
        if not protected(args):
            continue
        if fn == "open" and not WRITE_MODE.search(args):
            continue
        if fn == "Path" and then not in PATH_WRITE_METHODS:
            continue
        if fn == "Path" and then == "open" and not WRITE_MODE.search(code[m.end():m.end() + 40]):
            continue
        if re.match(r"shutil\.(copy\w*)$", fn) and not protected(args.split(",")[-1]):
            continue                                    # copying a protected file elsewhere is a read
        return True
    return False


# --- Code that hides what it runs -------------------------------------------------------------------------------

INTERPRETERS = re.compile(r"^(sh|bash|zsh|dash|ksh|fish|busybox|python[\d.]*|pypy[\d.]*|perl|ruby|node|nodejs|deno|"
                          r"bun|php|lua|tclsh|osascript|pwsh|powershell|swift|Rscript|source|eval|\.)$")
REEVALUATING_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "busybox", "eval", "source", "."}
PURE_READERS = {"grep", "egrep", "fgrep", "rg", "head", "tail", "wc", "cut", "sort", "uniq", "tr", "cat", "column",
                "nl", "jq", "yq", "ls", "echo", "printf", "diff", "tee", "base64", "stat", "file", "date", "less",
                "more", "fold", "fmt", "paste", "rev", "tac", "md5", "md5sum", "shasum", "sha256sum", "xxd", "od",
                "hexdump", "strings", "iconv", "expand", "unexpand", "comm", "join", "sed", "awk", "gawk", "mawk",
                "nawk", "true", "false", "test", "["}
STDIN = re.compile(r"^(-|-s|/dev/stdin|/dev/fd/\d+|/proc/self/fd/\d+)$")
CODE_OPTIONS = re.compile(r"^-(c|e|E|m|-eval|-command)$")
INLINE_CODE_OPTIONS = {"-e", "-c", "-E", "--eval", "--command", "eval"}
DECODE = re.compile(r"\bb(ase)?64\b|b64decode|decode_base64|Base64|Buffer\.from|unhexlify|fromhex|codecs\.decode|"
                    r"\bpack\b|base64\.b?decode|atob\s*\(", re.I)
SYSTEM_CALL = re.compile(r"\b(system|popen|exec\w*|spawn\w*|child_process|qx|popen\d?)\b")
GIT_C_EXEC = re.compile(r"\b(core\.pager|core\.sshCommand|core\.editor|sequence\.editor|core\.fsmonitor|diff\.external|"
                        r"core\.hooksPath|credential\.helper|filter\.\w+\.(clean|smudge|process))\b")
FILTER_OPTIONS = {"perl": "nplae", "ruby": "nplae", "node": "pe"}
FILTER_FORBIDDEN = re.compile(
    r"\b(eval|do|require|import|use|open|sysopen|qx|qw|syscall|fork|send|public_send|instance_eval|class_eval|"
    r"module_eval|binding|Function|vm|process|Kernel|IO|File|Dir|Open3|ObjectSpace|global|globalThis|constructor|"
    r"system|exec|kill|unlink|rmdir|rename|chmod|chown|link|symlink|glob|BEGIN|END|ioctl|spawn|socket|exit|truncate|"
    r"mkdir|utime)\b|%x|"
    r"\bs\s*(?P<dl>[^\w\s{(\[<])(?:\\.|(?!(?P=dl)).)*(?P=dl)(?:\\.|(?!(?P=dl)).)*(?P=dl)[a-z]*e|"
    r"\bs\s*[{(\[<].*[})\]>][a-z]*e")

READ_ONLY_MODULES = {"json", "glob", "os", "re", "sys", "pathlib", "datetime", "collections", "itertools", "math",
                     "time", "textwrap", "pprint", "statistics", "csv", "string", "operator", "functools", "html",
                     "unicodedata", "decimal", "fractions"}
OS_READ = {"path", "environ", "getcwd", "listdir", "scandir", "stat", "walk", "sep", "getenv", "linesep"}
FORBIDDEN_CALLS = {"exec", "eval", "compile", "getattr", "setattr", "delattr", "globals", "locals", "vars",
                   "__import__", "breakpoint"}
WRITE_METHODS = {"write", "writelines", "write_text", "write_bytes", "rename", "replace", "unlink", "rmdir", "mkdir",
                 "makedirs", "touch", "symlink_to", "hardlink_to", "link_to", "chmod", "chown", "truncate", "dump",
                 "remove", "removedirs", "system", "popen", "kill", "link", "symlink", "utime", "rmtree", "copy",
                 "copyfile", "copy2", "copytree", "move", "putenv", "unsetenv"}


def is_interpreter(word: str) -> bool:
    return bool(INTERPRETERS.match(os.path.basename(word or "")))


def python_reads_only(code: str) -> bool:
    """True if Python code only reads: known modules and names, no call that writes, moves, runs or builds code,
    open() only in read mode. Unreadable code: False. Lets ``... | python3 -c 'import json,sys; ...'`` through."""
    try:
        tree = ast.parse(code or "")
    except (SyntaxError, ValueError):
        return False
    called = {id(nd.func) for nd in ast.walk(tree) if isinstance(nd, ast.Call)}
    for nd in ast.walk(tree):
        if isinstance(nd, (ast.Name, ast.Attribute)) and getattr(nd, "id", getattr(nd, "attr", "")) == "open" and \
                id(nd) not in called:
            return False                              # open handed around (o = open; o(p, "w")): unreadable
        if isinstance(nd, ast.Import):
            if any(a.name.split(".")[0] not in READ_ONLY_MODULES for a in nd.names):
                return False
        elif isinstance(nd, ast.ImportFrom):
            root = (nd.module or "").split(".")[0]
            if root not in READ_ONLY_MODULES or any(
                    a.name == "*" or a.name in WRITE_METHODS or a.name in FORBIDDEN_CALLS or
                    (root == "os" and a.name not in OS_READ) for a in nd.names):
                return False
        elif isinstance(nd, ast.Name) and (nd.id in FORBIDDEN_CALLS or nd.id.startswith("__")):
            return False
        elif isinstance(nd, ast.Attribute):
            if nd.attr.startswith("__") or nd.attr in WRITE_METHODS or nd.attr == "modules" or \
                    re.match(r"^(exec|spawn|fork|posix_spawn)", nd.attr):
                return False
            if isinstance(nd.value, ast.Name) and nd.value.id == "os" and nd.attr not in OS_READ:
                return False
        elif isinstance(nd, ast.Call):
            f = nd.func
            name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""

            def read_mode(v):
                return isinstance(v, ast.Constant) and bool(re.fullmatch(r"[rbt]+", str(v.value)))
            if name == "open":
                modes = nd.args[1:] if isinstance(f, ast.Name) else nd.args
                modes += [k.value for k in nd.keywords if k.arg == "mode"]
                if len(modes) > 1 or not all(read_mode(m) for m in modes):
                    return False
            elif any(k.arg in ("file", "mode") for k in nd.keywords):
                return False
    return True


def python_hides_execution(code: str, decoding: bool = True) -> bool:
    """True if inline Python runs a non-literal command, or (decoding=True) decodes something (ast). Decoding alone is
    not counted for execute_code, where processing base64 data is ordinary work."""
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return False
    run = {"system", "popen", "run", "call", "Popen", "check_output", "check_call", "getoutput", "getstatusoutput",
           "spawn", "spawnl", "spawnv", "spawnlp", "spawnvp", "execv", "execve", "execvp", "execlp", "execl",
           "create_subprocess_shell", "create_subprocess_exec"}
    decoders = {"b64decode", "standard_b64decode", "urlsafe_b64decode", "b32decode", "b16decode", "a85decode",
                "b85decode", "unhexlify", "fromhex", "a2b_base64", "decompress"}

    def literal(nd):
        if isinstance(nd, ast.Constant):
            return True
        if isinstance(nd, ast.BinOp) and isinstance(nd.op, ast.Add):
            return literal(nd.left) and literal(nd.right)
        if isinstance(nd, (ast.List, ast.Tuple)):
            return all(literal(e) for e in nd.elts)
        if isinstance(nd, ast.JoinedStr):
            return all(isinstance(v, ast.Constant) for v in nd.values)
        return False
    for nd in ast.walk(tree):
        if isinstance(nd, ast.Call):
            f = nd.func
            name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""
            if decoding and name in decoders or decoding and (name == "decode" and any(
                    isinstance(a, ast.Constant) and str(a.value).lower() in ("base64", "hex", "rot13", "rot_13")
                    for a in nd.args)):
                return True
            if name in ("exec", "eval", "compile") and nd.args and not literal(nd.args[0]):
                return True
            if name in run:
                if any(k.arg == "shell" and getattr(k.value, "value", False) is True for k in nd.keywords):
                    return True
                if nd.args and not literal(nd.args[0]):
                    return True
    return False


def other_code_hides_execution(code: str) -> bool:
    """Cautious heuristic for perl, ruby, node, awk: a system call whose argument is not a literal string, or a
    decoding step. When in doubt, True."""
    if DECODE.search(code):
        return True
    for m in SYSTEM_CALL.finditer(code):
        rest = code[m.end():].lstrip()
        if rest.startswith("("):
            arg = rest[1:].lstrip()
            if not (arg.startswith(('"', "'")) and not re.search(
                    r"[$`]", arg[:arg.find(arg[0], 1) + 1] if arg[0] in "\"'" else arg)):
                return True
        elif rest[:1] in ("$", "`", "@", "%") or re.match(r"\w", rest[:1] or " "):
            return True
    return bool(re.search(r"`[^`]*\$|`[^`]*`", code))


def _inline_filter(v, args, seg):
    """True if perl/ruby/node reading a pipe is only a filter with literal, harmless code (``| perl -pe 's/a/b/'``)."""
    letters = FILTER_OPTIONS.get(v)
    if not letters or len(args) != 2 or not re.fullmatch(f"-[{letters}]*e", args[0]):
        return False
    code = args[1]
    if "'" in code or re.search(r"\$\(|`", code) or f"'{code}'" not in seg:
        return False
    if v in ("perl", "ruby") and "\\" in code:
        return False
    if v == "node" and code.strip() == "process.stdin.pipe(process.stdout)":
        return True
    return not (other_code_hides_execution(code) or FILTER_FORBIDDEN.search(code))


def hidden_interpreter(text: str):
    """Reason if an interpreter reads its code from somewhere other than the command itself (a pipe, process
    substitution, a file redirected to stdin, xargs, a computed -c), else None."""
    p = parse(text)
    if p.ambiguous and re.search(r"\|\s*(\S*/)?(\S+\s+)*?(sh|bash|zsh|dash|ksh|fish|busybox|python[\d.]*|perl|ruby|"
                                 r"node|php|swift|Rscript|source|\.)(\s|$)", text):
        return "an interpreter reads its code from a pipe"
    for k, seg in enumerate(p.segments):
        if not seg:
            continue
        w = command_words(seg)
        strong = p.piped[k] or seg.rstrip().endswith("<")        # pipe, or process substitution <(...)
        if w is None:
            if strong and re.search(r"(^|[\s/])(sh|bash|zsh|dash|ksh|busybox|python[\d.]*|perl|ruby|node|swift|"
                                    r"Rscript|source|\.)(\s|$)", seg):
                return "an interpreter reads its code from a pipe"
            continue
        if not w:
            continue
        names = [os.path.basename(a) for a in w]
        for j, a in enumerate(w[:-1]):
            if a == "-c" and any(nm in REEVALUATING_SHELLS or is_interpreter(nm) for nm in names[:j]):
                arg = w[j + 1]
                if re.search(r"[$`]", arg) or (arg.split() and is_interpreter(arg.split()[0])):
                    return "an interpreter runs a computed text, or another interpreter"
        if any(nm in REEVALUATING_SHELLS for nm in names) and any(re.search(r"\$\(|`|^\$$", a) for a in w):
            return "a shell runs a computed command ($(...) or `...`)"
        v, args = names[0], w[1:]
        raw = words(seg) or []
        if raw and os.path.basename(raw[0]) == "xargs" and any(is_interpreter(nm) for nm in names):
            return "xargs builds a command that an interpreter runs"
        if strong:
            if v in PURE_READERS:
                if v in ("awk", "gawk", "mawk", "nawk"):
                    prog = " ".join(a for a in args if not a.startswith("-"))
                    if re.search(r"\bsystem\b|\||getline", prog):
                        return "awk runs commands read from a pipe (system, |)"
                if v in ("sed", "gsed"):
                    prog = " ".join(a for a in args if not a.startswith("-"))
                    if re.search(r"(^|[;\s}{])e($|[\s;}])|^s(?P<d>.).*(?P=d).*(?P=d)[gpiImM0-9]*e", prog):
                        return "sed runs commands read from a pipe (e command)"
                continue
            if re.match(r"^python[\d.]*$", v) and (
                    (len(args) == 2 and args[0] == "-c" and python_reads_only(args[1])) or args == ["-m", "json.tool"]):
                continue
            if _inline_filter(v, args, seg):
                continue
            if any(is_interpreter(nm) for nm in names):
                return "an interpreter reads its code from a pipe"
            continue
        if is_interpreter(v) and re.search(r"(^|[^<])<($|[^<])", seg):
            named = any(CODE_OPTIONS.match(a) for a in args) or \
                any(not a.startswith("-") and not STDIN.match(a) for a in args)
            if not named or any(STDIN.match(a) for a in args):
                return "an interpreter reads its code from a redirected file"
    return None


def _inline_code(v, args):
    """(language, code) of an interpreter's inline code, or (None, None). awk: the program is the first non-option."""
    base = os.path.basename(v)
    if re.fullmatch(r"python[\d.]*|pypy[\d.]*|perl|ruby|node|nodejs|deno|bun|php|lua|tclsh|pwsh|powershell|"
                    r"osascript|Rscript|swift", base):
        for i, a in enumerate(args[:-1]):
            if a in INLINE_CODE_OPTIONS:
                return base, args[i + 1]
        return base, None
    if base in ("awk", "gawk", "mawk", "nawk"):
        return base, next((a for a in args if not a.startswith("-")), None)
    return None, None


def _indirect_launcher(v, args, toks, seg, piped=False):
    if v == "env" and any(a == "-S" or a.startswith("-S") for a in args):
        return "env -S runs a string as a command"
    if v == "git":
        for i, a in enumerate(args):
            if a == "-c" and i + 1 < len(args):
                key, _, val = args[i + 1].partition("=")
                if val.lstrip().startswith("!") or GIT_C_EXEC.search(key) or key.startswith("alias."):
                    return "git -c that runs a command (pager, sshCommand, editor, hooks, alias !)"
    if v == "expect":
        return "expect runs a script"
    if v == "crontab" and ("-" in args or "<<<" in toks or "|" in seg):
        return "crontab reads its input"
    if v in ("at", "batch") and (args or piped or "|" in seg):
        return "at/batch runs a deferred command"
    if v in ("vim", "vi", "nvim", "ex", "view"):
        for i, a in enumerate(args):
            rest = a[2:] if a.startswith("-c") and len(a) > 2 else (a[1:] if a.startswith("+") else (
                args[i + 1] if a == "-c" and i + 1 < len(args) else ""))
            if a.startswith(("-c", "+")) and "!" in (rest or "") + a:
                return "vim -c/+ that runs a shell command"
    if v in ("make", "gmake") and "-f" in args:
        i = args.index("-f")
        if i + 1 < len(args) and args[i + 1] == "-":
            return "make -f - reads its Makefile from stdin"
    if v in ("Rscript", "swift", "deno", "bun") and any(a in ("-e", "--eval", "eval") for a in args):
        return f"{v} runs a text"
    if v == "osascript" and "-l" in args:
        return "osascript -l runs another language"
    if v == "launchctl" and "submit" in args:
        return "launchctl submit runs a command"
    if v in ("find",) and any(a in ("-exec", "-execdir", "-ok", "-okdir") for a in args):
        i = next(i for i, a in enumerate(args) if a in ("-exec", "-execdir", "-ok", "-okdir"))
        if i + 1 < len(args) and is_interpreter(args[i + 1]) and \
                any(a in ("-c", "-e", "--eval") for a in args[i + 2:]):
            return "find -exec runs an interpreter on inline code"
    return None


def indirect_execution(text: str):
    """Reason if a command runs text it computes or hides: computed here-string, computed or decoding inline code,
    process substitution to an interpreter, indirect launcher, file written then executed in the same command."""
    p = parse(text or "")
    for inner in re.findall(r"[<>]\(\s*([^()]*)", text or ""):
        first = inner.split()[0] if inner.split() else ""
        if first and is_interpreter(first):
            return "process substitution into an interpreter"
    written, executed = set(), set()
    for k, seg in enumerate(p.segments):
        if not seg:
            continue
        w = command_words(seg)
        toks = tokens(seg) or []
        v = os.path.basename(w[0]) if w else ""
        args = w[1:] if w else []
        if "<<<" in toks and is_interpreter(v):
            hs = seg[seg.find("<<<") + 3:]
            if re.search(r"[$`]", hs):
                return "computed here-string read by an interpreter"
        lang, code = _inline_code(v, args)
        if code is not None:
            if re.search(r"\$\(|`", code):
                return "inline code computed by the shell"
            if re.match(r"^(python|pypy)[\d.]*$", lang or ""):
                if python_hides_execution(code):
                    return "inline Python that runs a non-literal command or decodes data"
            elif other_code_hides_execution(code):
                return "inline code that runs a non-literal command or decodes data"
        raw = words(seg) or []
        if raw and os.path.basename(raw[0]) == "env" and any(a == "-S" or a.startswith("-S") for a in raw[1:]):
            return "env -S runs a string as a command"
        reason = _indirect_launcher(v, args, toks, seg, p.piped[k])
        if reason:
            return reason
        for target in REDIRECTION.findall(seg):
            written.add(os.path.basename(target.strip("\"'")))
        if v == "tee":
            written.update(os.path.basename(a.strip("\"'")) for a in args if not a.startswith("-"))
        if is_interpreter(v):
            skip = False
            for a in args:
                if skip:
                    skip = False
                    continue
                if a in ("-c", "-e", "-m", "--eval", "--command"):
                    skip = True
                    continue
                if not a.startswith("-") and not STDIN.match(a):
                    executed.add(os.path.basename(a.strip("\"'")))
                    break
        if v == "chmod" and any("x" in a for a in args if a.startswith("+") or re.match(r"^[0-7]*[1357]", a)):
            executed.update(os.path.basename(a.strip("\"'")) for a in args
                            if not a.startswith(("+", "-")) and not re.match(r"^[0-7]+$", a))
        if w and re.match(r"^(\./|\.\./|/)", w[0]):
            executed.add(os.path.basename(w[0].strip("\"'")))
    for k, quoted, body in p.heredocs:
        seg = p.segments[k] if k < len(p.segments) else ""
        v = verb(seg)
        if v in REEVALUATING_SHELLS or (is_interpreter(v) and not re.match(r"^(python|pypy)[\d.]*$", v)):
            if body and DECODE.search(body):
                return "heredoc that decodes data for an interpreter"
        if re.match(r"^(python|pypy)[\d.]*$", v) and python_hides_execution(body):
            return "heredoc Python that runs a non-literal command or decodes data"
    if written & executed:
        return "a file written then executed in the same command"
    return None


def computed_command(text: str, depth: int = 0):
    """Reason if the program that runs is computed by the shell (its name holds $ or `), an alias is defined then
    used, eval runs something computed, or an interpreter runs a script whose path is computed. A rule written
    against a program name cannot see such a command."""
    reason = "the program or script that runs is computed by the shell (variable, $(...), `...`, alias or eval)"
    if depth > 4:
        return reason
    p = parse(text or "")
    bodies = {}
    for k, _, b in p.heredocs:
        bodies.setdefault(k, []).append(b)
    alias_defined = False
    for k, seg in enumerate(p.segments):
        if not seg:
            continue
        w = command_words(seg)
        if w is None:
            w = seg.split()
        if not w:
            continue
        v = w[0]
        if v == "alias":
            alias_defined = alias_defined or any("=" in a for a in w[1:])
            continue
        if v in ("for", "case", "function", "select", "[", "[[", "((", "local", "export", "declare", "readonly",
                 "typeset", "unset", "set", "shift", "return", "break", "continue", "wait", "read", "trap", "cd"):
            continue
        if alias_defined or re.search(r"[$`]", v):
            return reason
        base = os.path.basename(v)
        if base == "eval":
            rest = " ".join(w[1:])
            if re.search(r"[$`]", rest):
                return reason
            r = computed_command(rest, depth + 1)
            if r:
                return r
            continue
        if not is_interpreter(base):
            continue
        if base in REEVALUATING_SHELLS:
            for b in bodies.get(k, ()):
                r = computed_command(b, depth + 1)
                if r:
                    return r
        rest = w[1:]
        while rest:
            a = rest.pop(0)
            if base in REEVALUATING_SHELLS and re.fullmatch(r"-[a-zA-Z]*c[a-zA-Z]*", a):
                r = computed_command(rest[0], depth + 1) if rest else None
                if r:
                    return r
                break
            if a in ("--eval", "--command") or re.fullmatch(r"-[a-zA-Z]*[cemE]", a):
                break
            if a in ("-W", "-X", "-o", "-O", "--rcfile", "--init-file", "-r", "--require", "-I"):
                if rest:
                    rest.pop(0)
                continue
            if a.startswith("-"):
                continue
            if re.search(r"[$`]", a):
                return reason
            break
    return None


def glob_launch(text: str):
    """Reason if a command launches a program whose name is a wildcard pattern (``/usr/bin/g?t push``)."""
    for seg in segments(text):
        w = command_words(seg)
        if not w or w[0] in ("for", "[", "[["):
            continue
        target = w[0]
        if is_interpreter(target):
            rest, target = w[1:], None
            while rest:
                a = rest.pop(0)
                if a in ("--eval", "--command") or re.fullmatch(r"-[a-zA-Z]*[cemE]", a):
                    break
                if not a.startswith("-"):
                    target = a
                    break
        if target and GLOB_CHARS.search(target):
            return "a program launched through a wildcard pattern (*, ?, [)"
    return None


def python_code_blocks(text: str, code: bool = False) -> list:
    """Python code readable in a command: python -c arguments and heredoc bodies read by python; or the whole text
    (code=True, for execute_code)."""
    if code:
        return [text or ""]
    p = parse(text or "")
    out = []
    for seg in p.segments:
        w = command_words(seg) if seg else None
        if w and re.match(r"^(python|pypy)[\d.]*$", os.path.basename(w[0])) and "-c" in w[1:-1]:
            out.append(w[w.index("-c", 1) + 1])
    out += [b for k, _, b in p.heredocs if k < len(p.segments) and re.match(r"^(python|pypy)[\d.]*$",
                                                                            verb(p.segments[k]))]
    return out


ARGV_LIST = re.compile(r"\[\s*((?:[rbuf]?[\"'][^\"'\n]*[\"']\s*,\s*)+[rbuf]?[\"'][^\"'\n]*[\"'])\s*,?\s*\]")


def argv_literals(code: str) -> list:
    """Literal argument lists in code, joined as a command: ``run(["git", "push"])`` gives ``git push``."""
    out = []
    for m in ARGV_LIST.finditer(code or ""):
        parts = re.findall(r"[rbuf]?[\"']([^\"'\n]*)[\"']", m.group(1))
        if parts:
            out.append(" ".join(parts))
    return out


def substitution_bodies(text: str) -> list:
    """The commands inside `...` and inside a double-quoted "$(...)" that the shell runs. Read segment by segment
    (comments and heredoc bodies are already out, so a stray apostrophe there opens no quote); an unquoted $(...) is
    not returned, parse already splits it into segments."""
    out = []
    for seg in parse(text or "").segments:
        i, n, quote = 0, len(seg), None
        while i < n:
            c = seg[i]
            if quote == "'":
                quote = None if c == "'" else quote
            elif c == "\\":
                i += 2
                continue
            elif c == "'" and quote is None:
                quote = "'"
            elif c == '"':
                quote = None if quote == '"' else '"'
            elif c == "`":
                end = seg.find("`", i + 1)
                while end > 0 and seg[end - 1] == "\\":
                    end = seg.find("`", end + 1)
                out.append(seg[i + 1:] if end < 0 else seg[i + 1:end].replace("\\`", "`"))
                if end < 0:
                    break
                i = end + 1
                continue
            elif c == "$" and quote == '"' and seg[i + 1:i + 2] == "(" and seg[i + 2:i + 3] != "(":
                depth, j = 1, i + 2
                while j < n and depth:
                    depth += {"(": 1, ")": -1}.get(seg[j], 0)
                    j += 1
                out.append(seg[i + 2:j - 1] if not depth else seg[i + 2:])
                i = j
                continue
            i += 1
    return [b for b in out if b.strip()]


def unquoted(segment: str) -> str:
    """A segment with the inside of its quotes blanked (same length): what the shell reads as operators, not text."""
    out, quote = [], None
    for c in segment:
        if quote:
            out.append(c if c == quote else " ")
            quote = None if c == quote else quote
        else:
            quote = c if c in "'\"" else None
            out.append(c)
    return "".join(out)


def command_views(text: str, depth: int = 0, code: bool = True) -> list:
    """What a command line actually runs, one line per simple command: its words, with any word that holds a space
    replaced by "…" (a text value such as a commit message, not a subcommand). Shell strings run by sh -c, eval,
    watch and heredocs read by a shell are opened and read the same way. Inline code (python -c, heredocs read by
    python) is returned as is, with its literal argument lists; with code=False, only command lines are returned."""
    if depth > 4:
        return []
    p = parse(text or "")
    out = []
    for body in substitution_bodies(text or "") if p.substitution else []:
        out += command_views(body, depth + 1, code)
    for k, seg in enumerate(p.segments):
        if not seg:
            continue
        w = command_words(seg)
        if w is None:
            out.append(unmask(seg))
            continue
        if not w:
            continue
        out.append(" ".join(a if not re.search(r"\s", a) else "…" for a in w))
        v = os.path.basename(w[0])
        if v in REEVALUATING_SHELLS - {".", "source"} or v in ("watch", "su", "runuser"):
            if v == "eval":
                out += command_views(" ".join(w[1:]), depth + 1, code)
            else:
                for j, a in enumerate(w[1:-1], 1):
                    if re.fullmatch(r"-[a-zA-Z]*c[a-zA-Z]*", a):
                        out += command_views(w[j + 1], depth + 1, code)
                        break
                if v == "watch" and len(w) > 1 and not w[-1].startswith("-"):
                    out += command_views(w[-1], depth + 1, code)
        if v == "find":
            for j, a in enumerate(w):
                if a in ("-exec", "-execdir", "-ok", "-okdir"):
                    out.append(" ".join(x for x in w[j + 1:] if x not in (";", "+", "{}")))
        if v == "xargs" or (w and os.path.basename((words(seg) or [""])[0]) == "xargs"):
            out.append(" ".join(w))
        lang, inline = _inline_code(v, w[1:])
        if code and inline is not None:
            out.append(inline)
            out += argv_literals(inline)
    for k, quoted, body in p.heredocs:
        v = verb(p.segments[k]) if k < len(p.segments) else ""
        if v in REEVALUATING_SHELLS:
            out += command_views(body, depth + 1, code)
        elif body and code:
            out.append(body)
            out += argv_literals(body)
    return out


def bypass(text: str, code: bool = False):
    """Reason if a command (or, with code=True, a block of Python) hides or computes what it executes; else None.
    These are not outbound actions in themselves: they are the shapes a rule written in clear cannot read."""
    if code:
        return "Python code that runs a command it computes (exec, eval, shell=True, a non-literal argument list)" \
            if python_hides_execution(text or "", decoding=False) else None
    return computed_command(text) or hidden_interpreter(text) or indirect_execution(text) or glob_launch(text) or \
        encoded_powershell(text)


ENCODED_FLAG = re.compile(r"[-/]e(c|n[a-z]*)?(:.*)?", re.I)


def encoded_powershell(text: str):
    """Reason if PowerShell is run with its code in base64 (-e, -ec, -enc, -EncodedCommand): nothing can be read."""
    for seg in segments(text or ""):
        w = command_words(seg)
        if w is None:
            if re.search(r"(^|[\s/\\])(powershell|pwsh)(\.exe)?\s[^\n;&|]*\s[-/]e(c|n[a-z]*)?(\s|:|$)", seg, re.I):
                return "PowerShell code passed encoded (-EncodedCommand)"
            continue
        w = [x for a in w for x in a.split()]                   # cmd //c "powershell -enc ..." is re-read
        names = [os.path.basename(a.replace("\\", "/")).lower() for a in w]   # also behind cmd //c, start
        k = next((i for i, n in enumerate(names) if n in ("powershell", "powershell.exe", "pwsh", "pwsh.exe")), -1)
        if k > 0 and not all(n in ("cmd", "cmd.exe", "start", "start.exe") or a.lower() in ("/c", "//c", "/k", "//k",
                                                                                         "/b", "//b")
                             for n, a in zip(names[:k], w[:k])):
            k = -1                                              # an argument (echo powershell -e), not a program
        if k >= 0 and any(ENCODED_FLAG.fullmatch(a) for a in w[k + 1:]):
            return "PowerShell code passed encoded (-EncodedCommand)"
    return None
