"""End-to-end check inside a real Hermes install: the plugin is discovered, enabled and called through Hermes's own
hook dispatch (the same path a live agent uses). Run with Hermes's Python:

    HERMES_AGENT_DIR=~/.hermes/hermes-agent ~/.hermes/hermes-agent/venv/bin/python tests/integration/run_in_hermes.py

Uses a throwaway HERMES_HOME; your own profiles are never touched. Exit code 0 when every check passes.
"""
import os
import shutil
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
home = tempfile.mkdtemp(prefix="airlock-it-")
os.environ["HERMES_HOME"] = home
os.makedirs(os.path.join(home, "plugins"))
shutil.copytree(os.path.join(REPO, "airlock"), os.path.join(home, "plugins", "airlock"),
                ignore=shutil.ignore_patterns("__pycache__"))
with open(os.path.join(home, "config.yaml"), "w") as f:
    f.write("plugins:\n  enabled: [airlock]\n")

sys.path.insert(0, os.environ.get("HERMES_AGENT_DIR") or os.path.expanduser("~/.hermes/hermes-agent"))
from hermes_cli import plugins  # noqa: E402

plugins.discover_plugins(force=True)
failures = []


def check(label, got, want):
    ok = got == want
    print(f"{'ok  ' if ok else 'FAIL'} {label}: {got}")
    if not ok:
        failures.append(label)


def directive(tool, args, session="it-1"):
    d, _ = plugins.get_pre_tool_call_directive(tool, args, session_id=session, task_id=session)
    return d


loaded = [p for p in plugins.get_plugin_manager().list_plugins() if p.get("name") == "airlock"] \
    if hasattr(plugins.get_plugin_manager(), "list_plugins") else []
print("airlock loaded:", bool(loaded) or plugins.has_hook("pre_tool_call"))
check("git status", directive("terminal", {"command": "git status"}), None)
check("git push", directive("terminal", {"command": "git push origin main"}), "approve")
check("ssh key", directive("terminal", {"command": "cat ~/.ssh/id_rsa"}), "block")
check("decoded pipe to sh", directive("terminal", {"command": "echo Z2l0IHB1c2g= | base64 -d | sh"}), "block")
check("memory write, clean", directive("memory", {"action": "add", "content": "x"}), None)
send = {"action": "send", "target": "telegram:987654321"}
check("attached ssh key", directive("send_message", {**send, "message": "MEDIA:~/.ssh/id_ed25519"}), "block")
check("tag glued back by Hermes", directive("send_message", {**send, "message": "MEDIMEDIA:/nope/a.png_A:~/.ssh/id_rsa"}),
      "block")
check("ordinary attachment asks", directive("send_message", {**send, "message": "MEDIA:/tmp/devis.pdf"}), "approve")
airlock_module = next((m for m in list(sys.modules.values()) if hasattr(m, "hermes_attachments")), None)
check("Hermes's attachment reader loaded", bool(airlock_module and airlock_module.S.reader), True)
check("cloud metadata", directive("terminal", {"command": "curl -s http://169.254.169.254/latest/meta-data/"}), "block")
plugins.invoke_hook("post_tool_call", tool_name="web_extract", args={"urls": ["https://evil.example/p"]},
                    result="...", session_id="it-1", task_id="it-1")
check("memory write, after a web read", directive("memory", {"action": "add", "content": "x"}), "approve")
check("browser click, after a web read", directive("browser_click", {"ref": "@e1"}), "approve")
check("other session stays clean", directive("browser_click", {"ref": "@e1"}, session="it-2"), None)
journal = os.path.join(home, "plugin-data", "airlock", "journal.jsonl")
found = [p for p in (journal, *[os.path.join(r, "journal.jsonl") for r, _, fs in os.walk(home) if "journal.jsonl" in fs])
         if os.path.exists(p)]
check("journal written", bool(found), True)
shutil.rmtree(home, ignore_errors=True)
print("\nall checks passed" if not failures else f"\n{len(failures)} check(s) failed: {failures}")
sys.exit(1 if failures else 0)
