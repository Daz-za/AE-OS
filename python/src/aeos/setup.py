"""Guided setup: `aeos setup` asks a few questions and creates a ready-to-use log.

Every question has a sensible default, so pressing Enter throughout works. The same
answers can be given as options (see `aeos setup --help`) for scripted installs.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shlex
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .log import ReceiptLog

MODES = {
    "proxy": "The agent runs its MCP servers on this machine (the AE-OS proxy sits in front)",
    "gateway": "The agent's tool calls go through an MCP gateway or are traced with "
               "OpenTelemetry",
    "claude": "The agent runs in Claude Code or is built on the Claude Agent SDK",
    "later": "Decide later",
}


def _slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s or "my-log"


def default_key_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "aeos" / "keys"


class Wizard:
    def __init__(self, ask: Callable[[str], str] = input, out: Callable[[str], None] = print,
                 assume_defaults: bool = False) -> None:
        self.ask_fn, self.out, self.assume_defaults = ask, out, assume_defaults

    def ask(self, question: str, default: str, given: Optional[str] = None) -> str:
        if given is not None:
            return given
        if self.assume_defaults:
            return default
        answer = self.ask_fn(f"{question} [{default}]: ").strip()
        return answer or default

    def choose(self, question: str, options: Dict[str, str], default: str,
               given: Optional[str] = None) -> str:
        if given is not None or self.assume_defaults:
            return given or default
        keys = list(options)
        self.out(question)
        for n, k in enumerate(keys, 1):
            self.out(f"  {n}. {options[k]}")
        while True:
            answer = self.ask_fn(f"Choose 1-{len(keys)} [{keys.index(default) + 1}]: ").strip()
            if not answer:
                return default
            if answer.isdigit() and 1 <= int(answer) <= len(keys):
                return keys[int(answer) - 1]
            if answer in options:
                return answer
            self.out("Please type one of the numbers shown.")


def run(wizard: Wizard, *, log: Optional[str] = None, name: Optional[str] = None,
        key: Optional[str] = None, agent: Optional[str] = None,
        mode: Optional[str] = None) -> int:
    out = wizard.out
    out("This sets up an AE-OS receipt log: a tamper-evident record of what your AI agents "
        "do,\nwith signed receipts an auditor can check. Press Enter to accept a suggestion.\n")

    name = _slug(wizard.ask("A short name for this log, such as your organization and "
                            "process", "acme-accounts-payable", name))
    folder = Path(wizard.ask("Folder for the log", f"./{name}-log", log)).expanduser()
    if (folder / "log.json").exists():
        out(f"\n{folder} already holds a receipt log. Choose another folder, or see its "
            f"state with:\n  aeos status {folder}")
        return 2
    key_path = Path(wizard.ask(
        "Where to keep the signing key (outside the log folder, where agents cannot read "
        "it)", str(default_key_dir() / f"{name}.key"), key)).expanduser()
    agent = wizard.ask("The agent's identity, a name in web-address form",
                       f"spiffe://{name.split('-')[0]}.example/agent/{name}", agent)
    mode = wizard.choose("\nHow will the agent's tool calls reach the log?", MODES, "later",
                         mode)

    key_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(key_path.parent, 0o700)
    except OSError:
        pass
    created = ReceiptLog.create(folder, log_id=f"urn:aeos:{name}", key_path=key_path)
    (folder / "public-key.txt").write_text(created.public_key.hex() + "\n")

    q = shlex.quote
    base = f"{q(str(folder))} --key {q(str(key_path))} --agent {q(agent)}"
    steps: List[str] = []
    if mode == "proxy":
        steps += ["Point the agent at this command in place of its MCP server command "
                  "(replace the part after -- with the server's own command):",
                  f"  aeos mcp-proxy {base} -- python my_mcp_server.py",
                  "Add --allow-tool NAME for each tool the agent may use."]
    elif mode == "gateway":
        token_file = key_path.with_suffix(".sink-token")
        token_file.write_text(secrets.token_hex(24) + "\n")
        os.chmod(token_file, 0o600)
        steps += ["Start the log sink:",
                  f"  aeos sink {base} --token-file {q(str(token_file))}",
                  "Then send the gateway's OpenTelemetry traces (protocol http/json) to "
                  "http://127.0.0.1:4318/v1/traces, with the header "
                  f"'Authorization: Bearer <the token in {token_file}>'."]
    elif mode == "claude":
        cmd = f"aeos hook {base}"
        hooks = {ev: [{"hooks": [{"type": "command", "command": cmd}]}]
                 for ev in ("SessionStart", "PreToolUse", "PostToolUse", "PostToolUseFailure",
                            "SessionEnd")}
        snippet = folder / "claude-settings.json"
        snippet.write_text(json.dumps({"hooks": hooks}, indent=2) + "\n")
        steps += [f"Copy the \"hooks\" section of {snippet} into the project's "
                  ".claude/settings.json. Every tool call is then recorded; add "
                  "--allow-tool NAME to the commands to allow only named tools."]
    else:
        steps += ["When you know how the agent reaches its tools, see "
                  "https://github.com/Daz-za/ae-os/tree/main/python#readme, or run "
                  "aeos setup again for a new log."]
    steps += ["", "Check on the log at any time:", f"  aeos status {q(str(folder))}",
              "", "Give your auditors the public key in "
              f"{folder / 'public-key.txt'} through a channel they trust, such as email "
              "from a known address or your website. Back up the signing key; without it "
              "no new receipts can be issued for this log."]

    (folder / "NEXT-STEPS.txt").write_text("\n".join(steps) + "\n")
    out(f"\nCreated the log in {folder} and the signing key at {key_path}.\n")
    out("Next steps (also saved in NEXT-STEPS.txt in the log folder):")
    for line in steps:
        out(line)
    return 0
