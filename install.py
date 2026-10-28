#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
1-Command Cross-Platform Installer for AI Agent & MCP Security Auditor
Installs the CLI scanner and registers the Agent Skill in both Antigravity and Claude Code.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main() -> None:
    parser = argparse.ArgumentParser(description="Install MCP & Agent Security Auditor CLI & Skill")
    parser.add_argument("--home", type=str, default=os.path.expanduser("~"), help="Target user home directory")
    args = parser.parse_args()

    home = os.path.abspath(args.home)
    src_dir = os.path.dirname(os.path.abspath(__file__))

    target_bin_dir = os.path.join(home, ".mcp-security-auditor")
    os.makedirs(target_bin_dir, exist_ok=True)

    scanner_dst = os.path.join(target_bin_dir, "mcp_security_auditor.py")
    shutil.copy2(os.path.join(src_dir, "mcp_security_auditor.py"), scanner_dst)

    agy_skill_dir = os.path.join(home, ".gemini", "config", "skills", "mcp-agent-security-auditor")
    claude_skill_dir = os.path.join(home, ".claude", "skills", "mcp-agent-security-auditor")
    for sdir in (agy_skill_dir, claude_skill_dir):
        os.makedirs(sdir, exist_ok=True)
        shutil.copy2(os.path.join(src_dir, "SKILL.md"), os.path.join(sdir, "SKILL.md"))
        shutil.copy2(os.path.join(src_dir, "mcp_security_auditor.py"), os.path.join(sdir, "mcp_security_auditor.py"))

    print(
        json.dumps(
            {
                "status": "installed",
                "scanner_script": scanner_dst,
                "agy_skill": os.path.join(agy_skill_dir, "SKILL.md"),
                "claude_skill": os.path.join(claude_skill_dir, "SKILL.md"),
                "run_command": f'"{sys.executable}" "{scanner_dst}" .',
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
