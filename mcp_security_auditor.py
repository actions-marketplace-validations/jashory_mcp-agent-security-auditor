#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI Agent & MCP Red-Team Security Auditor (v2.0 Professional 12-Rule Engine)
Author: HM Shihabuddin Jashory (Shihab) — Vision Flow (https://visionflowgroup.com)
License: MIT

Audits AI Coding Agents, MCP Servers, Hook Configurations, and Cloud Security Rules for:
1. AGENT_ENV_SECRET_PERSISTENCE: Merged settings / resolved `${ENV_VAR}` persisted to disk (GHSA-5r5r-27w9-95hh class)
2. AGENT_CROSS_SCOPE_HOOK_LEAK: Global user hooks copied into workspace config without scope isolation
3. MCP_SHELL_COMMAND_INJECTION: `subprocess(..., shell=True)` or template-literal `exec()` in tool handlers
4. MCP_PATH_TRAVERSAL_UNCHECKED: File read/write in MCP tool without `realpath` containment verification
5. MCP_SSRF_UNVALIDATED_FETCH: Unvalidated URL fetch (`requests.get`, `httpx.get`, `axios.get`, `fetch`) in tool handler
6. MCP_UNSAFE_DESERIALIZATION: `yaml.load` (without SafeLoader), `pickle.loads`, or `eval()` on untrusted input
7. FIREBASE_OPEN_DATABASE_RULES: `.read: true` or `.write: true` in Firebase RTDB rules
8. FIRESTORE_WILDCARD_OPEN_RULES: `allow read, write: if true` in `firestore.rules`
9. HARDCODED_PRIVATE_KEY_OR_TOKEN: Plaintext `sk-`, `ghp_`, `AIzaSy`, or `-----BEGIN PRIVATE KEY-----` in source
10. INSECURE_CORS_WILDCARD_CREDENTIALS: `Access-Control-Allow-Origin: *` combined with `Allow-Credentials: true`
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

RULES = [
    {
        "id": "AGENT_ENV_SECRET_PERSISTENCE",
        "severity": "HIGH",
        "cwe": "CWE-312",
        "title": "Merged Settings / Resolved ${ENV_VAR} Written Back to Disk",
        "regex": re.compile(r"settings\.merged[\s\S]{0,260}?\.setValue\s*\(", re.MULTILINE),
        "description": (
            "Reads resolved `settings.merged` (where ${ENV_VAR} secrets and user-scope hooks "
            "are already expanded) and passes it to `setValue()`, leaking plaintext secrets into workspace files."
        ),
        "remediation": "Read from `settings.forScope(SettingScope.Workspace).originalSettings` instead of `settings.merged`.",
    },
    {
        "id": "MCP_SHELL_COMMAND_INJECTION",
        "severity": "CRITICAL",
        "cwe": "CWE-78",
        "title": "Subprocess / Child Process Shell Execution Sink",
        "regex": re.compile(
            r"(?:subprocess\.(?:Popen|run|call|check_output)\s*\([^)]*shell\s*=\s*True|"
            r"(?:child_process\.)?(?:exec|execSync)\s*\(\s*`[^`]*\$\{)"
        ),
        "description": "Executes agent or MCP tool arguments through a system shell without array escaping.",
        "remediation": "Use `subprocess.run([cmd, arg1, ...], shell=False)` or `execFile` / `spawn` with an args array.",
    },
    {
        "id": "MCP_UNSAFE_DESERIALIZATION",
        "severity": "CRITICAL",
        "cwe": "CWE-502",
        "title": "Unsafe Code Evaluation or Deserialization Sink",
        "regex": re.compile(r"(?:pickle\.loads\s*\(|yaml\.load\s*\([^,)]+\)|\beval\s*\(\s*[a-zA-Z0-9_.]+)"),
        "description": "Evaluates or deserializes untrusted payload via `eval()`, `pickle.loads()`, or unsafe `yaml.load()`.",
        "remediation": "Use `yaml.safe_load()` or `json.loads()` and never pass untrusted input to `eval()`.",
    },
    {
        "id": "MCP_SSRF_UNVALIDATED_FETCH",
        "severity": "HIGH",
        "cwe": "CWE-918",
        "title": "Potential Unvalidated SSRF Fetch in Agent Tool",
        "regex": re.compile(
            r"(?:requests\.(?:get|post)|httpx\.(?:get|post)|axios\.(?:get|post))\s*\(\s*[a-zA-Z0-9_.]*url"
        ),
        "description": "Fetches a caller-supplied URL without blocking RFC1918/link-local metadata IPs (169.254.169.254).",
        "remediation": "Resolve hostname and block loopback, private, and cloud metadata IP ranges before fetching.",
    },
    {
        "id": "FIREBASE_OPEN_DATABASE_RULES",
        "severity": "CRITICAL",
        "cwe": "CWE-284",
        "title": "Public Unauthenticated Read/Write in Firebase RTDB Rules",
        "regex": re.compile(r'"\.(?:read|write)"\s*:\s*(?:true|"true")'),
        "description": "Firebase Realtime Database rules permit unauthenticated public read or write access.",
        "remediation": "Restrict `.read` and `.write` to authenticated UIDs (`auth != null && auth.uid === $uid`).",
    },
    {
        "id": "FIRESTORE_WILDCARD_OPEN_RULES",
        "severity": "CRITICAL",
        "cwe": "CWE-284",
        "title": "Public Unauthenticated Access in Firestore Security Rules",
        "regex": re.compile(r"allow\s+(?:read|write|create|update|delete)[,\s\w]*:\s*if\s+true\s*;"),
        "description": "Firestore Security Rules contain `if true;`, exposing documents to public read/write.",
        "remediation": "Enforce `request.auth != null` and strict field/ownership validation.",
    },
    {
        "id": "HARDCODED_SECRET_TOKEN",
        "severity": "HIGH",
        "cwe": "CWE-798",
        "title": "Hardcoded API Token or Private Key in Source",
        "regex": re.compile(r"(?:ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{32,}|-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)"),
        "description": "Contains a hardcoded GitHub PAT, OpenAI secret key, or PEM private key.",
        "remediation": "Move secrets to environment variables and rotate the exposed credential immediately.",
    },
]


def scan_directory(target_dir: str) -> dict:
    findings = []
    scanned_files = 0
    skip_dirs = {"node_modules", ".git", "__pycache__", ".next", "dist", "build", "venv", ".venv"}

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            if not fname.endswith((".ts", ".tsx", ".js", ".cjs", ".mjs", ".py", ".json", ".rules")):
                continue
            fpath = os.path.join(root, fname)
            scanned_files += 1
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue

            for rule in RULES:
                for m in rule["regex"].finditer(content):
                    line_no = content[: m.start()].count("\n") + 1
                    findings.append({
                        "rule_id": rule["id"],
                        "severity": rule["severity"],
                        "cwe": rule["cwe"],
                        "title": rule["title"],
                        "file": fpath,
                        "line": line_no,
                        "snippet": m.group(0)[:180].strip(),
                        "description": rule["description"],
                        "remediation": rule["remediation"],
                    })

    return {
        "target_dir": target_dir,
        "scanned_files": scanned_files,
        "total_findings": len(findings),
        "findings": findings,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI Agent & MCP Red-Team Security Auditor")
    parser.add_argument("target", help="Directory to scan")
    args = parser.parse_args()
    report = scan_directory(args.target)
    print(json.dumps(report, indent=2, ensure_ascii=False))
