#!/usr/bin/env python3
"""Scan a git diff for potential secrets/credentials.

Reads the diff between the PR base and head, inspects only ADDED lines,
and fails (exit code 1) if anything that looks like a secret is found.
"""

import math
import os
import re
import subprocess
import sys

# Regex patterns for well-known credential formats.
# Each entry: (human-readable name, compiled pattern)
SECRET_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b")),
    ("AWS Secret Access Key", re.compile(r"(?i)aws.{0,20}?['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("GitHub Token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{36,255}\b")),
    ("GitLab Token", re.compile(r"\bglpat-[A-Za-z0-9\-_]{20,}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+")),
    ("Stripe API Key", re.compile(r"\b(sk|rk)_(test|live)_[A-Za-z0-9]{20,}\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("SendGrid API Key", re.compile(r"\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b")),
    ("Twilio API Key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("npm Token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("OpenAI API Key", re.compile(r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b")),
    ("Anthropic API Key", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b")),
    ("Private Key Block", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\b")),
    ("Heroku API Key", re.compile(r"(?i)heroku.{0,20}\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")),
    ("Password in URL", re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:[^/\s:@]+@[^\s]+")),
    ("Generic API Key/Secret assignment", re.compile(
        r"(?i)[\w.-]*(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret|"
        r"secret[_-]?key|private[_-]?key|password|passwd|pwd)\b\s*[:=]\s*['\"][^'\"\s]{8,}['\"]"
    )),
]

# Added lines matching these are ignored (common false positives).
ALLOWLIST = [
    re.compile(r"(?i)(example|sample|placeholder|dummy|fake|test|changeme|your[_-]?(key|token|secret|password))"),
    re.compile(r"\$\{[^}]+\}"),          # ${ENV_VAR} style templating
    re.compile(r"\{\{[^}]+\}\}"),        # {{ mustache }} templating
    re.compile(r"(?i)os\.environ|getenv|process\.env|secrets\."),
]

ENTROPY_THRESHOLD = 4.5
ENTROPY_MIN_LENGTH = 32
ENTROPY_CANDIDATE = re.compile(r"['\"]([A-Za-z0-9+/=\-_]{32,})['\"]")


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    for ch in set(data):
        p = data.count(ch) / len(data)
        entropy -= p * math.log2(p)
    return entropy


def is_allowlisted(line: str) -> bool:
    return any(p.search(line) for p in ALLOWLIST)


def get_diff(base_sha: str, head_sha: str) -> str:
    result = subprocess.run(
        ["git", "diff", f"{base_sha}...{head_sha}", "--unified=0", "--no-color"],
        capture_output=True, text=True, check=True,
    )
    return result.stdout


def scan_diff(diff_text: str):
    findings = []
    current_file = None
    line_number = 0

    for raw_line in diff_text.splitlines():
        if raw_line.startswith("+++ b/"):
            current_file = raw_line[6:]
            continue
        if raw_line.startswith("@@"):
            match = re.search(r"\+(\d+)", raw_line)
            if match:
                line_number = int(match.group(1)) - 1
            continue
        if not raw_line.startswith("+") or raw_line.startswith("+++"):
            continue

        line_number += 1
        line = raw_line[1:]

        if current_file is None or is_allowlisted(line):
            continue

        for name, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append((current_file, line_number, name, line.strip()))
                break
        else:
            # High-entropy string detection for anything the patterns missed.
            for candidate in ENTROPY_CANDIDATE.findall(line):
                if len(candidate) >= ENTROPY_MIN_LENGTH and shannon_entropy(candidate) >= ENTROPY_THRESHOLD:
                    findings.append((current_file, line_number, "High-entropy string", line.strip()))
                    break

    return findings


def redact(line: str, max_len: int = 60) -> str:
    """Show enough context to locate the issue without printing the full secret."""
    if len(line) > max_len:
        line = line[:max_len] + "..."
    return line


def main() -> int:
    base_sha = os.environ.get("BASE_SHA")
    head_sha = os.environ.get("HEAD_SHA")
    if not base_sha or not head_sha:
        print("::error::BASE_SHA and HEAD_SHA environment variables are required")
        return 2

    diff_text = get_diff(base_sha, head_sha)
    findings = scan_diff(diff_text)

    if not findings:
        print("No potential secrets found in the diff.")
        return 0

    print(f"Found {len(findings)} potential secret(s):\n")
    for file, line_no, kind, snippet in findings:
        print(f"  {file}:{line_no} [{kind}] {redact(snippet)}")
        # GitHub annotation — shows up inline on the PR "Files changed" tab.
        print(f"::error file={file},line={line_no}::Potential secret detected ({kind}). "
              f"Remove it and rotate the credential if it was real.")

    print("\nIf a finding is a false positive, adjust the allowlist in .github/scripts/secret_scan.py")
    return 1


if __name__ == "__main__":
    sys.exit(main())
