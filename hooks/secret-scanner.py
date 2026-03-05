#!/usr/bin/env python3
"""
Secret Scanner Hook (PreToolUse on Bash)

Intercepts git commit/add commands and scans staged files for secrets.
Exit code 2 = hard block (secrets found)
Exit code 0 = allow (clean)
Exit code 1 = error (graceful continue)
"""

import json
import re
import subprocess
import sys

# Secret patterns to detect
SECRET_PATTERNS = [
    # AWS Access Key ID
    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID'),
    # AWS Secret Access Key (generic 40-char base64)
    (r'(?i)aws_secret_access_key\s*[:=]\s*[\'"]?[A-Za-z0-9/+=]{40}[\'"]?', 'AWS Secret Access Key'),
    # Generic secrets in assignments
    (r'(?i)(password|passwd|pwd)\s*[:=]\s*[\'"][^\'"]{4,}[\'"]', 'Hardcoded password'),
    (r'(?i)(secret|api_key|apikey|auth_token)\s*[:=]\s*[\'"][^\'"]{8,}[\'"]', 'Hardcoded secret/API key'),
    # JWT tokens
    (r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+', 'JWT token'),
    # Private keys
    (r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', 'Private key'),
    # GitHub tokens
    (r'ghp_[A-Za-z0-9]{36}', 'GitHub personal access token'),
    (r'gho_[A-Za-z0-9]{36}', 'GitHub OAuth token'),
    (r'ghu_[A-Za-z0-9]{36}', 'GitHub user token'),
    # Generic bearer tokens
    (r'(?i)bearer\s+[A-Za-z0-9-_]{20,}', 'Bearer token'),
    # Connection strings with passwords
    (r'(?i)(mongodb|postgres|mysql|redis)://[^:]+:[^@]+@', 'Database connection string with password'),
]

# Files to skip (binary, lock files, etc.)
SKIP_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp',
    '.woff', '.woff2', '.ttf', '.eot',
    '.pdf', '.zip', '.tar', '.gz',
    '.lock', '.sum',
    '.min.js', '.min.css',
}


def get_staged_files():
    """Get list of staged files from git."""
    try:
        result = subprocess.run(
            ['git', 'diff', '--cached', '--name-only', '--diff-filter=ACMR'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            return []
        return [f.strip() for f in result.stdout.strip().split('\n') if f.strip()]
    except Exception:
        return []


def should_skip_file(filepath):
    """Check if file should be skipped."""
    lower_path = filepath.lower()
    for ext in SKIP_EXTENSIONS:
        if lower_path.endswith(ext):
            return True
    return False


def get_staged_content(filepath):
    """Get staged content of a file."""
    try:
        result = subprocess.run(
            ['git', 'show', f':{filepath}'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            return None
        return result.stdout
    except Exception:
        return None


def scan_content(content, filepath):
    """Scan content for secrets. Returns list of findings."""
    findings = []
    lines = content.split('\n')

    for line_num, line in enumerate(lines, 1):
        for pattern, secret_type in SECRET_PATTERNS:
            if re.search(pattern, line):
                # Mask the actual secret in output
                masked_line = line[:50] + '...' if len(line) > 50 else line
                findings.append({
                    'file': filepath,
                    'line': line_num,
                    'type': secret_type,
                    'preview': masked_line.strip()
                })

    return findings


def main():
    # Read hook input from stdin
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)  # No input, allow

    # Get the command being executed
    tool_input = input_data.get('tool_input', {})
    command = tool_input.get('command', '')

    # Only intercept git commit and git add commands
    if not command:
        sys.exit(0)

    # Check if this is a git commit or git add
    is_git_commit = 'git commit' in command or 'git add' in command
    if not is_git_commit:
        sys.exit(0)

    # Get staged files
    staged_files = get_staged_files()
    if not staged_files:
        sys.exit(0)

    # Scan each file
    all_findings = []
    for filepath in staged_files:
        if should_skip_file(filepath):
            continue

        content = get_staged_content(filepath)
        if content:
            findings = scan_content(content, filepath)
            all_findings.extend(findings)

    # If secrets found, block the operation
    if all_findings:
        print("=" * 60, file=sys.stderr)
        print("SECRETS DETECTED - COMMIT BLOCKED", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        print(f"\nFound {len(all_findings)} potential secret(s):\n", file=sys.stderr)

        for finding in all_findings[:10]:  # Limit output
            print(f"  [{finding['type']}]", file=sys.stderr)
            print(f"  File: {finding['file']}:{finding['line']}", file=sys.stderr)
            print(f"  Preview: {finding['preview']}", file=sys.stderr)
            print("", file=sys.stderr)

        if len(all_findings) > 10:
            print(f"  ... and {len(all_findings) - 10} more\n", file=sys.stderr)

        print("Remove secrets before committing.", file=sys.stderr)
        print("Use environment variables or .env files (gitignored).", file=sys.stderr)
        print("=" * 60, file=sys.stderr)

        sys.exit(2)  # Hard block

    sys.exit(0)  # Clean, allow


if __name__ == '__main__':
    main()
