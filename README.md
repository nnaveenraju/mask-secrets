# mask-secrets

A Claude Code plugin that masks secrets, API keys, PII, and sensitive data before they enter Claude's context window.

## How It Works

Two-layer defense-in-depth architecture:

| Layer | Hook Event | What It Does |
|-------|-----------|--------------|
| **Layer 1: Prevention** | PreToolUse (Read, Bash, Grep) | Intercepts data ingestion and masks sensitive content *before* Claude sees it |
| **Layer 2: Audit** | PostToolUse (Read, Bash, Grep) | Scans tool output for anything that slipped through Layer 1 and instructs Claude to use `[MASKED]` placeholders |
| **Secret Scanner** | PreToolUse (Bash) | Blocks `git commit`/`git add` if staged files contain secrets |
| **Cleanup** | SessionEnd | Removes temporary masked files |

## What Gets Masked

### Secrets (17 patterns)
AWS keys, generic passwords, API keys, JWT tokens, private keys, GitHub tokens, bearer tokens, database connection strings, Slack tokens, Stripe keys, SendGrid keys, OpenAI keys, Anthropic keys, Google API keys, npm tokens, PyPI tokens

### PII (5 patterns)
SSNs, credit card numbers, email addresses, US phone numbers, private IP addresses

### Always-masked files
`.env`, `.env.*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*credentials*`, `*secrets*`, `id_rsa*`, `id_ed25519*`

## Installation

Install as a Claude Code plugin:

```bash
claude plugin add /path/to/mask-secrets
```

Or add to your `.claude/plugins.json` manually.

## Configuration

The plugin ships with a default config at `config/sensitive-data.yaml`. You can override it at two levels:

| Level | Path | Purpose |
|-------|------|---------|
| **User global** | `~/.claude/sensitive-data.yaml` | Your personal overrides across all projects |
| **Per-project** | `.claude/sensitive-data.yaml` | Project-specific patterns and settings |

Config merging: bundled defaults < user global < project overrides. Lists append with deduplication. Scalars override.

### Adding custom patterns

```yaml
custom_patterns:
  - name: internal_account_id
    regex: 'ACCT-[0-9]{8}'
    mask: '[MASKED_ACCOUNT]'
```

### Disabling for a project

```yaml
enabled: false
```

## Architecture

```
mask-secrets/
  .claude-plugin/
    plugin.json           # Plugin manifest
  hooks/
    hooks.json            # Hook registration (uses ${CLAUDE_PLUGIN_ROOT})
    masking_engine.py     # Shared core: config, patterns, masking, file classification
    sensitive-data-mask.py  # Layer 1: PreToolUse prevention
    sensitive-data-audit.py # Layer 2: PostToolUse audit
    mask-filter.py        # Stdin/stdout pipe filter for Bash command wrapping
    secret-scanner.py     # Git commit secret scanner
  config/
    sensitive-data.yaml   # Bundled default configuration
  tests/
    test-sensitive-data.py  # 104-test suite
```

## How Each Hook Works

### sensitive-data-mask.py (PreToolUse)

- **Read**: Masks file content, writes to temp file, redirects Claude to read the temp file via `updatedInput`
- **Bash**: Detects file-reading commands (`cat`, `grep`, `curl`, etc.) and pipes their output through `mask-filter.py`
- **Grep**: Adds security warning context when content mode is active

### sensitive-data-audit.py (PostToolUse)

Scans `tool_response` for sensitive patterns. If found, provides feedback telling Claude to use `[MASKED]` placeholders instead of raw values.

### secret-scanner.py (PreToolUse)

Intercepts `git commit` and `git add`, scans staged files for secrets, and hard-blocks (exit 2) if any are found.

## Testing

```bash
python3 tests/test-sensitive-data.py
```

Runs 104 tests covering pattern matching, false positives, config loading, Read/Bash/Grep flows, PostToolUse audit, pipe filter, file classification, and hooks.json integrity.

## Exit Codes

| Code | Meaning | Effect |
|------|---------|--------|
| 0 | Allow | Operation proceeds |
| 2 | Block/Feedback | PreToolUse: blocks operation. PostToolUse: shows feedback |
| 1 | Error | Hook failed, operation proceeds (graceful) |

## Requirements

- Python 3.8+
- PyYAML (optional — falls back to built-in basic parser)

## License

MIT

---

**Version:** 1.0.0
**Author:** Naveen Nadimpalli
