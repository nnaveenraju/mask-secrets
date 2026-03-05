#!/usr/bin/env python3
"""
Sensitive Data Mask — PreToolUse hook for Read, Bash, Grep.

Layer 1 (Prevention): Intercepts data ingestion tools and masks
sensitive content before it reaches Claude's context window.

Read  → mask file content → redirect to temp file via updatedInput
Bash  → wrap file-reading commands with pipe filter via updatedInput
Grep  → add additionalContext warning for content mode
"""

import json
import os
import re
import sys

# Import shared masking engine
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import masking_engine
except ImportError:
    sys.exit(0)  # Engine missing — allow everything

# ---------------------------------------------------------------------------
# Bash command detection — patterns that indicate file/data reading
# ---------------------------------------------------------------------------
FILE_READ_PATTERNS = [
    re.compile(p) for p in [
        r'\bcat\b', r'\bhead\b', r'\btail\b', r'\bless\b', r'\bmore\b',
        r'\bsed\b', r'\bawk\b', r'\bcut\b', r'\bgrep\b',
        r'\bcurl\b', r'\bwget\b',
        r'\benv\b', r'\bprintenv\b', r'\bset\b', r'\bstrings\b',
        r'\bdocker\s+logs\b', r'\bkubectl\s+logs\b',
        r'\bpg_dump\b', r'\bmysqldump\b',
    ]
]

_PLUGIN_ROOT = os.environ.get(
    'CLAUDE_PLUGIN_ROOT',
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
MASK_FILTER = os.path.join(_PLUGIN_ROOT, 'hooks', 'mask-filter.py')


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _emit(updated_input=None, context=None):
    """Write hookSpecificOutput JSON to stdout and exit 0."""
    hook_output = {
        "hookEventName": "PreToolUse",
        "permissionDecision": "allow",
    }
    if updated_input:
        hook_output["updatedInput"] = updated_input
    if context:
        hook_output["additionalContext"] = context
    json.dump({"hookSpecificOutput": hook_output}, sys.stdout)
    sys.exit(0)


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------

def handle_read(tool_input, config, patterns, session_id):
    """Intercept Read: mask file, redirect to temp via updatedInput."""
    file_path = tool_input.get('file_path', '')
    if not file_path:
        sys.exit(0)

    if masking_engine.should_skip_file(file_path, config):
        sys.exit(0)

    temp_path, count = masking_engine.mask_file(
        file_path, config, patterns, session_id
    )

    if temp_path and count > 0:
        name = os.path.basename(file_path)
        updated = {"file_path": temp_path}
        # Preserve offset/limit so paginated reads work on the temp file
        for key in ('offset', 'limit'):
            if tool_input.get(key) is not None:
                updated[key] = tool_input[key]
        _emit(
            updated_input=updated,
            context=f"[SECURITY] {count} sensitive value(s) masked in {name}",
        )

    sys.exit(0)


def handle_bash(tool_input):
    """Intercept Bash: wrap file-reading commands with pipe filter."""
    command = tool_input.get('command', '')
    if not command:
        sys.exit(0)

    # Don't double-wrap
    if 'mask-filter.py' in command:
        sys.exit(0)

    if any(pat.search(command) for pat in FILE_READ_PATTERNS):
        wrapped = f'({command}) 2>&1 | python3 {MASK_FILTER}'
        _emit(updated_input={"command": wrapped})

    sys.exit(0)


def handle_grep(tool_input):
    """Intercept Grep: warn Claude when content mode exposes file data."""
    if tool_input.get('output_mode') == 'content':
        _emit(context=(
            "[SECURITY] Grep content mode active — output may contain "
            "sensitive data. Do NOT repeat raw secret values from results. "
            "Use [MASKED] placeholders if you need to reference them."
        ))

    sys.exit(0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    try:
        input_data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)

    tool_name = input_data.get('tool_name', '')
    tool_input = input_data.get('tool_input', {})
    session_id = input_data.get('session_id', '')

    config = masking_engine.load_config(os.getcwd())
    if not config.get('enabled', True):
        sys.exit(0)

    if tool_name == 'Read':
        patterns = masking_engine.compile_patterns(config)
        handle_read(tool_input, config, patterns, session_id)
    elif tool_name == 'Bash':
        handle_bash(tool_input)
    elif tool_name == 'Grep':
        handle_grep(tool_input)

    sys.exit(0)


if __name__ == '__main__':
    main()
