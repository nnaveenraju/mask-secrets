#!/usr/bin/env python3
"""
Sensitive Data Audit — PostToolUse hook for Read, Bash, Grep.

Layer 2 (Detection): Scans tool_response for sensitive patterns that
slipped through Layer 1 (PreToolUse masking). If found, provides
feedback to Claude instructing it not to repeat the raw values.

Note: PostToolUse "block" does NOT prevent the data from reaching
Claude's context. It provides after-the-fact feedback that Claude
should use [MASKED] placeholders instead of real values.
"""

import json
import os
import sys

# Import shared masking engine
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import masking_engine
except ImportError:
    sys.exit(0)  # Engine missing — allow everything


def _collect_strings(obj):
    """Recursively extract all string values from a nested structure."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _collect_strings(v)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            yield from _collect_strings(item)


def _extract_response_text(input_data):
    """Extract scannable text from tool_response.

    tool_response can be a string, dict, or nested structure.
    For dicts/lists, we extract leaf strings directly (not via
    json.dumps) so that quotes aren't escaped — regex patterns
    can match values like password="secret" correctly.
    """
    response = input_data.get('tool_response', '')
    if isinstance(response, str):
        return response
    return '\n'.join(_collect_strings(response))


def main():
    try:
        input_data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)

    config = masking_engine.load_config(os.getcwd())
    if not config.get('enabled', True):
        sys.exit(0)

    response_text = _extract_response_text(input_data)
    if not response_text:
        sys.exit(0)

    patterns = masking_engine.compile_patterns(config)
    _, count = masking_engine.mask_content(response_text, patterns)

    if count > 0:
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "decision": "block",
                "reason": (
                    f"[SECURITY AUDIT] {count} sensitive value(s) detected "
                    f"in tool output. Do NOT repeat, log, or reference the "
                    f"raw values. Use [MASKED] placeholders if you need to "
                    f"discuss them."
                ),
            }
        }
        json.dump(output, sys.stdout)

    sys.exit(0)


if __name__ == '__main__':
    main()
