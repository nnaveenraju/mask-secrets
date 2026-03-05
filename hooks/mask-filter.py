#!/usr/bin/env python3
"""
Mask Filter — Standalone stdin-to-stdout pipe filter.

Used by sensitive-data-mask.py to wrap Bash file-reading commands:
  (original_command) 2>&1 | python3 mask-filter.py

Reads all of stdin, applies sensitive data patterns, writes
masked output to stdout. Always exits 0 to avoid breaking pipes.
"""

import os
import sys

# Import shared masking engine
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import masking_engine
except ImportError:
    # Engine missing — pass through unmodified
    try:
        sys.stdout.write(sys.stdin.read())
    except Exception:
        pass
    sys.exit(0)


def main():
    try:
        content = sys.stdin.read()
    except Exception:
        sys.exit(0)

    if not content:
        sys.exit(0)

    config = masking_engine.load_config(os.getcwd())
    if not config.get('enabled', True):
        sys.stdout.write(content)
        sys.exit(0)

    patterns = masking_engine.compile_patterns(config)
    masked, _ = masking_engine.mask_content(content, patterns)
    sys.stdout.write(masked)
    sys.exit(0)


if __name__ == '__main__':
    main()
