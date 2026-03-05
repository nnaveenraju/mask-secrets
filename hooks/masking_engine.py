#!/usr/bin/env python3
"""
Masking Engine — Shared core for sensitive data hooks.

Provides config loading, pattern compilation, content masking,
and file classification. Used by sensitive-data-mask.py,
sensitive-data-audit.py, and mask-filter.py.
"""

import fnmatch
import os
import re

# Optional: PyYAML for config loading. Fall back to basic parser if unavailable.
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# ---------------------------------------------------------------------------
# Module-level caches (persist for the lifetime of a single hook invocation)
# ---------------------------------------------------------------------------
_config_cache = None
_patterns_cache = None

# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

# Resolve config: plugin-bundled default → user global override → project override
_PLUGIN_ROOT = os.environ.get(
    'CLAUDE_PLUGIN_ROOT',
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
BUNDLED_CONFIG_PATH = os.path.join(_PLUGIN_ROOT, 'config', 'sensitive-data.yaml')
GLOBAL_CONFIG_PATH = os.path.expanduser('~/.claude/sensitive-data.yaml')
PROJECT_CONFIG_NAME = '.claude/sensitive-data.yaml'

# Minimal defaults if no config file exists at all
DEFAULT_CONFIG = {
    'version': 1,
    'enabled': True,
    'patterns': {'secrets': [], 'pii': []},
    'custom_patterns': [],
    'always_mask_files': ['.env', '.env.*', '*.pem', '*.key'],
    'skip_patterns': ['node_modules', '.git', '__pycache__',
                      '*.png', '*.jpg', '*.gif', '*.pdf', '*.zip',
                      '*.lock', '*.wasm', '*.pyc', '*.so'],
    'max_file_size': 10 * 1024 * 1024,  # 10 MB
    'temp_dir_prefix': '/tmp/claude-masked',
}


def _parse_yaml_file(path):
    """Load a YAML file. Returns dict or None on failure."""
    if not os.path.isfile(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            if HAS_YAML:
                return yaml.safe_load(f) or {}
            else:
                return _basic_yaml_parse(f.read())
    except Exception:
        return None


def _basic_yaml_parse(text):
    """Minimal YAML-like parser for when PyYAML is not installed.
    Handles simple key: value pairs and lists. Not a full YAML parser.
    Returns a flat dict with basic structure."""
    result = {}
    current_key = None
    current_list = None
    indent_stack = []

    for line in text.split('\n'):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue

        # Simple key: value
        if ':' in stripped and not stripped.startswith('-'):
            key, _, value = stripped.partition(':')
            key = key.strip()
            value = value.strip()
            if value:
                # Remove quotes
                if (value.startswith("'") and value.endswith("'")) or \
                   (value.startswith('"') and value.endswith('"')):
                    value = value[1:-1]
                # Type conversion
                if value.lower() == 'true':
                    value = True
                elif value.lower() == 'false':
                    value = False
                elif value.isdigit():
                    value = int(value)
                result[key] = value
            else:
                current_key = key
                if current_key not in result:
                    result[current_key] = {}
        elif stripped.startswith('- '):
            value = stripped[2:].strip()
            if (value.startswith("'") and value.endswith("'")) or \
               (value.startswith('"') and value.endswith('"')):
                value = value[1:-1]
            if current_key:
                if not isinstance(result.get(current_key), list):
                    result[current_key] = []
                result[current_key].append(value)

    return result


def _merge_list(global_list, project_list):
    """Append project items to global list, deduplicating."""
    combined = list(global_list)
    existing = set(str(item) for item in combined)
    for item in project_list:
        if str(item) not in existing:
            combined.append(item)
            existing.add(str(item))
    return combined


def _merge_pattern_list(global_patterns, project_patterns):
    """Append project patterns to global, deduplicate by name."""
    combined = list(global_patterns)
    existing_names = {p['name'] for p in combined}
    for p in project_patterns:
        if p.get('name') not in existing_names:
            combined.append(p)
            existing_names.add(p['name'])
    return combined


def _merge_project_config(base, project):
    """Merge project config into base config in place.

    Scalars (enabled, max_file_size) override.
    Lists and pattern categories append with deduplication.
    """
    # Scalars: project overrides global
    for key in ('enabled', 'max_file_size'):
        if key in project:
            base[key] = project[key]

    # Pattern categories: merge by name
    proj_patterns = project.get('patterns', {})
    for category in ['secrets', 'pii']:
        if category in proj_patterns:
            base['patterns'][category] = _merge_pattern_list(
                base.get('patterns', {}).get(category, []),
                proj_patterns[category]
            )

    # Lists: append with deduplication
    for key in ('custom_patterns', 'always_mask_files', 'skip_patterns'):
        if key in project and project[key]:
            base[key] = _merge_list(base.get(key, []), project[key])


def load_config(cwd=None):
    """Load and merge global + project config. Returns dict."""
    global _config_cache
    if _config_cache is not None:
        return _config_cache

    # Load config: bundled default → user global override → project override
    config = _parse_yaml_file(BUNDLED_CONFIG_PATH) or dict(DEFAULT_CONFIG)
    for key, default in DEFAULT_CONFIG.items():
        if key not in config:
            config[key] = default

    # Merge user's global config on top (if they've customized)
    global_override = _parse_yaml_file(GLOBAL_CONFIG_PATH)
    if global_override:
        _merge_project_config(config, global_override)

    # Merge project config if cwd provided
    if cwd:
        project = _parse_yaml_file(os.path.join(cwd, PROJECT_CONFIG_NAME))
        if project:
            _merge_project_config(config, project)

    _config_cache = config
    return config


# ---------------------------------------------------------------------------
# Pattern compilation
# ---------------------------------------------------------------------------

def _compile_pattern_entry(entry, default_mask='[MASKED]'):
    """Compile a single pattern dict into (compiled_re, mask, name) or None."""
    regex = entry.get('regex', '')
    if not regex:
        return None
    try:
        return (re.compile(regex), entry.get('mask', default_mask), entry.get('name', 'unknown'))
    except re.error:
        return None


def _collect_all_pattern_dicts(config):
    """Gather all pattern dicts from config categories + custom_patterns."""
    all_entries = []
    for category in ['secrets', 'pii']:
        all_entries.extend(config.get('patterns', {}).get(category, []))
    all_entries.extend(config.get('custom_patterns', []) or [])
    return all_entries


def compile_patterns(config):
    """Compile all regex patterns from config. Returns list of (compiled_re, mask, name)."""
    global _patterns_cache
    if _patterns_cache is not None:
        return _patterns_cache

    entries = _collect_all_pattern_dicts(config)
    compiled = [c for c in (_compile_pattern_entry(e) for e in entries) if c is not None]

    _patterns_cache = compiled
    return compiled


# ---------------------------------------------------------------------------
# Content masking
# ---------------------------------------------------------------------------

def mask_content(content, patterns):
    """Apply all patterns to content string.

    Returns (masked_content, mask_count) where mask_count is the total
    number of replacements made.
    """
    if not content or not patterns:
        return content, 0

    total_count = 0
    masked = content

    for compiled_re, mask_label, _name in patterns:
        # Count matches before replacing
        matches = compiled_re.findall(masked)
        if matches:
            total_count += len(matches)
            masked = compiled_re.sub(mask_label, masked)

    return masked, total_count


def mask_full_content(content):
    """Mask ALL non-empty, non-comment lines in content.
    Used for files in the always_mask_files list.

    Preserves structure (blank lines, comments, key names) but masks values.
    """
    if not content:
        return content, 0

    lines = content.split('\n')
    masked_lines = []
    mask_count = 0

    for line in lines:
        stripped = line.strip()

        # Preserve empty lines
        if not stripped:
            masked_lines.append(line)
            continue

        # Preserve comment lines
        if stripped.startswith('#') or stripped.startswith('//'):
            masked_lines.append(line)
            continue

        # For key=value or key: value lines, mask the value
        for separator in ['=', ':']:
            if separator in stripped:
                idx = line.index(separator)
                key_part = line[:idx + 1]
                value_part = line[idx + 1:].strip()
                if value_part:
                    masked_lines.append(f"{key_part} [MASKED_VALUE]")
                    mask_count += 1
                else:
                    masked_lines.append(line)
                break
        else:
            # No separator found — mask the entire line
            masked_lines.append('[MASKED_LINE]')
            mask_count += 1

    return '\n'.join(masked_lines), mask_count


# ---------------------------------------------------------------------------
# File classification
# ---------------------------------------------------------------------------

def _glob_matches(name, pattern):
    """Case-insensitive glob match."""
    return fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(name.lower(), pattern.lower())


def _matches_any_glob(name, patterns):
    """Return True if name matches any pattern in the list."""
    return any(_glob_matches(name, p) for p in patterns)


def _exceeds_max_size(filepath, config):
    """Return True if file exceeds max_file_size."""
    max_size = config.get('max_file_size', 10 * 1024 * 1024)
    try:
        return os.path.isfile(filepath) and os.path.getsize(filepath) > max_size
    except OSError:
        return False


def should_skip_file(filepath, config):
    """Return True if this file should be skipped entirely (binary, vendor, etc.)."""
    if not filepath:
        return True

    if _exceeds_max_size(filepath, config):
        return True

    skip_list = config.get('skip_patterns', [])
    if not skip_list:
        return False

    parts = filepath.replace('\\', '/').split('/')
    return any(_matches_any_glob(part, skip_list) for part in parts)


def should_always_mask(filepath, config):
    """Return True if this file should have ALL content masked."""
    if not filepath:
        return False

    always_list = config.get('always_mask_files', [])
    if not always_list:
        return False

    return _matches_any_glob(os.path.basename(filepath), always_list)


# ---------------------------------------------------------------------------
# Temp file management
# ---------------------------------------------------------------------------

def get_temp_dir(session_id):
    """Get or create temp directory for masked files.
    Returns path like /tmp/claude-masked-{session_id}/
    """
    prefix = '/tmp/claude-masked'
    if session_id:
        temp_dir = f"{prefix}-{session_id}"
    else:
        temp_dir = f"{prefix}-default"

    os.makedirs(temp_dir, exist_ok=True)
    return temp_dir


def get_temp_path(session_id, original_path):
    """Get deterministic temp file path for an original file.

    Converts /path/to/file.env → /tmp/claude-masked-{sid}/path___to___file.env
    """
    temp_dir = get_temp_dir(session_id)
    # Replace path separators with ___ to create flat filename
    safe_name = original_path.replace('/', '___').replace('\\', '___')
    # Remove leading separators
    safe_name = safe_name.lstrip('_')
    return os.path.join(temp_dir, safe_name)


def write_temp_file(content, session_id, original_path):
    """Write masked content to a temp file. Returns the temp file path."""
    temp_path = get_temp_path(session_id, original_path)
    with open(temp_path, 'w', encoding='utf-8') as f:
        f.write(content)
    return temp_path


# ---------------------------------------------------------------------------
# Convenience: full pipeline for a file
# ---------------------------------------------------------------------------

def mask_file(filepath, config, patterns, session_id):
    """Read a file, mask its content, write to temp.

    Returns (temp_path, mask_count) or (None, 0) if no masking needed.
    """
    # Skip binary/vendor files
    if should_skip_file(filepath, config):
        return None, 0

    # Read the file
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except (OSError, UnicodeDecodeError):
        return None, 0

    if not content:
        return None, 0

    # Apply masking
    if should_always_mask(filepath, config):
        masked, count = mask_full_content(content)
        # Also apply pattern masking on top (catch anything mask_full_content missed)
        masked, extra = mask_content(masked, patterns)
        count += extra
    else:
        masked, count = mask_content(content, patterns)

    if count == 0:
        return None, 0

    # Write temp file
    temp_path = write_temp_file(masked, session_id, filepath)
    return temp_path, count
