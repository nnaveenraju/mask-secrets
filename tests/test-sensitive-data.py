#!/usr/bin/env python3
"""
Test Suite — Sensitive Data Masking Hook System

Validates all components: masking engine, PreToolUse hook,
PostToolUse auditor, pipe filter, and configuration loading.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

# Add hooks directory to path (tests/ is sibling to hooks/)
HOOKS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'hooks')
sys.path.insert(0, HOOKS_DIR)

# Track results
_pass = 0
_fail = 0


def ok(msg):
    global _pass
    _pass += 1
    print(f"  PASS  {msg}")


def fail(msg, detail=""):
    global _fail
    _fail += 1
    extra = f" — {detail}" if detail else ""
    print(f"  FAIL  {msg}{extra}")


def assert_eq(actual, expected, msg):
    if actual == expected:
        ok(msg)
    else:
        fail(msg, f"expected {expected!r}, got {actual!r}")


def assert_true(condition, msg, detail=""):
    if condition:
        ok(msg)
    else:
        fail(msg, detail)


def assert_in(needle, haystack, msg):
    if needle in haystack:
        ok(msg)
    else:
        fail(msg, f"{needle!r} not found")


def run_hook(hook_script, input_data):
    """Run a hook script with JSON input, return (stdout, stderr, exit_code)."""
    result = subprocess.run(
        ["python3", os.path.join(HOOKS_DIR, hook_script)],
        input=json.dumps(input_data),
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout, result.stderr, result.returncode


# =========================================================================
# Test 1: Pattern Matching — True Positives
# =========================================================================
def test_pattern_true_positives():
    print("\n[1] Pattern Matching — True Positives")
    import masking_engine

    # Reset caches for clean test
    masking_engine._config_cache = None
    masking_engine._patterns_cache = None

    config = masking_engine.load_config()
    patterns = masking_engine.compile_patterns(config)

    cases = [
        # Secrets
        ("AKIAIOSFODNN7EXAMPLE", "[MASKED_AWS_KEY]", "AWS access key"),
        ('aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
         "[MASKED_AWS_SECRET]", "AWS secret key"),
        ('password = "my_super_secret"', "[MASKED_PASSWORD]", "Generic password"),
        ('api_key = "abcdefgh12345678"', "[MASKED_SECRET]", "Generic secret"),
        ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.abc123",
         "[MASKED_JWT]", "JWT token"),
        ("-----BEGIN RSA PRIVATE KEY-----",
         "[MASKED_PRIVATE_KEY]", "RSA private key header"),
        ("-----BEGIN PRIVATE KEY-----",
         "[MASKED_PRIVATE_KEY]", "Generic private key header"),
        ("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
         "[MASKED_GITHUB_TOKEN]", "GitHub PAT"),
        ("gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
         "[MASKED_GITHUB_TOKEN]", "GitHub OAuth token"),
        ("Bearer eyJhbGciOiJIUzI1NiJ9abcdef",
         "[MASKED_BEARER]", "Bearer token"),
        ("postgres://admin:s3cret@db:5432/prod",
         "[MASKED_DB_URL]", "Postgres connection string"),
        ("mongodb://user:pass@mongo:27017/db",
         "[MASKED_DB_URL]", "MongoDB connection string"),
        ("xoxb-123456789-abcdefghij",
         "[MASKED_SLACK_TOKEN]", "Slack bot token"),
        ("sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZab",
         "[MASKED_STRIPE_KEY]", "Stripe live key"),
        ("sk_test_ABCDEFGHIJKLMNOPQRSTUVWXYZab",
         "[MASKED_STRIPE_KEY]", "Stripe test key"),
        ("SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr",
         "[MASKED_SENDGRID_KEY]", "SendGrid key"),
        ("sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh",
         "[MASKED_OPENAI_KEY]", "OpenAI key"),
        ("sk-ant-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh",
         "[MASKED_ANTHROPIC_KEY]", "Anthropic key"),
        ("AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg",
         "[MASKED_GOOGLE_KEY]", "Google API key"),
        ("npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
         "[MASKED_NPM_TOKEN]", "npm token"),
        # PII
        ("123-45-6789", "[MASKED_SSN]", "SSN"),
        ("4111-1111-1111-1111", "[MASKED_CC]", "Credit card (dashes)"),
        ("4111 1111 1111 1111", "[MASKED_CC]", "Credit card (spaces)"),
        ("user@example.com", "[MASKED_EMAIL]", "Email address"),
        ("(555) 123-4567", "[MASKED_PHONE]", "US phone number"),
        ("10.0.1.100", "[MASKED_IP]", "Private IP (10.x)"),
        ("192.168.1.1", "[MASKED_IP]", "Private IP (192.168.x)"),
    ]

    for test_input, expected_mask, label in cases:
        masked, count = masking_engine.mask_content(test_input, patterns)
        assert_true(
            count > 0 and expected_mask in masked,
            label,
            f"count={count}, masked={masked!r}",
        )


# =========================================================================
# Test 2: Pattern Matching — False Positives
# =========================================================================
def test_pattern_false_positives():
    print("\n[2] Pattern Matching — False Positives (should NOT mask)")
    import masking_engine

    config = masking_engine.load_config()
    patterns = masking_engine.compile_patterns(config)

    safe = [
        ("550e8400-e29b-41d4-a716-446655440000", "UUID"),
        ("sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", "Hash constant"),
        ("http://localhost:3000/api/v1/users", "Localhost URL"),
        ("port: 5432", "Port number"),
        ("version: 2.1.0", "Semantic version"),
        ("AKIA", "Partial AWS key (too short)"),
        ("password: ''", "Empty password"),
        ('password: "ab"', "Short password (< 4 chars)"),
        ("export PATH=/usr/bin", "PATH variable"),
        ("const MAX_RETRIES = 3", "Code constant"),
    ]

    for test_input, label in safe:
        _, count = masking_engine.mask_content(test_input, patterns)
        assert_eq(count, 0, f"No false positive: {label}")


# =========================================================================
# Test 3: Config Loading
# =========================================================================
def test_config_loading():
    print("\n[3] Config Loading")
    import masking_engine

    # Reset caches
    masking_engine._config_cache = None
    masking_engine._patterns_cache = None

    config = masking_engine.load_config()
    assert_true(config.get("enabled") is True, "Config enabled")
    assert_true(len(config.get("patterns", {}).get("secrets", [])) > 0,
                "Has secret patterns")
    assert_true(len(config.get("patterns", {}).get("pii", [])) > 0,
                "Has PII patterns")
    assert_true(".env" in config.get("always_mask_files", []),
                ".env in always_mask_files")
    assert_true("node_modules" in config.get("skip_patterns", []),
                "node_modules in skip_patterns")

    # Test project config merge
    masking_engine._config_cache = None
    masking_engine._patterns_cache = None

    tmpdir = tempfile.mkdtemp()
    proj_config_dir = os.path.join(tmpdir, ".claude")
    os.makedirs(proj_config_dir)

    with open(os.path.join(proj_config_dir, "sensitive-data.yaml"), "w") as f:
        f.write("version: 1\ncustom_patterns:\n  - name: test_custom\n"
                "    regex: 'CUSTOM_[0-9]+'\n    mask: '[MASKED_CUSTOM]'\n")

    config2 = masking_engine.load_config(cwd=tmpdir)
    custom = config2.get("custom_patterns", [])
    has_custom = any(p.get("name") == "test_custom" for p in custom
                     if isinstance(p, dict))
    assert_true(has_custom, "Project custom pattern merged")

    shutil.rmtree(tmpdir)


# =========================================================================
# Test 4: Read Flow — PreToolUse Masking
# =========================================================================
def test_read_flow():
    print("\n[4] Read Flow — PreToolUse Masking")

    # Create test file with secrets
    tmpdir = tempfile.mkdtemp()
    test_file = os.path.join(tmpdir, "test.env")
    with open(test_file, "w") as f:
        f.write("# Config\nDB=postgres://admin:secret@db:5432/app\n"
                "TOKEN=sk_live_abcdefghijklmnopqrstuv\nSAFE=hello\n")

    # Run PreToolUse hook with Read input
    stdout, _, code = run_hook("sensitive-data-mask.py", {
        "tool_name": "Read",
        "tool_input": {"file_path": test_file},
        "session_id": "test-read-flow",
    })

    assert_eq(code, 0, "Read hook exits 0")
    assert_true(len(stdout) > 0, "Read hook produces output")

    if stdout:
        output = json.loads(stdout)
        hook = output.get("hookSpecificOutput", {})
        assert_eq(hook.get("permissionDecision"), "allow", "Decision is allow")
        temp_path = hook.get("updatedInput", {}).get("file_path", "")
        assert_true(temp_path.startswith("/tmp/claude-masked"),
                    "Redirected to temp file")
        assert_in("[SECURITY]", hook.get("additionalContext", ""),
                  "Has security context message")

        # Verify temp file content is masked
        if os.path.isfile(temp_path):
            with open(temp_path) as f:
                content = f.read()
            assert_in("[MASKED_DB_URL]", content, "DB URL masked in temp")
            assert_in("[MASKED_STRIPE_KEY]", content,
                      "Stripe key masked in temp")
            assert_in("SAFE=hello", content,
                      "Safe value preserved in temp")

    # Test offset/limit passthrough
    stdout2, _, _ = run_hook("sensitive-data-mask.py", {
        "tool_name": "Read",
        "tool_input": {"file_path": test_file, "offset": 5, "limit": 10},
        "session_id": "test-read-flow",
    })
    if stdout2:
        out2 = json.loads(stdout2)
        upd = out2.get("hookSpecificOutput", {}).get("updatedInput", {})
        assert_eq(upd.get("offset"), 5, "Offset preserved in updatedInput")
        assert_eq(upd.get("limit"), 10, "Limit preserved in updatedInput")

    shutil.rmtree(tmpdir)
    # Clean up temp masked dir
    masked_dir = "/tmp/claude-masked-test-read-flow"
    if os.path.isdir(masked_dir):
        shutil.rmtree(masked_dir)


# =========================================================================
# Test 5: Bash Flow — Command Detection & Wrapping
# =========================================================================
def test_bash_flow():
    print("\n[5] Bash Flow — Command Detection & Wrapping")

    should_wrap = [
        "cat /etc/passwd",
        "head -20 config.yml",
        "tail -f /var/log/app.log",
        "grep -i password config.yml",
        "curl https://api.example.com/secrets",
        "printenv",
        "docker logs mycontainer",
        "kubectl logs pod/myapp",
        "pg_dump mydb",
        "env",
        "set",
    ]

    should_skip = [
        "npm run build",
        "git commit -m 'fix'",
        "python3 app.py",
        "ls -la",
        "mkdir /tmp/test",
        "echo hello",
    ]

    for cmd in should_wrap:
        stdout, _, code = run_hook("sensitive-data-mask.py", {
            "tool_name": "Bash",
            "tool_input": {"command": cmd},
            "session_id": "test-bash",
        })
        has_wrap = "mask-filter.py" in stdout if stdout else False
        assert_true(has_wrap, f"Wraps: {cmd}")

    for cmd in should_skip:
        stdout, _, code = run_hook("sensitive-data-mask.py", {
            "tool_name": "Bash",
            "tool_input": {"command": cmd},
            "session_id": "test-bash",
        })
        assert_true(not stdout, f"Skips: {cmd}")

    # Test double-wrap prevention
    stdout, _, _ = run_hook("sensitive-data-mask.py", {
        "tool_name": "Bash",
        "tool_input": {"command": "(cat file) 2>&1 | python3 mask-filter.py"},
        "session_id": "test-bash",
    })
    assert_true(not stdout, "No double-wrap")


# =========================================================================
# Test 6: Grep Flow — Content Mode Warning
# =========================================================================
def test_grep_flow():
    print("\n[6] Grep Flow — Content Mode Warning")

    stdout, _, _ = run_hook("sensitive-data-mask.py", {
        "tool_name": "Grep",
        "tool_input": {"pattern": "TODO", "output_mode": "content"},
        "session_id": "test-grep",
    })
    assert_true(stdout and "SECURITY" in stdout, "Grep content mode warning")

    stdout2, _, _ = run_hook("sensitive-data-mask.py", {
        "tool_name": "Grep",
        "tool_input": {"pattern": "TODO", "output_mode": "files_with_matches"},
        "session_id": "test-grep",
    })
    assert_true(not stdout2, "Grep files mode no warning")


# =========================================================================
# Test 7: PostToolUse Audit
# =========================================================================
def test_audit_flow():
    print("\n[7] PostToolUse Audit — Leak Detection")

    # Leaked secret in response
    stdout, _, _ = run_hook("sensitive-data-audit.py", {
        "tool_name": "Bash",
        "tool_response": "Connection: postgres://admin:s3cret@db:5432/app",
    })
    if stdout:
        out = json.loads(stdout)
        decision = out.get("hookSpecificOutput", {}).get("decision")
        assert_eq(decision, "block", "Audit blocks on leaked DB URL")
    else:
        fail("Audit blocks on leaked DB URL", "no output")

    # Nested dict response with secret
    stdout2, _, _ = run_hook("sensitive-data-audit.py", {
        "tool_name": "Read",
        "tool_response": {"content": 'api_key = "abcdefghijklmnop"'},
    })
    assert_true(stdout2 and "block" in stdout2, "Audit detects secret in dict")

    # Clean response
    stdout3, _, _ = run_hook("sensitive-data-audit.py", {
        "tool_name": "Bash",
        "tool_response": "Build successful. 42 tests passed.",
    })
    assert_true(not stdout3, "Audit passes clean response")


# =========================================================================
# Test 8: Pipe Filter
# =========================================================================
def test_pipe_filter():
    print("\n[8] Pipe Filter — stdin/stdout masking")

    # Content with secrets
    input_text = ("DB=postgres://admin:pw@host:5432/db\n"
                  "TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                  "eyJzdWIiOiIxIn0.abc123\nSAFE=hello world\n")

    result = subprocess.run(
        ["python3", os.path.join(HOOKS_DIR, "mask-filter.py")],
        input=input_text,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert_eq(result.returncode, 0, "Filter exits 0")
    assert_in("[MASKED_DB_URL]", result.stdout, "Filter masks DB URL")
    assert_in("[MASKED_JWT]", result.stdout, "Filter masks JWT")
    assert_in("SAFE=hello world", result.stdout, "Filter preserves safe text")

    # Empty input
    result2 = subprocess.run(
        ["python3", os.path.join(HOOKS_DIR, "mask-filter.py")],
        input="",
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert_eq(result2.returncode, 0, "Filter exits 0 on empty input")


# =========================================================================
# Test 9: File Classification & Edge Cases
# =========================================================================
def test_edge_cases():
    print("\n[9] Edge Cases — File Classification & Boundaries")
    import masking_engine

    masking_engine._config_cache = None
    masking_engine._patterns_cache = None
    config = masking_engine.load_config()

    # Skip patterns
    assert_true(masking_engine.should_skip_file("node_modules/pkg/index.js", config),
                "Skips node_modules")
    assert_true(masking_engine.should_skip_file(".git/objects/abc", config),
                "Skips .git")
    assert_true(masking_engine.should_skip_file("image.png", config),
                "Skips PNG")
    assert_true(not masking_engine.should_skip_file("src/app.py", config),
                "Allows app.py")

    # Always-mask patterns
    assert_true(masking_engine.should_always_mask(".env", config),
                "Always masks .env")
    assert_true(masking_engine.should_always_mask(".env.production", config),
                "Always masks .env.production")
    assert_true(masking_engine.should_always_mask("server.pem", config),
                "Always masks .pem")
    assert_true(masking_engine.should_always_mask("credentials.json", config),
                "Always masks *credentials*")
    assert_true(not masking_engine.should_always_mask("app.py", config),
                "Does not always-mask app.py")

    # Full content masking
    env_content = "# Comment\nKEY=value\nDB_HOST=localhost\n\nEMPTY_KEY=\n"
    masked, count = masking_engine.mask_full_content(env_content)
    assert_in("# Comment", masked, "Full mask preserves comments")
    assert_in("KEY= [MASKED_VALUE]", masked, "Full mask replaces values")
    assert_true(count >= 2, "Full mask counts replacements",
                f"count={count}")

    # Empty file
    masked_empty, count_empty = masking_engine.mask_content("", [])
    assert_eq(count_empty, 0, "Empty content returns 0")

    # Unicode content
    unicode_text = 'password = "p\u00e4ssw\u00f6rd"'
    config2 = masking_engine.load_config()
    patterns = masking_engine.compile_patterns(config2)
    masked_uni, count_uni = masking_engine.mask_content(unicode_text, patterns)
    assert_true(count_uni > 0, "Unicode password masked",
                f"count={count_uni}")

    # Large file skip (mock via config)
    tmpdir = tempfile.mkdtemp()
    large_file = os.path.join(tmpdir, "large.txt")
    with open(large_file, "w") as f:
        f.write("x" * 100)  # Small file
    mock_config = dict(config)
    mock_config["max_file_size"] = 50  # Set tiny limit
    assert_true(masking_engine.should_skip_file(large_file, mock_config),
                "Skips file exceeding max_file_size")
    shutil.rmtree(tmpdir)


# =========================================================================
# Test 10: Settings.json Integrity
# =========================================================================
def test_hooks_json_integrity():
    print("\n[10] hooks.json — Plugin Hook Registration Integrity")

    hooks_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "hooks", "hooks.json"
    )
    with open(hooks_path) as f:
        data = json.load(f)

    hooks = data.get("hooks", {})

    # PreToolUse has masking hook
    pre = hooks.get("PreToolUse", [])
    mask_entry = [e for e in pre
                  if "sensitive-data-mask.py" in str(e)]
    assert_true(len(mask_entry) > 0, "PreToolUse has sensitive-data-mask")

    # PreToolUse has secret-scanner
    scanner_entry = [e for e in pre
                     if "secret-scanner.py" in str(e)]
    assert_true(len(scanner_entry) > 0, "PreToolUse has secret-scanner")

    # PostToolUse has audit hook
    post = hooks.get("PostToolUse", [])
    audit_entry = [e for e in post
                   if "sensitive-data-audit.py" in str(e)]
    assert_true(len(audit_entry) > 0, "PostToolUse has sensitive-data-audit")

    # SessionEnd has cleanup
    session = hooks.get("SessionEnd", [])
    cleanup = [e for e in session
               if "claude-masked" in str(e)]
    assert_true(len(cleanup) > 0, "SessionEnd has temp cleanup")

    # All commands use ${CLAUDE_PLUGIN_ROOT}
    hooks_str = json.dumps(data)
    assert_true("${CLAUDE_PLUGIN_ROOT}" in hooks_str,
                "Commands use ${CLAUDE_PLUGIN_ROOT}")
    assert_true("~/.claude/hooks" not in hooks_str,
                "No hardcoded ~/.claude/hooks paths")


# =========================================================================
# Main
# =========================================================================
def main():
    print("=" * 60)
    print("Sensitive Data Masking Hook — Test Suite")
    print("=" * 60)

    test_pattern_true_positives()
    test_pattern_false_positives()
    test_config_loading()
    test_read_flow()
    test_bash_flow()
    test_grep_flow()
    test_audit_flow()
    test_pipe_filter()
    test_edge_cases()
    test_hooks_json_integrity()

    print("\n" + "=" * 60)
    total = _pass + _fail
    print(f"Results: {_pass}/{total} passed, {_fail} failed")
    if _fail == 0:
        print("ALL TESTS PASSED")
    else:
        print(f"FAILURES: {_fail}")
    print("=" * 60)

    sys.exit(0 if _fail == 0 else 1)


if __name__ == "__main__":
    main()
