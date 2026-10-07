"""Check that the quality gate rejects known bad examples without executing them."""
from pathlib import Path
import json
import os
import subprocess
import sys

import pytest

from harness import check_harness as harness


@pytest.mark.parametrize('source,rule', [
    ('cursor.execute(f"SELECT * FROM todos WHERE title = {value}")', 'CWE-89'),
    ('query = f"DELETE FROM todos WHERE id = {value}"', 'CWE-89'),
    ('query = "SELECT * FROM todos WHERE id = " + value', 'CWE-89'),
    ('query = "UPDATE todos SET title = %s" % value', 'CWE-89'),
    ('query = "INSERT INTO todos VALUES ({})".format(value)', 'CWE-89'),
    ('ADMIN_TOKEN = "example-only"', 'CWE-798'),
    ('ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "example-only")', 'CWE-798'),
    ('ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", default="example-only")', 'CWE-798'),
    ('import hashlib\nhashlib.md5(value)', 'CWE-327'),
    ('try:\n    run()\nexcept:\n    pass', 'Silent Failure'),
])
def test_known_bad_patterns_are_rejected(tmp_path, monkeypatch, source, rule):
    monkeypatch.chdir(tmp_path)
    (tmp_path / 'main.py').write_text(source, encoding='utf-8')
    findings = harness.stage1_security_audit()
    assert any(rule in finding['rule'] for finding in findings), findings


def test_bound_sql_and_environment_secret_pass(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / 'main.py').write_text(
        'ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")\n'
        'cursor.execute("SELECT * FROM todos WHERE id = ?", (value,))\n',
        encoding='utf-8',
    )
    assert harness.stage1_security_audit() == []


def test_folder_name_containing_test_is_still_scanned(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    folder = tmp_path / 'latest'
    folder.mkdir()
    (folder / 'api.py').write_text('import hashlib\nhashlib.md5(value)', encoding='utf-8')
    assert harness.stage1_security_audit()


def test_unreadable_source_fails_instead_of_silently_skipping(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / 'main.py').write_bytes(b'\xff\xfe\x00')
    assert harness.stage1_security_audit()


@pytest.mark.parametrize('empty_dir', [False, True])
def test_missing_tests_fail_the_gate(tmp_path, monkeypatch, empty_dir):
    monkeypatch.chdir(tmp_path)
    if empty_dir:
        (tmp_path / 'tests').mkdir()
    assert harness.stage2_unit_tests()


def test_failing_pytest_output_is_reported(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    folder = tmp_path / 'tests'; folder.mkdir()
    (folder / 'test_example.py').write_text('def test_example(): assert False', encoding='utf-8')
    monkeypatch.setattr(subprocess, 'run', lambda *a, **kw: subprocess.CompletedProcess(a, 1, 'FAILED example', ''))
    assert 'FAILED example' in harness.stage2_unit_tests()[0]['message']


def test_wal_comment_is_not_an_executed_setting(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / 'main.py').write_text('# PRAGMA journal_mode=WAL\n', encoding='utf-8')
    assert harness.stage3_performance_benchmark()


def test_invalid_python_syntax_is_reported(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / 'main.py').write_text('def incomplete(', encoding='utf-8')
    assert harness.stage1_security_audit()[0]['rule'] == 'Source Parse Error'


def test_comments_are_not_executed_code(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / 'main.py').write_text('# hashlib.md5(value)\npass\n', encoding='utf-8')
    assert harness.stage1_security_audit() == []


def test_security_cli_rejects_then_accepts_corrected_example(tmp_path):
    script = Path(harness.__file__).resolve()
    example = tmp_path / 'main.py'
    example.write_text('ADMIN_TOKEN = "example-not-real-secret"\n', encoding='utf-8')
    command = [sys.executable, str(script), '--security-only']
    options = dict(cwd=tmp_path, env={**os.environ, 'PYTHONUTF8': '1'},
                   capture_output=True, text=True, encoding='utf-8', timeout=30)
    bad = subprocess.run(command, **options)
    report_path = tmp_path / 'harness_report.json'
    bad_report = json.loads(report_path.read_text(encoding='utf-8'))
    assert bad.returncode == 1 and bad_report['status'] == 'REJECTED'
    assert 'example-not-real-secret' not in bad.stdout + report_path.read_text(encoding='utf-8')
    example.write_text('import os\nADMIN_TOKEN = os.getenv("ADMIN_TOKEN")\n', encoding='utf-8')
    good = subprocess.run(command, **options)
    assert good.returncode == 0
    assert json.loads(report_path.read_text(encoding='utf-8'))['status'] == 'APPROVED'
