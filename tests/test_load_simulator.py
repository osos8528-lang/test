"""Exercise the real CLI and ensure failed writes release their DB handles."""
import os
from pathlib import Path
import subprocess
import sys
import urllib.error

import pytest
from harness import simulate_load


def test_standalone_comparison_cleans_up_after_lock_failures(tmp_path):
    script = Path(__file__).resolve().parents[1] / 'harness' / 'simulate_load.py'
    env = os.environ.copy()
    env.update(PYTHONUTF8='1', TEMP=str(tmp_path), TMP=str(tmp_path))
    result = subprocess.run(
        [sys.executable, str(script), '--requests', '100', '--concurrency', '20'],
        cwd=tmp_path, env=env, capture_output=True, text=True, encoding='utf-8', timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert '[Step 1]' in result.stdout and '[Step 2]' in result.stdout
    assert not list(tmp_path.glob('campus_load_*.db*'))


@pytest.mark.parametrize('flag,value', [('--requests', '0'), ('--requests', '-1'), ('--concurrency', '0')])
def test_invalid_load_arguments_are_rejected(flag, value, monkeypatch):
    monkeypatch.setattr(sys, 'argv', ['simulate_load.py', flag, value])
    with pytest.raises(SystemExit) as exc:
        simulate_load.main()
    assert exc.value.code == 2


def test_failed_http_load_returns_failure_exit_code(monkeypatch):
    monkeypatch.setattr(sys, 'argv', ['simulate_load.py', '--url', 'http://localhost/todos', '--requests', '2'])
    def unavailable(*args, **kwargs):
        raise urllib.error.URLError('test-only simulated refusal')
    monkeypatch.setattr(simulate_load.urllib.request, 'urlopen', unavailable)
    assert simulate_load.main() == 1


def test_successful_http_load_returns_success_exit_code(monkeypatch):
    monkeypatch.setattr(sys, 'argv', ['simulate_load.py', '--url', 'http://localhost/todos', '--requests', '2'])
    class Created:
        status = 201
        def __enter__(self): return self
        def __exit__(self, *args): return False
    monkeypatch.setattr(simulate_load.urllib.request, 'urlopen', lambda *a, **kw: Created())
    assert simulate_load.main() == 0
