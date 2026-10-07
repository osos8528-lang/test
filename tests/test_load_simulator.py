"""Exercise the real CLI and ensure failed writes release their DB handles."""
import os
from pathlib import Path
import subprocess
import sys


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
