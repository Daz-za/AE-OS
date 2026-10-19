"""The shared test vectors must match what this implementation produces today."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_vectors_are_up_to_date():
    run = subprocess.run([sys.executable, str(ROOT / "testvectors" / "generate.py"), "--check"],
                         capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
