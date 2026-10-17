"""Unified test runner — runs tests/ directory via pytest."""
import subprocess
import sys
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "tests/"],
        cwd=root,
    )
    if result.returncode == 0:
        print("ALL_SECURITY_TESTS_PASSED")
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
