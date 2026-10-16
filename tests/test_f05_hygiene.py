from pathlib import Path

def test_gitignore():
    gi = Path(".gitignore").read_text()
    for p in ["*.pem", "*.key", "__pycache__/", "*.py[cod]", ".env"]:
        assert p in gi

def test_no_pyc_tracked():
    assert not [p for p in Path(".").rglob("*.pyc") if "__pycache__" not in p.parts]
