from pathlib import Path

def test_default_deny():
    assert "default allow := false" in Path("rego/gold_rules.rego").read_text()
