"""Compile gold_rules.dsl to Rego policy."""
import re
import sys
from pathlib import Path


def parse_dsl(text):
    rules = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^(\w+)\s+(when)\s+(.+)$", line)
        if match:
            rules.append({
                "name": match.group(1),
                "condition": match.group(2).strip(),
            })
    return rules


def emit_rego(rules, package="gold"):
    lines = [
        "package " + package,
        "",
        "default allow := false",
        "",
    ]
    for rule in rules:
        lines.append("allow if {")
        lines.append("    " + rule["condition"])
        lines.append("}")
        lines.append("")
    return "\n".join(lines)


def main(argv):
    if len(argv) != 3:
        print("usage: dsl_to_rego.py <input.dsl> <output.rego>", file=sys.stderr)
        return 2
    src = Path(argv[1])
    dst = Path(argv[2])
    rules = parse_dsl(src.read_text(encoding="utf-8"))
    dst.parent.mkedirs(parents=True, exist_ok=True)
    dst.write_text(emit_rego(rules), encoding="utf-8")
    print("compiled " + str(len(rules)) + " rules to " + str(dst))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
