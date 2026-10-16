import re, json, sys
TOKEN = re.compile(r'rule\s+"([^"]+)"\s*\{(.*?)\}', re.S)
def parse(t):
    rules = []
    for m in TOKEN.finditer(t):
        name, body = m.group(1), m.group(2)
        conds = [c.group(1).strip() for c in re.finditer(r'(?:when|and)\s+([^\n]+)', body)]
        rules.append({"name": name, "conditions": conds})
    return rules

def compile_rego(rules):
    out = ["package viper.gold", "", "all_gates_pass {", "  every g in input.gates { g == \"PASS\" }", "}", ""]
    for r in rules:
        rn = r["name"].replace("-", "_")
        out.append(rn + " {")
        for c in r["conditions"]:
            c = c.replace("evidence.", "input.evidence.").replace("score.", "input.score.")
            c = c.replace("all gates == PASS", "all_gates_pass")
            out.append("  " + c)
        out.append("}")
    return "\n".join(out)

if __name__ == "__main__":
    rules = parse(open(sys.argv[1]).read())
    open(sys.argv[2], "w").write(compile_rego(rules))
    print(json.dumps({"rules_parsed": len(rules)}))
