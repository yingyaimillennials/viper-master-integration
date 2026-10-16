import sys, zipfile, hashlib, os

src, dst = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as z:
    for root, dirs, fs in os.walk(src):
        dirs[:] = [d for d in dirs if d not in ("__pycache__", ".pytest_cache", "dist")]
        for f in fs:
            if f.endswith((".pyc", ".pyo")):
                continue
            p = os.path.join(root, f)
            z.write(p, os.path.relpath(p, src))
print("sha256:", hashlib.sha256(open(dst, "rb").read()).hexdigest())
