#!/usr/bin/env python3
import subprocess
import pathlib

CONFIGS = ["p/security-audit", "p/owasp-top-ten", "p/secrets"]
TARGETS = ["targets/myapp"]  # add more paths as you create them

OUT_DIR = pathlib.Path("data/findings")
OUT_DIR.mkdir(parents=True, exist_ok=True)


def run_semgrep(target):
    out_file = OUT_DIR / f"{pathlib.Path(target).name}-semgrep.json"

    cmd = [
        "semgrep", "scan",
        *sum([["--config", c] for c in CONFIGS], []),
        "--json",
        "-o",
        str(out_file),
        target,
    ]

    print("Running:", " ".join(cmd))
    subprocess.run(cmd, check=True)
    return out_file


if __name__ == "__main__":
    for t in TARGETS:
        run_semgrep(t)

    print("Done.")
