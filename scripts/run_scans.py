#!/usr/bin/env python3
import pathlib
import platform
import shutil
import subprocess
import sys

CONFIGS = ["p/security-audit", "p/owasp-top-ten", "p/secrets"]
TARGETS = ["examples/myapp", "examples/safeapp", "examples/evalapp", "examples/safeevalapp", "examples/sqlapp", "examples/pathapp", "examples/ssrfapp", "examples/yamlapp", "examples/pickleapp", "examples/redirectapp"]

OUT_DIR = pathlib.Path("data/findings")
OUT_DIR.mkdir(parents=True, exist_ok=True)


def run_cmd(cmd):
    print("Running:", " ".join(cmd))
    subprocess.run(cmd, check=True)


def docker_available():
    return shutil.which("docker") is not None


def semgrep_available():
    return shutil.which("semgrep") is not None


def run_semgrep_native(target, out_file):
    cmd = [
        "semgrep",
        "scan",
        "--no-git-ignore",
        *sum([["--config", c] for c in CONFIGS], []),
        "--json",
        "-o",
        str(out_file),
        target,
    ]
    run_cmd(cmd)


def run_semgrep_docker(target, out_file):
    cwd = pathlib.Path.cwd()

    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{cwd}:/src",
        "-w",
        "/src",
        "semgrep/semgrep:1.82.0",
        "semgrep",
        "scan",
        "--no-git-ignore",
        *sum([["--config", c] for c in CONFIGS], []),
        "--json",
        "-o",
        str(out_file).replace("\\", "/"),
        target.replace("\\", "/"),
    ]
    run_cmd(cmd)


def run_semgrep(target):
    target_path = pathlib.Path(target)

    if not target_path.exists():
        print(f"Target does not exist: {target}")
        sys.exit(1)

    out_file = OUT_DIR / f"{target_path.name}-semgrep.json"

    if platform.system() == "Windows":
        if not docker_available():
            print("Docker is required for Semgrep on this Windows setup.")
            sys.exit(1)
        run_semgrep_docker(target, out_file)
    else:
        if semgrep_available():
            run_semgrep_native(target, out_file)
        elif docker_available():
            run_semgrep_docker(target, out_file)
        else:
            print("Neither Semgrep nor Docker is available.")
            sys.exit(1)

    return out_file


if __name__ == "__main__":
    for t in TARGETS:
        run_semgrep(t)

    print("Done.")