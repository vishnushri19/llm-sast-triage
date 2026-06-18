#!/usr/bin/env python3
import json
import subprocess
import pathlib

MODEL = "llama3"
MAX_RESULTS = 20

PROMPT_FILE = pathlib.Path("prompts/triage_prompt.txt")
FINDINGS_DIR = pathlib.Path("data/findings")
RANKINGS_DIR = pathlib.Path("data/rankings")
RANKINGS_DIR.mkdir(parents=True, exist_ok=True)


def load_prompt():
    return PROMPT_FILE.read_text()


def process_file(fpath):
    data = json.load(open(fpath))
    results = data.get("results", [])[:MAX_RESULTS]

    prompt_template = load_prompt()
    prompt = prompt_template.replace(
        "{{FINDINGS_JSON}}",
        json.dumps(results, indent=2)
    )

    return results, prompt


def call_ollama(prompt):
    cmd = ["ollama", "run", MODEL]
    out = subprocess.run(
        cmd,
        input=prompt.encode(),
        check=True,
        capture_output=True
    )
    return out.stdout.decode()


if __name__ == "__main__":
    for f in FINDINGS_DIR.glob("*-semgrep.json"):
        results, prompt = process_file(f)

        if not results:
            print(f"{f.name}: no findings.")
            continue

        print(f"{f.name}: sending to LLM...")
        resp = call_ollama(prompt)

        out_file = RANKINGS_DIR / f"{f.stem}-llm.txt"
        out_file.write_text(resp)

        print(f"Wrote LLM output to {out_file}")
