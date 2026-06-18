#!/usr/bin/env python3
import json
import os
import pathlib
import requests
import sys
from collections import defaultdict

MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")
MAX_RESULTS = int(os.environ.get("MAX_RESULTS", "50"))

FINDINGS_DIR = pathlib.Path("data/findings")
RANKINGS_DIR = pathlib.Path("data/rankings")
RANKINGS_DIR.mkdir(parents=True, exist_ok=True)

OLLAMA_URL = "http://localhost:11434/api/generate"


SEVERITY_RANK = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
}


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def first_nonempty(values, default=None):
    for v in values:
        if v:
            return v
    return default


def get_metadata(result):
    return result.get("extra", {}).get("metadata", {}) or {}


def get_message(result):
    return result.get("extra", {}).get("message", "") or ""


def get_code_line(result):
    return result.get("extra", {}).get("lines", "") or ""


def get_line(result):
    return result.get("start", {}).get("line")


def get_vulnerability_class(result):
    metadata = get_metadata(result)
    values = metadata.get("vulnerability_class", [])
    if isinstance(values, list) and values:
        return values[0]
    if isinstance(values, str):
        return values
    return None


def get_cwe(result):
    metadata = get_metadata(result)
    values = metadata.get("cwe", [])
    if isinstance(values, list) and values:
        return values[0]
    if isinstance(values, str):
        return values
    return None


def practical_severity(result):
    """
    Convert Semgrep metadata into a practical triage severity.
    This is intentionally simple and deterministic.
    """
    metadata = get_metadata(result)

    text = " ".join([
        result.get("check_id", ""),
        get_message(result),
        get_code_line(result),
        str(metadata.get("impact", "")),
        str(metadata.get("likelihood", "")),
        str(metadata.get("confidence", "")),
        " ".join(metadata.get("cwe", []) if isinstance(metadata.get("cwe", []), list) else []),
        " ".join(metadata.get("vulnerability_class", []) if isinstance(metadata.get("vulnerability_class", []), list) else []),
    ]).lower()

    impact = str(metadata.get("impact", "")).lower()
    likelihood = str(metadata.get("likelihood", "")).lower()
    semgrep_sev = str(result.get("severity", "")).upper()

    if "command injection" in text or "cwe-78" in text:
        if "user" in text or "request.args" in text or "shell=true" in text:
            return "High"

    if impact == "high" and likelihood in {"high", "medium"}:
        return "High"

    if semgrep_sev == "ERROR":
        return "Medium"

    if semgrep_sev == "WARNING":
        return "Medium"

    return "Low"


def cluster_name(result):
    vuln_class = get_vulnerability_class(result)
    if vuln_class:
        return vuln_class

    cwe = get_cwe(result)
    if cwe:
        if "CWE-78" in cwe:
            return "Command Injection"
        return cwe

    check_id = result.get("check_id", "")
    if "subprocess" in check_id:
        return "Command Injection"

    return "Security Finding"


def cluster_key(result):
    """
    Group findings pointing to the same underlying issue.
    For this prototype, same file + same line + same vulnerability class/CWE
    is treated as the same vulnerability cluster.
    """
    path = result.get("path", "unknown")
    line = get_line(result)
    vuln = first_nonempty([
        get_vulnerability_class(result),
        get_cwe(result),
        cluster_name(result),
    ], "unknown")

    return f"{path}:{line}:{vuln}"


def simplify_finding(result):
    metadata = get_metadata(result)

    return {
        "check_id": result.get("check_id"),
        "path": result.get("path"),
        "line": get_line(result),
        "severity": result.get("severity"),
        "message": get_message(result),
        "code": get_code_line(result),
        "cwe": metadata.get("cwe", []),
        "owasp": metadata.get("owasp", []),
        "vulnerability_class": metadata.get("vulnerability_class", []),
        "confidence": metadata.get("confidence"),
        "impact": metadata.get("impact"),
        "likelihood": metadata.get("likelihood"),
    }


def build_clusters(results):
    grouped = defaultdict(list)

    for result in results:
        grouped[cluster_key(result)].append(result)

    clusters = []

    for _, items in grouped.items():
        severities = [practical_severity(r) for r in items]
        highest_severity = max(severities, key=lambda s: SEVERITY_RANK[s])

        check_ids = sorted({r.get("check_id") for r in items if r.get("check_id")})
        files = sorted({
            f"{r.get('path')}:{get_line(r)}"
            for r in items
            if r.get("path") and get_line(r)
        })

        name = cluster_name(items[0])

        clusters.append({
            "severity": highest_severity,
            "cluster": name,
            "check_ids": check_ids,
            "files": files,
            "findings": [simplify_finding(r) for r in items],
        })

    clusters.sort(key=lambda c: SEVERITY_RANK[c["severity"]], reverse=True)
    return clusters


def fallback_enrichment(cluster):
    name = cluster["cluster"].lower()

    if "command injection" in name:
        return {
            "impact": (
                "User-controlled input reaches a subprocess call, which can allow an attacker to execute arbitrary operating-system commands. "
                "If exploited, this can lead to server compromise, data exposure, malware execution, or lateral movement."
            ),
            "minimal_safe_fix": (
                "Avoid shell=True and pass arguments as a list, for example subprocess.check_output(['ping', '-c', '1', host], shell=False). "
                "Validate the host value with an allowlist or strict IP/hostname parser before passing it to subprocess."
            ),
            "likely_false_positive": "No",
            "false_positive_reason": (
                "Multiple Semgrep rules point to the same line where request input flows into subprocess execution."
            ),
        }

    return {
        "impact": (
            "This finding may expose the application to a security weakness depending on runtime reachability and input control. "
            "Review the affected code path to determine whether untrusted data can influence the vulnerable operation."
        ),
        "minimal_safe_fix": (
            "Apply the safest API or framework-specific mitigation and add a regression test for the vulnerable pattern."
        ),
        "likely_false_positive": "Unclear",
        "false_positive_reason": (
            "The available static finding does not provide enough context to fully confirm exploitability."
        ),
    }


def call_ollama_for_enrichment(cluster):
    """
    Ask the LLM only for explanatory text.
    Do not allow it to decide check IDs, files, lines, or severity.
    """
    prompt = f"""
You are a concise application security triage assistant.

Return only valid JSON with this exact object shape:
{{
  "impact": "Exactly two sentences explaining practical exploit impact.",
  "minimal_safe_fix": "Specific minimal safe fix guidance.",
  "likely_false_positive": "Yes|No|Unclear",
  "false_positive_reason": "One sentence explaining the false-positive decision."
}}

Do not include markdown.
Do not include check IDs.
Do not include files.
Do not include severity.
Do not add extra keys.

Cluster:
{json.dumps(cluster, indent=2)}
""".strip()

    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0
        }
    }

    try:
        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=300
        )
        response.raise_for_status()

        text = response.json().get("response", "")
        parsed = json.loads(text)

        required = {
            "impact",
            "minimal_safe_fix",
            "likely_false_positive",
            "false_positive_reason",
        }

        if not isinstance(parsed, dict):
            raise ValueError("LLM did not return a JSON object")

        if not required.issubset(parsed.keys()):
            raise ValueError("LLM response missing required keys")

        if parsed["likely_false_positive"] not in {"Yes", "No", "Unclear"}:
            parsed["likely_false_positive"] = "Unclear"

        return {
            "impact": str(parsed.get("impact", "")).strip(),
            "minimal_safe_fix": str(parsed.get("minimal_safe_fix", "")).strip(),
            "likely_false_positive": parsed["likely_false_positive"],
            "false_positive_reason": str(parsed.get("false_positive_reason", "")).strip(),
        }

    except Exception as e:
        print(f"LLM enrichment failed, using fallback: {e}")
        return fallback_enrichment(cluster)


def validate_output(raw_results, final_clusters):
    expected_ids = {r.get("check_id") for r in raw_results if r.get("check_id")}
    actual_ids = set()

    for cluster in final_clusters:
        for cid in cluster.get("check_ids", []):
            actual_ids.add(cid)

    missing = expected_ids - actual_ids
    extra = actual_ids - expected_ids

    if missing or extra:
        print("Validation failed.")
        if missing:
            print("Missing check IDs:")
            for cid in sorted(missing):
                print(f"- {cid}")
        if extra:
            print("Extra check IDs:")
            for cid in sorted(extra):
                print(f"- {cid}")
        return False

    print("Validation passed.")
    print(f"Covered check IDs: {len(actual_ids)}")
    return True


def process_semgrep_file(fpath):
    data = load_json(fpath)
    raw_results = data.get("results", [])[:MAX_RESULTS]

    if not raw_results:
        return []

    clusters = build_clusters(raw_results)
    final_clusters = []

    for cluster in clusters:
        enrichment = call_ollama_for_enrichment(cluster)

        final_clusters.append({
            "severity": cluster["severity"],
            "cluster": cluster["cluster"],
            "check_ids": cluster["check_ids"],
            "files": cluster["files"],
            "impact": enrichment["impact"],
            "minimal_safe_fix": enrichment["minimal_safe_fix"],
            "likely_false_positive": enrichment["likely_false_positive"],
            "false_positive_reason": enrichment["false_positive_reason"],
        })

    if not validate_output(raw_results, final_clusters):
        sys.exit(2)

    return final_clusters


if __name__ == "__main__":
    files = list(FINDINGS_DIR.glob("*-semgrep.json"))

    if not files:
        print("No Semgrep JSON files found in data/findings.")
        sys.exit(1)

    for f in files:
        print(f"{f.name}: processing...")

        output = process_semgrep_file(f)

        if not output:
            print(f"{f.name}: no findings.")
            continue

        out_file = RANKINGS_DIR / f"{f.stem}-llm.json"
        write_json(out_file, output)

        print(f"Wrote validated LLM triage output to {out_file}")