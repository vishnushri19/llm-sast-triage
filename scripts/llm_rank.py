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


def get_extra(result):
    return result.get("extra", {}) or {}


def get_metadata(result):
    return get_extra(result).get("metadata", {}) or {}


def get_message(result):
    return get_extra(result).get("message", "") or ""


def get_code_line(result):
    return get_extra(result).get("lines", "") or ""


def get_line(result):
    return result.get("start", {}).get("line")


def get_check_id(result):
    return result.get("check_id", "") or ""


def get_vulnerability_classes(result):
    values = get_metadata(result).get("vulnerability_class", [])
    if isinstance(values, list):
        return values
    if isinstance(values, str):
        return [values]
    return []


def get_cwes(result):
    values = get_metadata(result).get("cwe", [])
    if isinstance(values, list):
        return values
    if isinstance(values, str):
        return [values]
    return []


def contains_sql_injection_signal(result):
    text = json.dumps({
        "check_id": get_check_id(result),
        "message": get_message(result),
        "code": get_code_line(result),
        "cwe": get_cwes(result),
        "vulnerability_class": get_vulnerability_classes(result),
    }).lower()

    return (
        "sql injection" in text
        or "tainted-sql-string" in text
        or "manually construct a sql string" in text
        or ("cursor.execute" in text and "select" in text)
    )


def contains_code_injection_signal(result):
    text = json.dumps({
        "check_id": get_check_id(result),
        "message": get_message(result),
        "code": get_code_line(result),
        "cwe": get_cwes(result),
        "vulnerability_class": get_vulnerability_classes(result),
    }).lower()

    return (
        "code injection" in text
        or "eval" in text
        or "user-eval" in text
        or "eval-injection" in text
        or "eval-detected" in text
    )


def contains_command_injection_signal(result):
    text = json.dumps({
        "check_id": get_check_id(result),
        "message": get_message(result),
        "code": get_code_line(result),
        "cwe": get_cwes(result),
        "vulnerability_class": get_vulnerability_classes(result),
    }).lower()

    return (
        "command injection" in text
        or "cwe-78" in text
        or "subprocess" in text
    )



def signal_text(result):
    return json.dumps({
        "check_id": get_check_id(result),
        "message": get_message(result),
        "code": get_code_line(result),
        "cwe": get_cwes(result),
        "vulnerability_class": get_vulnerability_classes(result),
    }).lower()


def contains_path_traversal_signal(result):
    text = signal_text(result)
    return "path traversal" in text or "path-traversal" in text or "path_traversal" in text


def contains_ssrf_signal(result):
    text = signal_text(result)
    return "ssrf" in text or "server-side request forgery" in text


def contains_insecure_transport_signal(result):
    text = signal_text(result)
    return "insecure-transport" in text or "request-with-http" in text or "http://" in text


def contains_yaml_deserialization_signal(result):
    text = signal_text(result)
    return "pyyaml" in text or "yaml.load" in text or "avoid-pyyaml-load" in text


def contains_pickle_deserialization_signal(result):
    text = signal_text(result)
    return "pickle.loads" in text or "avoid-pickle" in text or "pickle deserialization" in text

def is_shell_true_only_signal(result):
    text = " ".join([
        get_check_id(result),
        get_message(result),
        get_code_line(result),
    ]).lower()

    return "shell-true" in text or "shell=true" in text


def has_user_controlled_source(result):
    """
    Detect whether Semgrep reported actual user-controlled flow.
    We intentionally avoid treating every shell=True finding as exploitable.
    """
    extra = get_extra(result)
    trace_text = json.dumps(extra.get("dataflow_trace", {})).lower()

    text = " ".join([
        get_check_id(result),
        get_message(result),
        get_code_line(result),
        trace_text,
    ]).lower()

    user_source_markers = [
        "user controlled",
        "user-controlled",
        "user input",
        "request.args",
        "request.form",
        "request.json",
        "request.get_json",
        "request.data",
        "request.values",
        "request.files",
        "request.cookies",
        "flask",
        "sys.argv",
        "input(",
        "taint_source",
    ]

    return any(marker in text for marker in user_source_markers)


def cluster_name_for_items(items):
    any_user_controlled = any(has_user_controlled_source(r) for r in items)
    any_command_injection = any(contains_command_injection_signal(r) for r in items)
    any_shell_true = any(is_shell_true_only_signal(r) for r in items)

    if any_user_controlled and any(contains_path_traversal_signal(r) for r in items):
        return "Path Traversal"

    if any(contains_path_traversal_signal(r) for r in items):
        return "Path Traversal Hardening"

    if any_user_controlled and any(contains_ssrf_signal(r) for r in items):
        return "SSRF"

    if any(contains_ssrf_signal(r) for r in items):
        return "SSRF Hardening"

    if any(contains_insecure_transport_signal(r) for r in items):
        return "Insecure Transport"

    if any_user_controlled and any(contains_yaml_deserialization_signal(r) for r in items):
        return "Unsafe YAML Deserialization"

    if any(contains_yaml_deserialization_signal(r) for r in items):
        return "YAML Deserialization Hardening"

    if any_user_controlled and any(contains_pickle_deserialization_signal(r) for r in items):
        return "Unsafe Pickle Deserialization"

    if any(contains_pickle_deserialization_signal(r) for r in items):
        return "Pickle Deserialization Hardening"

    if any(has_user_controlled_source(r) and contains_sql_injection_signal(r) for r in items):
        return "SQL Injection"

    if any(contains_sql_injection_signal(r) for r in items):
        return "SQL Query Hardening"

    if any(has_user_controlled_source(r) and contains_code_injection_signal(r) for r in items):
        return "Code Injection"

    if any(contains_code_injection_signal(r) for r in items):
        return "Eval Usage Hardening"

    if any_user_controlled and any_command_injection:
        return "Command Injection"

    if any_shell_true and not any_user_controlled:
        return "Shell=True Subprocess Hardening"

    for r in items:
        vuln_classes = get_vulnerability_classes(r)
        if vuln_classes:
            return vuln_classes[0]

    for r in items:
        cwes = get_cwes(r)
        if cwes:
            return cwes[0]

    return "Security Finding"

def practical_severity_for_items(items):
    any_user_controlled = any(has_user_controlled_source(r) for r in items)
    any_command_injection = any(contains_command_injection_signal(r) for r in items)
    any_shell_true = any(is_shell_true_only_signal(r) for r in items)

    if any_user_controlled and any(contains_path_traversal_signal(r) for r in items):
        return "High"

    if any(contains_path_traversal_signal(r) for r in items):
        return "Low"

    if any_user_controlled and any(contains_ssrf_signal(r) for r in items):
        return "High"

    if any(contains_ssrf_signal(r) for r in items):
        return "Low"

    if any(contains_insecure_transport_signal(r) for r in items):
        return "Low"

    if any_user_controlled and any(contains_yaml_deserialization_signal(r) for r in items):
        return "High"

    if any(contains_yaml_deserialization_signal(r) for r in items):
        return "Low"

    if any_user_controlled and any(contains_pickle_deserialization_signal(r) for r in items):
        return "High"

    if any(contains_pickle_deserialization_signal(r) for r in items):
        return "Low"

    if any(has_user_controlled_source(r) and contains_sql_injection_signal(r) for r in items):
        return "High"

    if any(contains_sql_injection_signal(r) for r in items):
        return "Low"

    if any(has_user_controlled_source(r) and contains_code_injection_signal(r) for r in items):
        return "High"

    if any(contains_code_injection_signal(r) for r in items):
        return "Low"

    if any_user_controlled and any_command_injection:
        return "High"

    if any_shell_true and not any_user_controlled:
        return "Low"

    semgrep_severities = {str(r.get("severity", "")).upper() for r in items}

    if "ERROR" in semgrep_severities:
        return "Medium"

    if "WARNING" in semgrep_severities:
        return "Medium"

    return "Low"

def false_positive_decision_for_items(items):
    any_user_controlled = any(has_user_controlled_source(r) for r in items)
    any_command_injection = any(contains_command_injection_signal(r) for r in items)
    any_shell_true = any(is_shell_true_only_signal(r) for r in items)

    if any_user_controlled and any(contains_path_traversal_signal(r) for r in items):
        return ("No", "Semgrep reports user-controlled input reaching a file path used for file access.")

    if any(contains_path_traversal_signal(r) for r in items):
        return ("Yes", "Semgrep reports file path access, but no user-controlled input is shown reaching the file operation.")

    if any_user_controlled and any(contains_ssrf_signal(r) for r in items):
        return ("No", "Semgrep reports user-controlled input reaching an outbound HTTP request.")

    if any(contains_ssrf_signal(r) for r in items):
        return ("Yes", "Semgrep reports an outbound request pattern, but no user-controlled input is shown reaching the request target.")

    if any(contains_insecure_transport_signal(r) for r in items):
        return ("No", "Semgrep reports use of insecure HTTP transport on the affected outbound request.")

    if any_user_controlled and any(contains_yaml_deserialization_signal(r) for r in items):
        return ("No", "Semgrep reports user-controlled input reaching unsafe YAML deserialization.")

    if any(contains_yaml_deserialization_signal(r) for r in items):
        return ("Yes", "Semgrep reports unsafe YAML deserialization, but no user-controlled input is shown reaching the parser.")

    if any_user_controlled and any(contains_pickle_deserialization_signal(r) for r in items):
        return ("No", "Semgrep reports user-controlled input reaching unsafe pickle deserialization.")

    if any(contains_pickle_deserialization_signal(r) for r in items):
        return ("Yes", "Semgrep reports unsafe pickle deserialization, but no user-controlled input is shown reaching pickle.loads.")

    if any(has_user_controlled_source(r) and contains_sql_injection_signal(r) for r in items):
        return ("No", "Semgrep reports user-controlled input reaching SQL query construction/execution.")

    if any(contains_sql_injection_signal(r) for r in items):
        return ("Yes", "Semgrep reports SQL query construction, but no user-controlled input is shown reaching the query.")

    if any(has_user_controlled_source(r) and contains_code_injection_signal(r) for r in items):
        return ("No", "Semgrep reports user-controlled input reaching eval-style code execution.")

    if any(contains_code_injection_signal(r) for r in items):
        return ("Yes", "Semgrep reports eval-style execution, but no user-controlled input is shown reaching the expression.")

    if any_user_controlled and any_command_injection:
        return ("No", "Semgrep reports user-controlled data reaching subprocess execution on the affected line.")

    if any_shell_true and not any_user_controlled:
        return ("Yes", "The finding is a shell=True hardening issue, but the available evidence does not show user-controlled input reaching the command.")

    return ("Unclear", "The static finding does not provide enough context to fully confirm exploitability.")

def cluster_key(result):
    """
    Group findings by vulnerability family when the same target produces duplicate Semgrep findings.
    Otherwise, group by affected file and line.
    """
    path = result.get("path", "unknown")
    line = get_line(result)

    if contains_path_traversal_signal(result):
        return f"{path}:path-traversal"

    if contains_ssrf_signal(result):
        return f"{path}:ssrf"

    if contains_insecure_transport_signal(result):
        return f"{path}:insecure-transport"

    if contains_yaml_deserialization_signal(result):
        return f"{path}:yaml-deserialization"

    if contains_pickle_deserialization_signal(result):
        return f"{path}:pickle-deserialization"

    if contains_code_injection_signal(result):
        return f"{path}:code-injection"

    return f"{path}:{line}"

def simplify_finding(result):
    metadata = get_metadata(result)

    return {
        "check_id": get_check_id(result),
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
        "has_user_controlled_source": has_user_controlled_source(result),
        "is_shell_true_signal": is_shell_true_only_signal(result),
    }


def build_clusters(results):
    grouped = defaultdict(list)

    for result in results:
        grouped[cluster_key(result)].append(result)

    clusters = []

    for _, items in grouped.items():
        check_ids = sorted({get_check_id(r) for r in items if get_check_id(r)})
        files = sorted({
            f"{r.get('path')}:{get_line(r)}"
            for r in items
            if r.get("path") and get_line(r)
        })

        likely_fp, fp_reason = false_positive_decision_for_items(items)

        clusters.append({
            "severity": practical_severity_for_items(items),
            "cluster": cluster_name_for_items(items),
            "check_ids": check_ids,
            "files": files,
            "likely_false_positive": likely_fp,
            "false_positive_reason": fp_reason,
            "findings": [simplify_finding(r) for r in items],
        })

    clusters.sort(key=lambda c: SEVERITY_RANK[c["severity"]], reverse=True)
    return clusters


def fallback_enrichment(cluster):
    if cluster["cluster"] == "Command Injection":
        return {
            "impact": (
                "User-controlled input reaches a subprocess call, which can allow an attacker to execute arbitrary operating-system commands. "
                "If exploited, this can lead to server compromise, data exposure, malware execution, or lateral movement."
            ),
            "minimal_safe_fix": (
                "Avoid shell=True and pass arguments as a list, for example subprocess.check_output(['ping', '-c', '1', host], shell=False). "
                "Validate the host value with an allowlist or strict IP/hostname parser before passing it to subprocess."
            ),
        }

    if cluster["cluster"] == "Shell=True Subprocess Hardening":
        return {
            "impact": (
                "The subprocess call uses shell=True, which increases risk because the command is interpreted by a shell. "
                "In this case, no user-controlled input is shown reaching the command, so the issue is better treated as hardening rather than confirmed command injection."
            ),
            "minimal_safe_fix": (
                "Avoid shell=True where possible and pass the command as an argument list. "
                "Keep command selection restricted to an internal allowlist."
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
    }


def call_ollama_for_enrichment(cluster):
    """
    The LLM may only write explanation/fix text.
    It is not allowed to decide severity, check IDs, files, or false-positive status.
    """
    safe_cluster = {
        "severity": cluster["severity"],
        "cluster": cluster["cluster"],
        "files": cluster["files"],
        "likely_false_positive": cluster["likely_false_positive"],
        "false_positive_reason": cluster["false_positive_reason"],
        "findings": cluster["findings"],
    }

    prompt = f"""
You are a concise application security triage assistant.

Return only valid JSON with this exact object shape:
{{
  "impact": "Exactly two sentences explaining practical exploit impact.",
  "minimal_safe_fix": "Specific minimal safe fix guidance."
}}

Do not include markdown.
Do not include check IDs.
Do not include files.
Do not include severity.
Do not decide false-positive status.
Do not add extra keys.

Cluster:
{json.dumps(safe_cluster, indent=2)}
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

        if not isinstance(parsed, dict):
            raise ValueError("LLM did not return a JSON object")

        if "impact" not in parsed or "minimal_safe_fix" not in parsed:
            raise ValueError("LLM response missing required keys")

        return {
            "impact": str(parsed.get("impact", "")).strip(),
            "minimal_safe_fix": str(parsed.get("minimal_safe_fix", "")).strip(),
        }

    except Exception as e:
        print(f"LLM enrichment failed, using fallback: {e}")
        return fallback_enrichment(cluster)


def validate_output(raw_results, final_clusters):
    expected_ids = {get_check_id(r) for r in raw_results if get_check_id(r)}
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
        if (
            cluster.get("likely_false_positive") == "Yes"
            or cluster.get("cluster") == "Shell=True Subprocess Hardening"
        ):
            enrichment = fallback_enrichment(cluster)
        else:
            enrichment = call_ollama_for_enrichment(cluster)

        final_clusters.append({
            "severity": cluster["severity"],
            "cluster": cluster["cluster"],
            "check_ids": cluster["check_ids"],
            "files": cluster["files"],
            "impact": enrichment["impact"],
            "minimal_safe_fix": enrichment["minimal_safe_fix"],
            "likely_false_positive": cluster["likely_false_positive"],
            "false_positive_reason": cluster["false_positive_reason"],
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