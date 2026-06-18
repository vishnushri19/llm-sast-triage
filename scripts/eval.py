#!/usr/bin/env python3
import json
import pathlib
import sys

LABELS_DIR = pathlib.Path("labels")
FINDINGS_DIR = pathlib.Path("data/findings")
RANKINGS_DIR = pathlib.Path("data/rankings")


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def finding_key(check_id, path, line):
    return f"{check_id}|{path}|{line}"


def semgrep_key(result):
    return finding_key(
        result.get("check_id"),
        result.get("path"),
        result.get("start", {}).get("line"),
    )


def label_key(label):
    return finding_key(
        label.get("check_id"),
        label.get("path"),
        label.get("line"),
    )


def severity_score(value):
    mapping = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "error": 3,
        "warning": 2,
        "info": 1,
    }
    return mapping.get(str(value).lower(), 0)


def evaluate_target(name):
    labels_file = LABELS_DIR / f"{name}.json"
    findings_file = FINDINGS_DIR / f"{name}-semgrep.json"
    llm_file = RANKINGS_DIR / f"{name}-semgrep-llm.json"

    if not labels_file.exists():
        print(f"Missing labels file: {labels_file}")
        return False

    if not findings_file.exists():
        print(f"Missing Semgrep findings file: {findings_file}")
        return False

    if not llm_file.exists():
        print(f"Missing LLM output file: {llm_file}")
        return False

    labels = load_json(labels_file)
    semgrep = load_json(findings_file)
    llm_clusters = load_json(llm_file)

    if isinstance(llm_clusters, dict):
        llm_clusters = [llm_clusters]

    semgrep_results = semgrep.get("results", [])

    label_by_key = {label_key(l): l for l in labels}
    semgrep_keys = {semgrep_key(r) for r in semgrep_results}

    labeled_tp_keys = {
        label_key(l)
        for l in labels
        if l.get("tp") is True
    }

    labeled_fp_keys = {
        label_key(l)
        for l in labels
        if l.get("tp") is False
    }

    found_labeled_tp = semgrep_keys & labeled_tp_keys
    found_labeled_fp = semgrep_keys & labeled_fp_keys

    llm_check_ids = set()
    for cluster in llm_clusters:
        for cid in cluster.get("check_ids", []):
            llm_check_ids.add(cid)

    semgrep_check_ids = {
        r.get("check_id")
        for r in semgrep_results
        if r.get("check_id")
    }

    missing_from_llm = semgrep_check_ids - llm_check_ids
    extra_from_llm = llm_check_ids - semgrep_check_ids

    total_findings = len(semgrep_results)
    total_clusters = len(llm_clusters)

    tp_count = len(found_labeled_tp)
    fp_count = len(found_labeled_fp)

    precision = tp_count / total_findings if total_findings else 0
    recall = tp_count / len(labeled_tp_keys) if labeled_tp_keys else 0

    severity_matches = 0
    severity_checked = 0

    for cluster in llm_clusters:
        cluster_severity = cluster.get("severity")
        cluster_ids = set(cluster.get("check_ids", []))

        matching_labels = [
            l for l in labels
            if l.get("check_id") in cluster_ids
        ]

        if not matching_labels:
            continue

        expected_score = max(severity_score(l.get("severity")) for l in matching_labels)
        actual_score = severity_score(cluster_severity)

        severity_checked += 1

        if expected_score == actual_score:
            severity_matches += 1

    severity_accuracy = (
        severity_matches / severity_checked
        if severity_checked
        else 0
    )

    print("")
    print(f"Evaluation target: {name}")
    print("-" * 50)
    print(f"Raw Semgrep findings:        {total_findings}")
    print(f"LLM triage clusters:         {total_clusters}")
    print(f"Labeled true positives:      {len(labeled_tp_keys)}")
    print(f"Detected labeled TPs:        {tp_count}")
    print(f"Detected labeled FPs:        {fp_count}")
    print(f"Finding-level precision:     {precision:.2f}")
    print(f"Finding-level recall:        {recall:.2f}")
    print(f"Severity accuracy:           {severity_accuracy:.2f}")
    print(f"LLM missing check IDs:       {len(missing_from_llm)}")
    print(f"LLM extra check IDs:         {len(extra_from_llm)}")

    if missing_from_llm:
        print("")
        print("Missing from LLM:")
        for cid in sorted(missing_from_llm):
            print(f"- {cid}")

    if extra_from_llm:
        print("")
        print("Extra from LLM:")
        for cid in sorted(extra_from_llm):
            print(f"- {cid}")

    return not missing_from_llm and not extra_from_llm


def main():
    label_files = sorted(LABELS_DIR.glob("*.json"))

    if not label_files:
        print("No label files found in labels/.")
        sys.exit(1)

    ok = True

    for label_file in label_files:
        target_name = label_file.stem
        result = evaluate_target(target_name)
        ok = ok and result

    if not ok:
        sys.exit(2)


if __name__ == "__main__":
    main()