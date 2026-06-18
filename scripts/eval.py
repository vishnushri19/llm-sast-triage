#!/usr/bin/env python3
import json
from pathlib import Path
import sys

LABELS = Path("labels")
FINDINGS = Path("data/findings")
RANKINGS = Path("data/rankings")
SEV = {"low":1,"medium":2,"high":3,"info":1,"warning":2,"error":3}

def load(p):
    return json.loads(p.read_text(encoding="utf-8"))

def sev(v):
    return SEV.get(str(v).lower(), 0)

def k(check_id, path, line):
    return f"{check_id}|{path}|{line}"

def rk(r):
    return k(r.get("check_id"), r.get("path"), r.get("start",{}).get("line"))

def lk(l):
    return k(l.get("check_id"), l.get("path"), l.get("line"))

def clusters(x):
    return [x] if isinstance(x, dict) else (x if isinstance(x, list) else [])

def match(c, l):
    return l.get("check_id") in set(c.get("check_ids", [])) and f"{l.get('path')}:{l.get('line')}" in set(c.get("files", []))

def pct(a,b):
    return a / b if b else 0.0

def eval_target(name):
    lf = LABELS / f"{name}.json"
    sf = FINDINGS / f"{name}-semgrep.json"
    of = RANKINGS / f"{name}-semgrep-llm.json"
    missing_files = [str(p) for p in (lf, sf, of) if not p.exists()]
    if missing_files:
        print(f"\nEvaluation target: {name}")
        print("Missing files:")
        for p in missing_files:
            print(f"- {p}")
        return None

    labels = load(lf)
    results = load(sf).get("results", [])
    outs = clusters(load(of))

    result_keys = {rk(r) for r in results}
    tp_keys = {lk(l) for l in labels if l.get("tp") is True}
    fp_keys = {lk(l) for l in labels if l.get("tp") is False}
    found_tp = result_keys & tp_keys
    found_fp = result_keys & fp_keys

    semgrep_ids = {r.get("check_id") for r in results if r.get("check_id")}
    llm_ids = {cid for c in outs for cid in c.get("check_ids", [])}
    missing_ids = semgrep_ids - llm_ids
    extra_ids = llm_ids - semgrep_ids

    sev_ok = sev_total = fp_ok = fp_total = 0
    for c in outs:
        matched = [l for l in labels if match(c, l)]
        if not matched:
            continue
        sev_total += 1
        if sev(c.get("severity")) == max(sev(l.get("severity")) for l in matched):
            sev_ok += 1
        for l in matched:
            fp_total += 1
            expected = "Yes" if l.get("tp") is False else "No"
            actual = str(c.get("likely_false_positive", "")).strip()
            if actual == expected:
                fp_ok += 1

    raw = len(results)
    cls = len(outs)
    row = {
        "raw": raw,
        "clusters": cls,
        "tp": len(tp_keys),
        "fp": len(fp_keys),
        "found_tp": len(found_tp),
        "found_fp": len(found_fp),
        "sev_ok": sev_ok,
        "sev_total": sev_total,
        "fp_ok": fp_ok,
        "fp_total": fp_total,
        "missing": len(missing_ids),
        "extra": len(extra_ids),
    }

    print(f"\nEvaluation target: {name}")
    print("-" * 50)
    print(f"Raw Semgrep findings:             {raw}")
    print(f"LLM triage clusters:              {cls}")
    print(f"Cluster compression ratio:        {pct(raw, cls):.2f}x")
    print(f"Labeled true positives:           {len(tp_keys)}")
    print(f"Labeled false positives:          {len(fp_keys)}")
    print(f"Detected labeled TPs:             {len(found_tp)}")
    print(f"Detected labeled FPs:             {len(found_fp)}")
    print(f"Finding-level precision:          {pct(len(found_tp), raw):.2f}")
    print(f"Finding-level recall:             {pct(len(found_tp), len(tp_keys)):.2f}")
    print(f"Severity accuracy:                {pct(sev_ok, sev_total):.2f}")
    print(f"False-positive triage accuracy:   {pct(fp_ok, fp_total):.2f}")
    print(f"LLM missing check IDs:            {len(missing_ids)}")
    print(f"LLM extra check IDs:              {len(extra_ids)}")
    return row

def main():
    rows = []
    for lf in sorted(LABELS.glob("*.json")):
        r = eval_target(lf.stem)
        if r:
            rows.append(r)
    if not rows:
        print("No completed targets found.")
        sys.exit(1)

    total = {k: sum(r[k] for r in rows) for k in rows[0]}
    print("\nOverall summary")
    print("=" * 50)
    print(f"Targets evaluated:                {len(rows)}")
    print(f"Total raw findings:               {total['raw']}")
    print(f"Total LLM clusters:               {total['clusters']}")
    print(f"Overall compression ratio:        {pct(total['raw'], total['clusters']):.2f}x")
    print(f"Overall precision:                {pct(total['found_tp'], total['raw']):.2f}")
    print(f"Overall recall:                   {pct(total['found_tp'], total['tp']):.2f}")
    print(f"Overall severity accuracy:        {pct(total['sev_ok'], total['sev_total']):.2f}")
    print(f"Overall FP triage accuracy:       {pct(total['fp_ok'], total['fp_total']):.2f}")
    print(f"Total missing check IDs:          {total['missing']}")
    print(f"Total extra check IDs:            {total['extra']}")
    if total["missing"] or total["extra"]:
        sys.exit(2)

if __name__ == "__main__":
    main()
