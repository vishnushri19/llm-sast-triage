#!/usr/bin/env python3
import subprocess
import sys

steps = [
    [sys.executable, 'scripts/run_scans.py'],
    [sys.executable, 'scripts/llm_rank.py'],
    [sys.executable, 'scripts/eval.py'],
]

for step in steps:
    print('\nRunning:', ' '.join(step))
    subprocess.run(step, check=True)

print('\nPipeline completed successfully.')
