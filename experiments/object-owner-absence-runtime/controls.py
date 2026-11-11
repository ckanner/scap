#!/usr/bin/env python3
"""Run all persisted absence-race negative controls and an unchanged positive."""
import argparse
import json
from pathlib import Path
from absence_controls import run

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    arguments = parser.parse_args()
    report = run(arguments.evidence, arguments.output)
    print(json.dumps({'status': report['status'], 'controls': str(arguments.output / 'controls.json')}, sort_keys=True))
    raise SystemExit(0 if report['status'] == 'PASSED' else 1)
