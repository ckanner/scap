#!/usr/bin/env python3
"""Audit the independently closed real-response absence-race evidence."""
import argparse
import json
from absence_audit import audit

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence')
    print(json.dumps(audit(parser.parse_args().evidence), sort_keys=True, indent=2))
