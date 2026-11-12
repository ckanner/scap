"""Reuse transport and independent decoders; never a product implementation."""
from __future__ import annotations

from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
BASE = HERE.parent / 'object-owner-plan-runtime'
sys.path.insert(0, str(BASE))

import spec as base_spec
import support as io
from harness import Harness
