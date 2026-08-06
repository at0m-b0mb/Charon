#!/usr/bin/env python3
"""Launch Charon from a source checkout without installing it.

    python3 run.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

if __name__ == "__main__":
    try:
        from charon.app import main
    except ImportError as exc:
        missing = str(exc).split("'")[1] if "'" in str(exc) else str(exc)
        sys.exit(
            f"Charon needs a dependency that is not installed: {missing}\n\n"
            f"  python3 -m venv .venv\n"
            f"  .venv/bin/pip install -r requirements.txt\n"
            f"  .venv/bin/python run.py\n"
        )
    raise SystemExit(main())
