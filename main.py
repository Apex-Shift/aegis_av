#!/usr/bin/env python3
"""AegisAV v2 — Advanced Python Security Suite."""

from __future__ import annotations

import os
import sys


def main() -> None:
    os.makedirs("data/signatures", exist_ok=True)
    os.makedirs("data/yara_rules", exist_ok=True)
    os.makedirs("data/quarantine", exist_ok=True)

    from src.ui.gui import AegisGUI

    app = AegisGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
