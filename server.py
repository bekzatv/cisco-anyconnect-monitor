"""Cisco AnyConnect Monitor — фоновый сборщик статистики и веб-панель.

Запуск: pythonw server.py [--open] [--bind 0.0.0.0] [--port 8765] [--data-dir C:\\ProgramData\\CiscoAnyConnectMonitor]
"""

import os
import sys


def _apply_data_dir(argv: list[str]):
    # Paths are resolved when vpnmon.config is imported, so the data folder must be known first.
    for i, arg in enumerate(argv):
        value = None
        if arg == "--data-dir" and i + 1 < len(argv):
            value = argv[i + 1]
        elif arg.startswith("--data-dir="):
            value = arg.split("=", 1)[1]
        if value:
            os.makedirs(value, exist_ok=True)
            os.environ["VPNMON_DATA_DIR"] = os.path.abspath(value)


_apply_data_dir(sys.argv[1:])

from vpnmon.server import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
