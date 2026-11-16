"""Run GTK integration tests with disposable files and settings.

Requires a display: use `xvfb-run -a make gui-test` on headless Linux.
SFM_SCREENSHOT_DIR optionally receives actual GTK widget renders of test states.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
binary = Path(os.environ.get("SFM_GUI_TEST", root / "bin" / "secure_gui_tests")).resolve()
if not binary.exists() and binary.with_suffix(".exe").exists():
    binary = binary.with_suffix(".exe")
with tempfile.TemporaryDirectory(prefix="sfm-gui-test-") as temporary:
    environment = os.environ.copy()
    environment["GSETTINGS_BACKEND"] = "memory"
    environment["GTK_USE_PORTAL"] = "0"
    environment["NO_AT_BRIDGE"] = "1"
    for key, folder in (("XDG_CONFIG_HOME", "config"), ("XDG_CACHE_HOME", "cache"),
                        ("XDG_DATA_HOME", "data")):
        path = Path(temporary) / folder
        path.mkdir()
        environment[key] = str(path)
    result = subprocess.run([str(binary)], cwd=temporary, env=environment,
                            capture_output=True, text=True, timeout=60)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    sys.exit(result.returncode)
