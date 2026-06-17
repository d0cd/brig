"""Pytest configuration for brig tests.

Isolates the entire test suite from the user's real ~/.brig directory by
pointing $BRIG_HOME at a session-scoped tmpdir BEFORE any brig module is
imported. Without this, tests that exercise high-level functions (e.g.
stop_cell → deregister_ingress, reconciler PODMAN_RUN → write_metadata)
silently mutate the operator's live state. The first time this bit us was
the aitelier-reported pytest-clobbers-subnet-map bug.
"""

import atexit
import os
import shutil
import sys
import tempfile
from pathlib import Path

# Must happen before `import brig` anywhere — config.py reads BRIG_HOME at
# class-definition time, and several modules cache derived paths at import.
_TEST_BRIG_HOME = tempfile.mkdtemp(prefix="brig-test-home-")
os.environ["BRIG_HOME"] = _TEST_BRIG_HOME
atexit.register(shutil.rmtree, _TEST_BRIG_HOME, ignore_errors=True)

src_dir = str(Path(__file__).parent.parent / "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

# The warden addons are flat-loaded by mitmproxy and import each other as flat
# modules (`from _common import ...`). Put their dir on the path so tests import
# them the same way the container does (`from ingress import ...`), matching the
# runtime /addons layout rather than treating them as a brig submodule.
addons_dir = str(Path(__file__).parent.parent / "src" / "brig" / "warden_addons")
if addons_dir not in sys.path:
    sys.path.insert(0, addons_dir)
