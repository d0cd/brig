"""warden start/stop emit lifecycle events so operators can correlate
cell-side TCP/HTTP connection failures with restart windows."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch


class TestWardenLifecycleEvents(unittest.TestCase):
    def test_stop_emits_warden_stop_event(self):
        """warden.proxy.stop() imports log_lifecycle inside the try
        block so it can no-op cleanly if brig.ops.history is broken.
        Patching at the source module catches the call regardless
        of when the import resolves."""
        from warden import proxy
        with patch.object(proxy, "vm_run", return_value=MagicMock(returncode=0)), \
             patch("brig.ops.history.log_lifecycle") as mock_log:
            proxy.stop()
        called_events = [c.args[0] for c in mock_log.call_args_list if c.args]
        self.assertIn("warden_stop", called_events)

    def test_stop_swallows_lifecycle_errors(self):
        """Lifecycle logging is best-effort — warden's stop must succeed
        even if the audit-log path can't be written (e.g., perms got
        weird, log dir doesn't exist on a fresh install)."""
        from warden import proxy
        with patch.object(proxy, "vm_run", return_value=MagicMock(returncode=0)), \
             patch("brig.ops.history.log_lifecycle",
                   side_effect=OSError("disk full")):
            # Must not raise.
            self.assertTrue(proxy.stop())


if __name__ == "__main__":
    unittest.main()
