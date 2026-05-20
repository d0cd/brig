"""brig image build --use-warden routes the build's HTTP traffic
through warden (aitelier wishlist #3). Closes the build/runtime
asymmetry — today's build is fast+unfiltered, runtime is slow+MITM'd,
forcing operators to pre-bake binaries into the image. With this flag
the build hits the same warden path as runtime; layer cache amortizes.

The Containerfile must opt in via standard `ARG HTTPS_PROXY` /
`ENV HTTPS_PROXY=$HTTPS_PROXY` patterns. Tools that honor the env
vars (curl, wget, npm, pip, apt) flow through warden; tools that
ignore them fall through to direct. Not as hermetic as a transient
network, but adequate for the common case and zero new infrastructure.
"""

from __future__ import annotations

import subprocess
import types
import unittest
from unittest.mock import patch


def _args(**kw):
    """Build the args namespace the cmd_build handler expects."""
    base = {
        "context": ".",
        "tag": "localhost/test:dev",
        "file": None,
        "build_arg": None,
        "use_warden": False,
    }
    base.update(kw)
    return types.SimpleNamespace(**base)


class TestUseWardenInjection(unittest.TestCase):
    def _run_with_capture(self, use_warden):
        """Invoke cmd_build with a fake context, capture the subprocess
        argv. Mocks every external dependency so we observe just the
        argv shape."""
        from brig.commands import image_cmd

        captured: dict = {}

        def fake_run(argv, **kw):
            captured["argv"] = argv
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        # Fake "context is a dir" + autodetect Containerfile.
        with patch.object(image_cmd.Path, "resolve",
                          lambda self: self), \
             patch.object(image_cmd.Path, "is_dir", lambda self: True), \
             patch.object(image_cmd, "_load_ignore_patterns",
                          return_value=[]), \
             patch.object(image_cmd, "_stream_tar_context",
                          return_value=b""), \
             patch.object(image_cmd, "_resolve_warden_ip",
                          return_value="10.42.0.2"), \
             patch("brig.network.proxy.proxy_running", return_value=True), \
             patch("subprocess.run", side_effect=fake_run), \
             patch.object(image_cmd.Path, "is_file",
                          lambda self: self.name in ("Containerfile",)):
            image_cmd.cmd_build(_args(use_warden=use_warden))
        return captured["argv"]

    def test_no_flag_no_injection(self):
        argv = self._run_with_capture(use_warden=False)
        joined = " ".join(argv)
        self.assertNotIn("HTTPS_PROXY", joined)
        self.assertNotIn("warden-ca.crt", joined)

    def test_flag_injects_proxy_env(self):
        argv = self._run_with_capture(use_warden=True)
        # Both upper- and lowercase forms get injected for tool coverage.
        for var in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
            self.assertIn(
                f"{var}=http://10.42.0.2:8080", " ".join(argv),
                f"missing {var}",
            )

    def test_flag_injects_no_proxy_for_localhost(self):
        """Build sidecar test servers (curl http://localhost:8080) must
        not be proxied through warden — that'd timeout or 502."""
        argv = self._run_with_capture(use_warden=True)
        joined = " ".join(argv)
        self.assertIn("NO_PROXY=localhost,127.0.0.1,::1", joined)
        self.assertIn("no_proxy=localhost,127.0.0.1,::1", joined)

    def test_flag_mounts_warden_ca(self):
        argv = self._run_with_capture(use_warden=True)
        joined = " ".join(argv)
        self.assertIn(":/etc/ssl/certs/warden-ca.crt:ro", joined)
        self.assertIn(
            "SSL_CERT_FILE=/etc/ssl/certs/warden-ca.crt", joined,
        )


class TestUseWardenRequiresWardenRunning(unittest.TestCase):
    def test_raises_brigerror_when_warden_off(self):
        from brig.commands import image_cmd
        from brig.errors import BrigError

        with patch.object(image_cmd.Path, "resolve",
                          lambda self: self), \
             patch.object(image_cmd.Path, "is_dir", lambda self: True), \
             patch.object(image_cmd.Path, "is_file",
                          lambda self: self.name == "Containerfile"), \
             patch("brig.network.proxy.proxy_running", return_value=False):
            with self.assertRaises(BrigError) as ctx:
                image_cmd.cmd_build(_args(use_warden=True))
        msg = str(ctx.exception)
        self.assertIn("Warden", msg)
        self.assertIn("brig up", ctx.exception.suggestion or "")


if __name__ == "__main__":
    unittest.main()
