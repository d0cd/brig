"""
Brig - Secure workload harness for running untrusted code.

Each cell runs in an isolated network with gVisor sandboxing.
All egress traffic goes through the Warden policy-enforcing proxy.

SDK usage:
    from brig import Brig

    b = Brig()
    result = b.execute_sync("python:3.12", ["python", "-c", "print('hi')"])
    print(result.exit_code)
    print(result.stdout, end="")
"""

from brig.config import VERSION
from brig.errors import BrigError

__version__ = VERSION

# Lazy SDK exports — only imported when first accessed via `brig.<name>`.
# Keeps `python -c "import brig"` and CLI startup cheap by deferring the
# import of brig.sdk (which transitively imports subprocess, json, etc.)
# until the SDK is actually used.
_SDK_NAMES = {
    "Brig", "Cell", "CellInfo", "CellNotFoundError", "CellRunResult",
    "ImageVerificationError", "ProfileError", "SecretNotFoundError",
    "WardenHandle", "WardenStatus",
}


def __getattr__(name):
    if name in _SDK_NAMES:
        from brig import sdk
        return getattr(sdk, name)
    raise AttributeError(f"module 'brig' has no attribute {name!r}")


def __dir__():
    return sorted(set(globals()) | _SDK_NAMES)


__all__ = [
    "Brig", "Cell", "BrigError", "CellNotFoundError", "ImageVerificationError",
    "ProfileError", "SecretNotFoundError", "CellRunResult", "CellInfo",
    "WardenStatus", "WardenHandle", "VERSION",
]
