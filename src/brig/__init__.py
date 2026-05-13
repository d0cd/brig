"""
Brig - Secure workload harness for running untrusted code.

Each cell runs in an isolated network with gVisor sandboxing.
All egress traffic goes through the Warden policy-enforcing proxy.

SDK usage:
    from brig import Brig

    b = Brig()
    result = b.execute_sync("python:3.12", ["python", "-c", "print('hello')"])
    print(result.exit_code, result.stdout)
"""

from brig.config import VERSION

__version__ = VERSION
from brig.errors import BrigError
from brig.sdk import (
    Brig,
    Cell,
    CellInfo,
    CellNotFoundError,
    CellRunResult,
    ImageVerificationError,
    ProfileError,
    SecretNotFoundError,
    WardenHandle,
    WardenStatus,
)

__all__ = [
    "Brig", "Cell", "BrigError", "CellNotFoundError", "ImageVerificationError",
    "ProfileError", "SecretNotFoundError", "CellRunResult", "CellInfo",
    "WardenStatus", "WardenHandle", "VERSION",
]
