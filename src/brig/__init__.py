"""
Brig - Secure workload harness for running untrusted code.

Each cell runs in an isolated network with gVisor sandboxing.
All egress traffic goes through the Warden policy-enforcing proxy.

SDK usage:
    from brig.sdk import Brig

    b = Brig()
    cell = b.run_sync(name="test", image="alpine", command=["echo", "hi"])
    exit_code = cell.wait_sync()
"""

__version__ = "0.2.0"

from brig.sdk import (
    Brig,
    BrigError,
    Cell,
    CellEvent,
    CellInfo,
    CellNotFoundError,
    CellResult,
    CellRunResult,
    CellStats,
    ImageVerificationError,
    ProfileError,
    SecretNotFoundError,
    WardenHandle,
    WardenStatus,
)

__all__ = [
    "Brig", "Cell", "BrigError", "CellNotFoundError", "ImageVerificationError",
    "ProfileError", "SecretNotFoundError", "CellResult", "CellInfo",
    "CellRunResult", "CellEvent", "CellStats", "WardenStatus", "WardenHandle",
]
