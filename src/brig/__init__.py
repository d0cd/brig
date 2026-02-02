"""
Brig - Secure workload harness for running untrusted code.

Each cell runs in an isolated network with gVisor sandboxing.
All egress traffic goes through the Warden policy-enforcing proxy.
"""

__version__ = "1.0.0"
