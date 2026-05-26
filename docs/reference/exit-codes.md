# Exit Codes

Brig follows the POSIX convention: `0` on success, non-zero on
failure. The bulk of failures surface as `BrigError`, which exits with
code `1` by default.

| Code | Meaning |
|---|---|
| 0   | Success. |
| 1   | Generic failure. Default for `BrigError`. Covers validation errors, policy denials, missing files, podman/lima command failures, and unhandled exceptions. The accompanying stderr message — and the `Suggestion:` line when present — explain the specific cause. |
| 130 | Interrupted (Ctrl-C). The SIGINT handler exits with the POSIX-standard `128 + SIGINT`. |

`BrigError(returncode=...)` is wired so individual commands can return
specific codes, but as of this release every raised `BrigError` uses
the default. Child-process signal exits (`podman` killed by signal N
reports `128 + N`) are propagated as-is.
