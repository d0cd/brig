#!/usr/bin/env python3
"""Warden CLI entry point."""


def main():
    """Entry point for warden CLI."""
    import os
    import runpy
    import sys

    src_dir = os.path.dirname(os.path.abspath(__file__))
    warden_script = os.path.join(src_dir, "warden.py")

    if os.path.exists(warden_script):
        sys.argv[0] = "warden"
        runpy.run_path(warden_script, run_name="__main__")
    else:
        print("ERROR: warden.py not found", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
