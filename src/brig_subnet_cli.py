#!/usr/bin/env python3
"""Brig-subnet CLI entry point."""


def main():
    """Entry point for brig-subnet CLI."""
    import os
    import runpy
    import sys

    src_dir = os.path.dirname(os.path.abspath(__file__))
    subnet_script = os.path.join(src_dir, "brig_subnet.py")

    if os.path.exists(subnet_script):
        sys.argv[0] = "brig-subnet"
        runpy.run_path(subnet_script, run_name="__main__")
    else:
        print("ERROR: brig_subnet.py not found", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
