#!/usr/bin/env python3
"""Brig CLI entry point.

This module provides the entry point for the brig command.
The actual implementation is in brig.py (which must be renamed or this must import it).
"""

# For simplicity, we duplicate the entry point logic here.
# The actual implementation remains in brig.py for direct script execution.

def main():
    """Entry point for brig CLI."""
    import runpy
    import sys
    import os

    # Find brig.py in the same directory.
    src_dir = os.path.dirname(os.path.abspath(__file__))
    brig_script = os.path.join(src_dir, "brig.py")

    if os.path.exists(brig_script):
        # Run brig.py as __main__.
        sys.argv[0] = "brig"
        runpy.run_path(brig_script, run_name="__main__")
    else:
        print("ERROR: brig.py not found", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
