#!/usr/bin/env python3
"""
Generate man page for brig CLI.

Usage:
    python3 brig-manpage.py > brig.1
    man ./brig.1
"""

import datetime

COMMANDS = [
    ("run", "Run a new cell", [
        ("-n, --name NAME", "Cell name (required unless in definition file)"),
        ("-f, --file FILE", "Cell definition file (YAML or JSON)"),
        ("-d, --detach", "Run in background"),
        ("--rm", "Remove container when it exits"),
        ("--dry-run", "Show what would be done without executing"),
        ("-e, --env VAR=VALUE", "Set environment variable"),
        ("--secret NAME", "Mount secret file at /run/secrets/"),
        ("--memory SIZE", "Memory limit (default: 2g)"),
        ("--cpus N", "CPU limit (default: 2)"),
        ("--pids-limit N", "PID limit (default: 512)"),
        ("--policy-allow DOMAIN", "Allow domain (adds to global policy)"),
        ("--policy-deny DOMAIN", "Deny domain (overrides global policy)"),
    ]),
    ("stop", "Gracefully stop a cell", [
        ("NAME", "Cell name"),
    ]),
    ("kill", "Immediately kill a cell", [
        ("NAME", "Cell name"),
    ]),
    ("rm", "Remove a cell and clean up resources", [
        ("-f, --force", "Force remove running cell"),
        ("--purge", "Also remove workspace"),
        ("NAME", "Cell name"),
    ]),
    ("start", "Start a stopped cell", [
        ("NAME", "Cell name"),
    ]),
    ("pause", "Pause a running cell", [
        ("NAME", "Cell name"),
    ]),
    ("unpause", "Unpause a paused cell", [
        ("NAME", "Cell name"),
    ]),
    ("list", "List all cells", [
        ("--format FORMAT", "Output format: table (default) or json"),
    ]),
    ("logs", "View cell logs", [
        ("-f, --follow", "Follow log output"),
        ("--tail N", "Number of lines to show"),
        ("NAME", "Cell name"),
    ]),
    ("exec", "Execute command in cell", [
        ("-i, --interactive", "Interactive mode"),
        ("-t, --tty", "Allocate pseudo-TTY"),
        ("NAME", "Cell name"),
        ("COMMAND...", "Command to execute"),
    ]),
    ("attach", "Attach to cell's console", [
        ("NAME", "Cell name"),
    ]),
    ("inspect", "Show cell details", [
        ("--format FORMAT", "Output format: table (default) or json"),
        ("NAME", "Cell name"),
    ]),
    ("export", "Export cell as YAML definition", [
        ("--format FORMAT", "Output format: yaml (default) or json"),
        ("NAME", "Cell name"),
    ]),
    ("stats", "Show cell resource usage", [
        ("--no-stream", "Disable live updates"),
        ("NAME", "Cell name (optional, shows all if omitted)"),
    ]),
    ("top", "Show processes in cell", [
        ("NAME", "Cell name"),
    ]),
    ("diff", "Show filesystem changes from base image", [
        ("--format FORMAT", "Output format: text (default) or json"),
        ("NAME", "Cell name"),
    ]),
    ("files", "List workspace contents", [
        ("NAME", "Cell name"),
        ("PATH", "Path within workspace (optional)"),
    ]),
    ("cat", "View file in workspace", [
        ("-n, --lines N", "Show only first N lines"),
        ("--max-size MB", "Max file size in MB (default: 1)"),
        ("--force", "Show binary files"),
        ("NAME", "Cell name"),
        ("PATH", "Path to file within workspace"),
    ]),
    ("cp", "Copy files to/from workspace", [
        ("--sanitize", "Block unsafe file types"),
        ("SRC", "Source path (cell:path or local path)"),
        ("DST", "Destination path (cell:path or local path)"),
    ]),
    ("network", "View cell network activity", [
        ("-f, --follow", "Follow log output"),
        ("--json", "Output raw JSONL"),
        ("--tail N", "Number of lines to show (default: 20)"),
        ("NAME", "Cell name"),
    ]),
    ("diagnose", "Run diagnostic checks on a cell", [
        ("NAME", "Cell name"),
    ]),
    ("verify", "Verify security invariants across all cells", []),
    ("history", "Show operation history", [
        ("--format FORMAT", "Output format: table (default) or json"),
        ("-n, --tail N", "Show last N entries (default: 20)"),
        ("--cell NAME", "Filter by cell name"),
    ]),
    ("policy show", "Show cell's effective network policy", [
        ("NAME", "Cell name"),
    ]),
    ("policy set", "Update cell's network policy", [
        ("--allow DOMAIN", "Add allowed domain"),
        ("--deny DOMAIN", "Add denied domain"),
        ("--remove-allow DOMAIN", "Remove allowed domain"),
        ("--remove-deny DOMAIN", "Remove denied domain"),
        ("NAME", "Cell name"),
    ]),
]


def generate_manpage():
    date = datetime.datetime.now().strftime("%B %Y")

    print(f'''.TH BRIG 1 "{date}" "Brig 1.0" "User Commands"
.SH NAME
brig \\- secure workload harness for running untrusted code
.SH SYNOPSIS
.B brig
[\\fB\\-\\-debug\\fR] [\\fB\\-\\-no\\-color\\fR]
.I command
[\\fIoptions\\fR]
.SH DESCRIPTION
.B brig
runs untrusted code in isolated cells with gVisor sandboxing.
Each cell gets its own network, and all egress traffic goes through the
Warden policy-enforcing proxy.
.PP
Cells provide defense-in-depth through multiple isolation layers:
.IP \\(bu 2
Lima VM provides hardware-level isolation from macOS
.IP \\(bu 2
gVisor (runsc) provides syscall-level sandboxing
.IP \\(bu 2
Per-cell networks prevent east-west traffic between cells
.IP \\(bu 2
Warden proxy enforces domain allowlists on egress traffic
.SH GLOBAL OPTIONS
.TP
.B \\-\\-debug
Enable debug output showing command execution details.
.TP
.B \\-\\-no\\-color
Disable colored output.
.SH COMMANDS''')

    for cmd, desc, opts in COMMANDS:
        cmd_escaped = cmd.replace("-", "\\-")
        print(f".SS {cmd}")
        print(f".B brig {cmd_escaped}")
        for opt, opt_desc in opts:
            opt_escaped = opt.replace("-", "\\-")
            print(f"[\\fB{opt_escaped}\\fR]")
        print(f".PP")
        print(f"{desc}.")
        if opts:
            print(".TP")
            for i, (opt, opt_desc) in enumerate(opts):
                opt_escaped = opt.replace("-", "\\-")
                if i > 0:
                    print(".TP")
                print(f".B {opt_escaped}")
                print(opt_desc)

    print('''.SH CELL DEFINITIONS
Cells can be defined in YAML or JSON files and run with \\fBbrig run -f\\fR.
.PP
Example cell definition:
.PP
.nf
.RS
name: my-worker
image: python:3.11-slim
command: ["python", "-m", "http.server"]
env:
  PORT: "8000"
secrets:
  - api-key
resources:
  memory: 2g
  cpus: 2
  pids_limit: 512
policy:
  allow:
    - "*.example.com"
  deny:
    - "internal.example.com"
detach: true
.RE
.fi
.SH SECURITY
.SS Isolation Layers
.IP 1. 4
\\fBLima VM\\fR: Hardware boundary protecting macOS (primary security boundary)
.IP 2. 4
\\fBgVisor\\fR: Syscall interception providing defense-in-depth
.IP 3. 4
\\fBPer-cell networks\\fR: Internal networks with no direct internet access
.IP 4. 4
\\fBWarden proxy\\fR: Domain-based egress filtering
.SS Security Invariants
.IP \\(bu 2
No east-west traffic between cells
.IP \\(bu 2
Cells cannot bypass the proxy
.IP \\(bu 2
gVisor must be active (no silent downgrade)
.IP \\(bu 2
Cells are single-homed (one network only)
.IP \\(bu 2
Proxy must be running before cells start
.PP
Run \\fBbrig verify\\fR to check all security invariants.
.SH FILES
.TP
.I ~/.brig/lima.yaml
Lima VM configuration
.TP
.I ~/.brig/network-policy.yaml
Global proxy policy
.TP
.I ~/.brig/cells/
Cell definition files
.TP
.I ~/.brig/secrets/
Secret files (one per secret)
.TP
.I ~/.brig/state/
Cell workspaces and logs
.SH EXAMPLES
.SS Run a cell interactively
.PP
.nf
brig run --name test alpine sh
.fi
.SS Run a cell in background
.PP
.nf
brig run -d --name worker python:3.11 python -m http.server
.fi
.SS Run from definition file
.PP
.nf
brig run -f cells/my-worker.yaml
.fi
.SS View network activity
.PP
.nf
brig network my-cell -f
.fi
.SS Check security
.PP
.nf
brig verify
.fi
.SH EXIT STATUS
.TP
.B 0
Success
.TP
.B 1
Error occurred
.SH SEE ALSO
.BR warden (1),
.BR podman (1),
.BR lima (1)
.SH AUTHORS
Brig is developed as part of the Cell secure workload harness project.''')


if __name__ == "__main__":
    generate_manpage()
