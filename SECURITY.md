# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Brig, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please use [GitHub Security Advisories](https://github.com/d0cd/brig/security/advisories/new) to report vulnerabilities privately. Include:

1. Description of the vulnerability.
2. Steps to reproduce.
3. Affected versions.
4. Potential impact.

## Scope

Brig's security model relies on the following boundaries:

- **Lima VM**: The only hard security boundary protecting macOS from untrusted workloads.
- **gVisor (runsc)**: Defense-in-depth inside the VM. Not a security boundary.
- **Per-cell networks**: Isolation by network topology.
- **Warden proxy**: Mandatory egress choke point enforcing network policy.

Vulnerabilities that break these boundaries are considered critical.

## Security Invariants

1. No east-west traffic between cells.
2. Warden cannot be abused as a gateway.
3. Secrets are observable (exfiltration is detectable), not preventable.
4. macOS state directory is untrusted.
5. gVisor must be active (no silent downgrade).
6. Only Warden may attach to the proxy-external network.
7. No privileged services on cell networks.
8. Cells must be single-homed (one network only).
9. Warden must be running before cells start.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | Yes       |
| < 0.3   | No        |
