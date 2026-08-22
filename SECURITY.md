# Security policy

## Supported code

Security fixes target the protected `main` branch and the most recent signed
GT-AX11000 release derived from it. Development branches and unsigned test
images are not supported releases.

## Reporting a vulnerability

Use GitHub's private vulnerability-reporting form:

https://github.com/0x1337F00D/asuswrt-merlin.ng/security/advisories/new

Do not disclose a suspected vulnerability in a public issue or pull request.
Include the affected commit or image hash, reachable interface, prerequisites,
minimal reproduction and impact. Remove passwords, keys, SSIDs, MAC addresses,
public IP addresses, NVRAM exports and packet payloads before submitting.

Expect an acknowledgement within seven days. Triage and remediation timing
depends on severity, upstream/vendor ownership and whether hardware validation
is required. Proprietary Broadcom/ASUS findings may need coordinated upstream
disclosure and cannot always be fixed in this overlay.

## Release boundary

No report or patch is sufficient by itself to authorize flashing. Release
candidates must pass the repository gates, a clean locked-input build and, for
runtime or recovery changes, the documented one-shot hardware trial with a
verified fallback partition.
