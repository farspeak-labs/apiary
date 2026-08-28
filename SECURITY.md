# Security policy

Apiary is security-sensitive software. It controls agent identities,
credentials, inference, local resources, remote services, and external agent
harnesses. Version 0.1 is a pre-audit beta and should not yet protect assets
whose compromise would be catastrophic.

## Reporting a vulnerability

Please report vulnerabilities through a private GitHub security advisory for
`farspeak-labs/apiary`. Do not open a public issue containing an exploit, credential,
private Nostr key, access token, host address, or agent export.

Include the affected commit or version, platform, configuration, reproduction
steps, impact, and whether you believe exploitation is active. Use synthetic
identities and credentials whenever possible.

## Supported releases

Only the latest tagged `0.1.x` release receives security fixes. The default
branch is development code and may contain incompatible manifest or storage
changes.

## Security boundaries

- `--auth open` is for loopback or a trusted SSH boundary only. Internet-facing
  hosts must use NIP-98 and an explicit host-manager registry.
- A browser session is an in-memory authentication cache, not authority. Every
  operation still checks the host or per-agent role bound to its Nostr signer.
- Connectors, skills, MCP servers, and ACP harnesses are separate grants. A
  skill or harness profile does not implicitly receive undeclared tools.
- The current local keystore uses NIP-49 encrypted keys. NIP-46 remote-signer
  custody and complete compromised-key rotation remain planned work.
- The macOS desktop and headless host have not yet completed an independent
  security assessment.

See [docs/SPEC.md](docs/SPEC.md) for the threat model and
[docs/RECOVERY.md](docs/RECOVERY.md) for current recovery limitations.
