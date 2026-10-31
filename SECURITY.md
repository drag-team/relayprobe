# Security policy

## Supported versions

Security fixes are applied to the latest released minor version. Older releases
may be affected even when a fix can be backported cleanly.

| Version | Supported |
|---|---|
| 0.4.x | Yes |
| Earlier | No |

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository. Open the
repository's **Security** tab, select **Advisories**, then select **Report a
vulnerability**. Do not open a public issue, discussion, or pull request for an
unresolved vulnerability.

Include the affected NetVex version, operating system and architecture,
the affected command, a minimal reproduction, expected impact, and any known
mitigations. Remove live proxy credentials, authentication headers, target
tokens, internal addresses, and unrelated environment data.

Reports are triaged for reproducibility and impact. The project will coordinate
disclosure after a fix or documented mitigation is available. There is no paid
bug bounty.

## Security scope

High-priority areas include destination-policy bypasses, DNS rebinding, unsafe
redirects, TLS verification failures, credential disclosure, input-driven code
execution, unbounded resource consumption, corrupt history writes, and incorrect
authentication classification.

The absence of an anonymity signal, the accuracy of third-party geolocation,
and availability failures in infrastructure outside NetVex's control are
not security guarantees. See the detailed [security model](docs/SECURITY.md).
