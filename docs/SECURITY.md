# Security model

RelayProbe assumes proxy endpoints and validation target names are explicitly
authorized by the operator. It does not discover proxies, scan address ranges,
evade controls, bypass rate limits, or execute imported content.

Default safeguards:

- exact hostname allowlist derived from configured targets;
- scheme limited to HTTP/HTTPS, with no target URL credentials;
- all DNS answers checked before use;
- loopback, private, link-local, carrier-grade NAT, cloud metadata, reserved,
  documentation, multicast, and unspecified address ranges denied;
- numeric IP pinned in HTTP CONNECT, SOCKS4, and SOCKS5 destination requests;
- concurrent DNS lookup collapse and bounded caching of fully checked answers;
- redirect destinations are revalidated without entering the DNS cache;
- redirects independently allowlisted and resolved;
- TLS 1.2 minimum and normal system certificate validation, never an insecure
  skip mode;
- independent certificate validation for HTTPS proxies and HTTPS destinations;
- overall, connect, input, line, response, concurrency, repeat, redirect, and
  target-count, URL-size, sorting and queue limits, plus a 64 KiB status/header limit;
- one aggregate decompressed-byte budget across all plain and gzip input sources;
- proxy usernames and passwords redacted from ordinary output and omitted from history;
- redacted `***` passwords rejected when diagnostic output is re-imported;
- target paths, fragments, and queries removed from persisted observations unless
  replaced by an explicit control-character-free scenario target name;
- forwarding evidence stores names but not potentially identifying header values;
- history, checkpoints, sharded credential lists, reports, and generated configuration use owner-only permissions;
- standalone summaries and credential-bearing exports use atomic owner-only files;
- generated configuration is synchronized and atomically replaced;
- input/output path aliases are compared after symbolic-link resolution;
- no shell evaluation, dynamic code loading, privileged operation, or service
  modification.

Explicit exceptions `--allow-private-targets` and `--allow-remote-dns` reduce
protection and exist for controlled labs. Private-target mode can reach internal
services through supplied proxies. Remote-DNS mode lets a proxy independently
resolve HTTP CONNECT, forward HTTP, SOCKS4a, and SOCKS5 destinations, so split DNS or
DNS rebinding can defeat IP pinning. These options should not be used with
untrusted datasets or targets.

Credentials present in process arguments may be visible in shell history and the
process list. Prefer a mode-0600 input file or protected standard input. Both
username and password are replaced by `***` in ordinary results. Public endpoint
IDs do not depend on credentials. Exact in-process deduplication uses a randomly
keyed HMAC so alternate credentials remain distinct without persisting a useful
credential verifier.

Normal results and history always redact usernames and passwords. `--working-output` is an
explicit credential-bearing export for operational use; it creates mode-0600
files, refuses replacement unless `--force` is present, refuses to target an
input path, and commits by same-directory atomic replacement only after a
complete run. Its contents must be handled as secrets.

Shard outputs also contain full credentials and use mode 0600. Resume
checkpoints are redacted; because their stable ID is credential-free, alternate
credentials for the same protocol/host/port share resume identity. Do not reuse
one checkpoint when comparing credential variants.

Custom CA bundles extend, rather than replace, the system trust store. RelayProbe
does not expose an insecure TLS mode. Certificate files are bounded before
parsing, and `doctor` validates configured bundles without making a network
request.

When a credential-bearing input file is readable by group or other users,
RelayProbe emits a security warning with the observed mode. It does not change
operator-owned file permissions automatically.

Anonymity observations are limited. Forwarded-header evidence proves that a
chosen echo target observed a header; its absence cannot prove anonymity. Exit
IP, geolocation, ASN, and operator labels can be wrong or unavailable. Treat
third-party target response data as untrusted evidence.

Elite, anonymous, and transparent labels require an operator-supplied baseline
IP and an echo target that returns both exit-IP and header evidence. They describe
one observed request, not a permanent property or guarantee. Supplying a
baseline IP through a process argument may expose it in process listings; use a
mode-0600 configuration file when that IP is sensitive.

Metadata files are local untrusted input with decompressed-byte, record, prefix,
and field limits. Their classifications are not independently verified. Content
assertions identify response properties but do not solve, bypass, or interact
with anti-bot challenges.

Report vulnerabilities according to the repository's private disclosure
procedure in [SECURITY.md](../SECURITY.md). Include the RelayProbe version,
affected command, sanitized input, and a minimal reproduction without live
third-party credentials.
