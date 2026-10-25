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
- overall, connect, input, line, response, concurrency, repeat, redirect, and
  target-count, URL-size, sorting and queue limits, plus a 64 KiB status/header limit;
- one aggregate decompressed-byte budget across all plain and gzip input sources;
- proxy passwords redacted from output and omitted from history;
- redacted `***` passwords rejected when diagnostic output is re-imported;
- target paths, fragments, and queries removed from persisted observations;
- history and generated configuration use owner-only permissions;
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

Passwords present in process arguments may be visible in shell history and the
process list. Prefer a mode-0600 input file or protected standard input. Usernames
remain visible while passwords are replaced by `***`. Endpoint IDs hash the
credential set so alternate credentials are not incorrectly deduplicated; the
hash is an identifier, not an encrypted secret.

Normal results and history always redact passwords. `--working-output` is an
explicit credential-bearing export for operational use; it creates mode-0600
files, refuses replacement unless `--force` is present, refuses to target an
input path, and commits by same-directory atomic replacement only after a
complete run. Its contents must be handled as secrets.

When a credential-bearing input file is readable by group or other users,
RelayProbe emits a security warning with the observed mode. It does not change
operator-owned file permissions automatically.

Anonymity observations are limited. Forwarded-header evidence proves that a
chosen echo target observed a header; its absence cannot prove anonymity. Exit
IP, geolocation, ASN, and operator labels can be wrong or unavailable. Treat
third-party target response data as untrusted evidence.

Report vulnerabilities according to the repository's private disclosure
procedure in [SECURITY.md](../SECURITY.md). Include the RelayProbe version,
affected command, sanitized input, and a minimal reproduction without live
third-party credentials.
