# Offline exit-IP metadata

RelayProbe can enrich an observed exit IP from an operator-supplied CSV database.
Lookup is entirely local: no proxy, exit IP, target, or credential is sent to a
metadata API.

Native MaxMind DB (`.mmdb`) files are not currently read directly. Export or
transform licensed data into the schema below without changing its license or
provenance, and validate the result in a controlled workflow. This keeps the
released binary dependency-free and avoids silently guessing vendor-specific
record layouts.

## Schema

The first row must be a header and must include `prefix`. Other recognized
columns are optional:

```csv
prefix,country_code,country,city,asn,organization,network_type
8.8.8.0/24,US,United States,Mountain View,AS15169,Google,datacenter
```

`prefix` accepts IPv4 or IPv6 CIDR notation. `asn` accepts `15169` or `AS15169`
and is normalized to the latter form. Country codes are normalized to uppercase;
network types are normalized to lowercase. The database may be gzip-compressed.

Overlapping networks use deterministic longest-prefix matching. Duplicate
prefixes, malformed networks, invalid two-letter country codes, fields longer
than 256 bytes, more than 2,000,000 records, or more than 256 MiB of decompressed
CSV are rejected before proxy validation starts.

## Usage

```sh
relayprobe check --metadata-file ip-metadata.csv.gz --save proxies.txt
relayprobe results --run latest --country ES --network-type residential
relayprobe export --run latest --asn AS3352 --min-score 75 --format csv --output as3352.csv
```

The configuration file field is `metadata_file`; the environment equivalent is
`RELAYPROBE_METADATA_FILE`.

## Data quality

Country, city, ASN, and network type are claims made by the chosen dataset.
Mobile and residential address space can change frequently, anycast exits may
have several valid locations, and an ASN can contain both hosting and access
networks. RelayProbe does not convert an organization name into a network type
or present metadata as independently verified fact.

Review the source's license before redistributing a database or enriched output.
Prefer datasets with a stated update cadence and retain the dataset version used
for repeatable comparisons.
