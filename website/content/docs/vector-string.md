---
title: Vector String
weight: 2
---

# Vector String

The CRIT vector string is a CVSS-style compact encoding of a record's
classification + identity fields. It is **deterministic** — given the
same structured fields, the encoder always produces the same string
and the parser is the inverse.

## Format

```
CRITv<semver>/<metric>:<value>[/...]#<vuln_id>:<service>:<resource_type>
```

Sample:

```
CRITv0.3.0/CP:AW/VS:FX/FP:RR/SR:SH/RL:SM/EV:T/PP:1719792000/SA:1514764800#CVE-2024-21626:eks:cluster
```

## Metric keys

The eight registered keys, in canonical order:

| Key | Field | Encoding |
|---|---|---|
| `CP` | `provider` | 2-char provider code (AW, MA, GC, CF, OC, …) |
| `VS` | `vex_status` | AF, FX, NA, UI |
| `FP` | `fix_propagation` | AU, CC, OI, VU, RD, RR, DC, RL, NF |
| `SR` | `shared_responsibility` | PO, CA, CO, SH |
| `RL` | `resource_lifecycle` | EP, SM, SC, CF, GC |
| `EV` | `existing_deployments_remain_vulnerable` | T or F |
| `PP` | `vuln_published_date` | int64 epoch seconds |
| `SA` | `service_available_date` | int64 epoch seconds |

After the `#`: three positional colon-separated values —
`vuln_id`, `service`, `resource_type` — exactly mirroring the
record's natural key.

## Round-trip rule

Every record's `vectorString` MUST be byte-equal to
`ComputeVector(parsed_fields)`. The validator runs this check by
parsing the vector, recomputing it from the structured fields, and
comparing strings. A mismatch is a reject-at-publish-time hard
failure.

## Why bother with a vector?

- **Compact wire format** — fits in CVE.org adp.metrics, in a Slack
  paste, in a header.
- **Signable** — short enough for a human to verify a hash; useful
  for chain-of-custody on advisories.
- **Greppable** — `CRITv0.3.0/CP:AW/.../#CVE-2024-` is a stable token
  for log/feed pipelines.
- **Versioned** — `CRITv<semver>` lets parsers reject vectors from a
  spec version they don't understand.

## Implementations

- **Go**: `github.com/Vulnetix/ietf-crit-spec.ComputeVector` /
  `ParseVector` / `ValidateVectorRoundTrip`.
- **JavaScript**: bundled in this site's
  [validator](../../validator/) — port of the Go reference. No deps.
