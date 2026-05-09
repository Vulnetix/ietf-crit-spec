---
title: Integrations (CVE 5.x, OSV)
weight: 11
---

CRIT records are designed to **embed** in existing vulnerability
record formats, not to ship as a parallel feed. Two integration
shapes are normative: CVE List v5 (via the ADP container's `x_crit`
extension) and OSV (via `cloud:<provider>` ecosystems).

For the full ADP / `x_crit` mechanics see
[ADP / x_crit Integration](../adp-integration/). This page summarises
both integrations side by side.

## CVE List v5 — ADP `x_crit`

CRIT data lands inside the **Authorized Data Publisher** container
on a CVE 5.x record. The Vulnetix ADP container is identified by
`providerMetadata.shortName = "VVD"` (or the Vulnetix `orgId`).

```json
"containers": {
  "adp": [{
    "providerMetadata": { "orgId": "…", "shortName": "VVD" },
    "x_crit": [
      { "vuln_id": "CVE-2024-21626", "provider": "aws", "service": "eks", … },
      { "vuln_id": "CVE-2024-21626", "provider": "aws", "service": "ec2", … }
    ]
  }]
}
```

Rules:

- `cveMetadata.state` **MUST** be `PUBLISHED` for any record carrying `x_crit`.
- Every `x_crit[i].vuln_id` **MUST** equal `cveMetadata.cveId`.
- One entry per natural key tuple — multiple natural keys per CVE
  are expected and supported.

See [ADP / x_crit Integration](../adp-integration/) for the
phase 1 / phase 2 roadmap and producer expectations.

## OSV Schema

Publishers **MAY** also produce CRIT data in OSV-schema format for
consumption by OSV.dev and compatible tooling. Cloud providers are
expressed as ecosystems:

| OSV field | Convention |
|---|---|
| `affected[].package.ecosystem` | `cloud:<provider>` (e.g. `cloud:aws`, `cloud:azure`, `cloud:gcp`) |
| `affected[].package.name` | `<service>:<resource_type>` (e.g. `eks:cluster`, `lambda:function`, `rds:db`) |
| `affected[].package.purl` | `pkg:cloud/<provider>/<service>/<resource_type>` |
| `id` | `OSV-<year>-<id>` per OSV convention; CRIT-specific data lives in `database_specific` or via a `cve` alias |

Notes:

- The `cloud:*` ecosystem namespace is **proposed** for registration
  with the OSV schema ecosystem list. Until registered, tooling that
  doesn't recognise `cloud:*` **MUST NOT** reject records using it.
- The `pkg:cloud/` PURL type is observed in the OSV ecosystem but
  is **not** a registered type in the PURL specification. CRIT
  acknowledges its use for OSV integration but does not define or
  govern it.

A consumer ingesting OSV records **MAY** treat the natural key
`(provider, service, resource_type)` derived from the ecosystem +
package-name as equivalent to a CRIT record's natural key for
deduplication. The full CRIT envelope is recommended over the OSV
shape when both are available, because OSV's schema doesn't carry
`temporal`, `provider_fix_version`, `detections[]`, or
`remediation_actions[]` in their normative form.

## Choosing a path

| Need | Use |
|---|---|
| Ship CRIT alongside the canonical CVE record | CVE List v5 ADP `x_crit` |
| Surface CRIT in OSV-driven SCA tooling | OSV `cloud:*` ecosystem |
| Both | Publish in both — they share the same source of truth |

The reference implementation
(`github.com/Vulnetix/ietf-crit-spec/cmd/crit-validate`) accepts CVE
5.x with `x_crit` directly. The
[in-browser validator](../../validator/) supports the same shape
under the **CVE 5.x with x_crit** tab.
