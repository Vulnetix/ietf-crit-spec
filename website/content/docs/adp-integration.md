---
title: ADP / x_crit Integration
weight: 4
---

CRIT records are designed to be **embedded** in CVE 5.x records — not
shipped as a parallel feed. The CVE.org record format reserves the
**ADP** (Authorized Data Publisher) container for third-party
enrichment of a CNA's CVE. CRIT lives there as `x_crit`.

## Where x_crit goes

```json
{
  "dataType": "CVE_RECORD",
  "dataVersion": "5.1",
  "cveMetadata": { "cveId": "CVE-2024-21626", "state": "PUBLISHED", … },
  "containers": {
    "cna": { … },
    "adp": [
      {
        "providerMetadata": {
          "orgId": "8d7b6f2a-0b1c-4f5d-a3e6-9c8d7e6f5a4b",
          "shortName": "Vulnetix"
        },
        "x_crit": [
          { "vectorString": "CRITv0.3.0/CP:AW/...", "vuln_id": "CVE-2024-21626", "provider": "aws", "service": "eks", "resource_type": "cluster", … },
          { "vectorString": "CRITv0.3.0/CP:AW/...", "vuln_id": "CVE-2024-21626", "provider": "aws", "service": "ec2", "resource_type": "instance", … }
        ]
      }
    ]
  }
}
```

## Rules

- `cveMetadata.state` MUST be `PUBLISHED` for any record carrying
  `x_crit`. The validator checks this.
- Every `x_crit[i].vuln_id` MUST equal `cveMetadata.cveId`.
- Multiple CRIT records per ADP entry are allowed and expected — one
  CVE often affects multiple `(provider, service, resource_type)`
  natural keys (EKS cluster + EC2 instance + Lambda function for
  Log4Shell, for example).
- Each `x_crit[i]` MUST validate against
  `crit-record-v0.3.0.schema.json` independently.

## Why ADP, not CNA?

CVE.org reserves the CNA container for the CVE numbering authority
that issued the CVE (vendor or coordinator). ADP is the spec-level
extension point for **third-party enrichment** — exactly what CRIT
is. Vulnetix publishes CRIT records into ADP entries it operates;
other publishers can do the same with their own `providerMetadata`.

## Validating a CVE+x_crit record

The [in-browser validator](../../validator/) accepts a full CVE 5.x
JSON record. It:

1. Confirms `dataType == "CVE_RECORD"` and parses the schema version.
2. Walks `containers.adp[]` looking for entries with `x_crit`.
3. Validates each `x_crit[i]` against the CRIT record schema.
4. Cross-checks `vuln_id == cveMetadata.cveId`.
5. Recomputes each `vectorString` and asserts byte-equality.
6. Resolves each natural key against the spec dictionaries.

## Reference implementation

`github.com/Vulnetix/ietf-crit-spec/cmd/crit-validate` is the
canonical Go validator and emits identical error messages to the
in-browser tool.
