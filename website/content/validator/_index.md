---
title: Validator
toc: false
weight: 1
---

# CRIT Validator

Paste a CRIT record, a CVE 5.x record carrying `x_crit`, or a vector
string. Get instant validation against the v0.3.0 schemas, vector
round-trip checks, and dictionary resolution.

**Nothing leaves your browser** — schemas, dictionaries, and the
parser all run client-side.

{{< crit-validator >}}

---

## Sources

- Schemas: [crit-record-v0.3.0](https://github.com/Vulnetix/ietf-crit-spec/blob/main/schemas/crit-record-v0.3.0.schema.json) · [crit-dictionary-v0.3.0](https://github.com/Vulnetix/ietf-crit-spec/blob/main/schemas/crit-dictionary-v0.3.0.schema.json)
- Sample envelopes: [samples/](https://github.com/Vulnetix/ietf-crit-spec/tree/main/samples)
- Reference validator (Go): [cmd/crit-validate](https://github.com/Vulnetix/ietf-crit-spec/tree/main/cmd/crit-validate)

## Modes

- **CRIT record** — single envelope. JSON Schema + vector round-trip
  + dictionary resolution.
- **CVE 5.x with x_crit** — full CVE.org record. Walks
  `containers.adp[].x_crit[]`, validates each, cross-checks
  `vuln_id == cveMetadata.cveId`.
- **Vector string** — paste a `CRITv0.3.0/...` string. Decodes to
  structured fields, recomputes, and reports any unknown metric
  warnings.
