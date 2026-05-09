---
title: Documentation
weight: 1
---

CRIT — **Cloud Resource Identifier Templates** — is a machine-readable
format for naming the specific cloud resources a CVE affects, alongside
the lifecycle, fix-propagation, and shared-responsibility metadata that
operators need to remediate it.

## Where to start

- **[Spec overview](spec/)** — the v0.3.0 record schema in plain English.
- **[Vector strings](vector-string/)** — CVSS-style compact encoding for
  the classification fields.
- **[Provider dictionaries](dictionaries/)** — the 30+ provider service
  catalogues that bind a `(provider, service, resource_type)` tuple to
  a template URL/ARN/locator format.
- **[ADP / x_crit integration](adp-integration/)** — how to embed CRIT
  records in a CVE 5.x record via the ADP container's `x_crit` field.
- **[In-browser validator](../validator/)** — paste a record, get
  instant validation. No data leaves your browser.

## Status

| Item | Version | Status |
|---|---|---|
| Specification | draft-vulnetix-crit-03 | Active development |
| JSON Schema (record) | crit-record-v0.3.0.schema.json | Released |
| JSON Schema (dictionary) | crit-dictionary-v0.3.0.schema.json | Released |
| Reference implementation | github.com/Vulnetix/ietf-crit-spec @ v0.3.0 | Released |

## Contributing

CRIT is developed in the open. Issues and PRs welcome at
[github.com/Vulnetix/ietf-crit-spec](https://github.com/Vulnetix/ietf-crit-spec).
For real-time discussion join the
[Vulnetix Discord](https://discord.gg/vulnetix).
