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
  the classification fields, with full code → meaning tables.
- **[Variable system](variable-system/)** — the four template slot
  states (named, wildcard, empty, hardcoded) and producer selection rules.
- **[Resolution](resolution/)** — how a consumer turns a template into
  a live identifier through dictionary + slot resolution.
- **[Provider dictionaries](dictionaries/)** — the 30+ provider service
  catalogues that bind a `(provider, service, resource_type)` tuple to
  a template URL/ARN/locator format.
- **[Provider fix version](provider-fix-version/)** — the discriminated
  `provider_fix_version` object, comparison operators, and per-provider
  `version_type` values.
- **[Detections](detections/)** — phase-tagged queries (`pre_fix`,
  `exploitation`, `post_fix`, `misconfiguration`), retention rules, and
  the pending-detection pattern.
- **[Exposure window](exposure-window/)** — formal `[W_start, W_end]`
  computation with per-resource and channel-aware semantics.
- **[Conformance](conformance/)** — producer + consumer MUSTs and
  SHOULDs, plus how to test them.
- **[Integrations (CVE 5.x, OSV)](integrations/)** — how to embed CRIT
  in a CVE 5.x record's ADP container or in OSV `cloud:*` ecosystems.
- **[ADP / x_crit integration](adp-integration/)** — full mechanics for
  the CVE 5.x ADP path.
- **[Security considerations](security-considerations/)** — the six
  classes of concern producers and consumers must account for.
- **[In-browser validator](../validator/)** — paste a record, get
  instant validation. No data leaves your browser.

## Status

| Item | Version | Status |
|---|---|---|
| Specification | draft-vulnetix-crit-02 | Active development |
| JSON Schema (record) | crit-record-v0.3.0.schema.json | Released |
| JSON Schema (dictionary) | crit-dictionary-v0.3.0.schema.json | Released |
| Reference implementation | github.com/Vulnetix/ietf-crit-spec @ v0.3.0 | Released |

## Contributing

CRIT is developed in the open. Issues and PRs welcome at
[github.com/Vulnetix/ietf-crit-spec](https://github.com/Vulnetix/ietf-crit-spec).
For real-time discussion join the
[Vulnetix Discord](https://discord.gg/vulnetix).
