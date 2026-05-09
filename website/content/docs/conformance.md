---
title: Conformance
weight: 10
---

The spec defines conformance for two roles: **producers** (parties
that author CRIT records) and **consumers** (tools that ingest CRIT
records and act on them). Each role has a set of MUSTs and SHOULDs.

## Producer conformance

A conformant CRIT producer **MUST**:

- Emit records that validate against `crit-record-v0.3.0.schema.json`.
- Enforce **natural key uniqueness**: no two records in a corpus
  share `(vuln_id, provider, service, resource_type)`.
- Apply [slot state selection rules](../variable-system/) — choose
  slot state by field semantics, not by what the producer happens
  to know.
- Apply AWS region-hardcoding rules per the spec's
  `pt-aws` guidance for global services.
- Set `existing_deployments_remain_vulnerable = false` **only** when
  `fix_propagation = automatic` AND `shared_responsibility = provider_only`.
- Set `existing_deployments_remain_vulnerable = true` whenever
  `provider_fix_version.auto_upgrade` is present and `false`.
- Set `fix_propagation = no_fix_available` and **omit** `provider_fix_date`
  when no fix exists.
- Include at least one `remediation_actions[]` entry for every
  record where `vex_status` is `affected` or `fixed`.
- Use **ISO 8601 full-date** format for all date fields.
- Include at least one `misconfiguration`-phase detection for
  records where `fix_propagation` is `opt_in` or `config_change`.
  A placeholder entry with `pending_reason` satisfies this rule —
  see [Detections](../detections/).
- Compute `vectorString` as the canonical CRIT vector string from
  the record's own fields.
- Encode `temporal.vuln_published_date` as `PP` (Unix epoch seconds, UTC).
- Encode `temporal.service_available_date` as `SA` (Unix epoch seconds, UTC).

A conformant CRIT producer **SHOULD**:

- Include at least one detection entry for `vex_status ∈ {affected, fixed}` records.
- Populate `provider_advisory` when a vendor security bulletin exists.
- Populate `vulnerability_introduced_date` when determinable; set
  `vulnerability_introduced_date_estimated = true` for estimates.

## Consumer conformance

A conformant CRIT consumer **MUST**:

- Treat `provider_fix_date` as closing the exposure window **only
  when** `existing_deployments_remain_vulnerable = false`.
- **Not** substitute hardcoded slot values with alternative values.
- **Not** use wildcard templates as live provider API identifiers.
- Track per-resource remediation events separately from
  record-level `vex_status` — the record speaks for the CVE, not for
  any specific resource.
- Treat a `misconfiguration`-phase detection match as a
  **window-reopening event** ([Exposure Window](../exposure-window/)).
- Keep `misconfiguration`-phase detections active **indefinitely**
  once deployed.
- Use channel-specific fix dates for `comparison: channel_and_gte`
  version types when per-resource channel enrollment is known.
- Prefer `image_digest` over `image_tag` for `container_image`
  comparison when both are present (tags are mutable).
- **Ignore unknown metric keys** in a `vectorString` without
  failing — forward compatibility.
- **Reject** a `vectorString` missing any registered metric.
- Not treat `vectorString` as a complete record representation —
  use the full JSON for operational decisions that need fields the
  vector doesn't carry (remediation actions, detections, etc.).

A conformant CRIT consumer **SHOULD**:

- Present `remediation_actions[]` in declared `sequence` order.
- Substitute consumer-specific named-slot values into detection
  query slots before deploying queries.
- Apply `temporal.customer_deadline_date` when computing remediation SLAs.
- Surface `vulnerability_introduced_date_estimated = true` in
  operator-facing exposure-window reporting.

## How to test conformance

- **Schema** — run records through the
  [in-browser validator](../../validator/) or the reference
  `cmd/crit-validate` tool. Both check the record schema, vector
  round-trip, dictionary resolution, and the cross-field MUST rules
  enumerated above.
- **Conformance suite** — `tests/cmd/crit-test` in the spec repo
  runs sample envelopes through every MUST + SHOULD rule and
  produces `tests/reports/crit-test-report.md`. Producers can run
  the same suite locally as a CI gate.

A failing MUST is a hard reject (publish-time rejection in the
publisher pipeline). A failing SHOULD is a warning surfaced to
reviewers but doesn't block publication.
