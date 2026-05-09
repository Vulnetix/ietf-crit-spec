---
title: Detections
weight: 9
---

`detections[]` is an array of phase-tagged queries a consumer can
deploy to find affected resources, exploitation attempts, or
configuration drift. Detection metadata is normative — `detection_phase`
in particular tells consumers when a query becomes applicable and
whether to retire it after remediation.

## Detection object

```json
{
  "provider": "aws",
  "service": "eks",
  "query_language": "cwli",
  "query": "fields @timestamp, @message | filter eventName = \"...\"",
  "detection_phase": "pre_fix",
  "description": "Detects EKS clusters running platform versions older than the runc-fix release.",
  "pending_reason": ""
}
```

| Field | Required | Notes |
|---|---|---|
| `provider`, `service` | yes | Match the record's natural key. |
| `query_language` | yes | Empty string allowed when `pending_reason` is set. |
| `query` | yes | Empty string allowed when `pending_reason` is set. |
| `detection_phase` | yes | One of `pre_fix`, `exploitation`, `post_fix`, `misconfiguration`. |
| `description` | yes | Human-readable explanation of what the query catches. |
| `pending_reason` | no | Required when `query` is empty. |

## Detection phase

The phase tells the consumer **when** the query is applicable and
**whether to retire it** after remediation.

| Phase | Detects | Retention |
|---|---|---|
| `pre_fix` | The vulnerable condition itself. | Deactivate or suppress per-resource after remediation is confirmed. May produce misleading results post-fix. |
| `exploitation` | Active exploitation attempts (regardless of fix status). | **MUST** remain active permanently. |
| `post_fix` | Exploitation attempts that remain possible after apparent remediation (e.g. credential reuse from before the rotation). | Activate at `provider_fix_date`; retain permanently. |
| `misconfiguration` | Drift back to a vulnerable state after remediation. A confirmed match is a **window-reopening event** ([Exposure Window](../exposure-window/)). | **MUST** remain active indefinitely after any `opt_in` or `config_change` remediation. |

## When detections are mandatory

A record where `fix_propagation` is `opt_in` or `config_change`
**MUST** include at least one `misconfiguration`-phase detection.
This is non-negotiable: those propagation modes require the
consumer to keep watching for drift, and the spec carries the
detection forward as part of the record so consumers don't have to
re-author it.

A record with `vex_status ∈ {affected, fixed}` **SHOULD** include
at least one detection (any phase).

## Pending detections

When a producer can't author a functional query at publication
time — a detection-surface gap, query in development, awaiting
provider telemetry — the spec **MUST** still include a detection
entry. The `query` is empty, `pending_reason` carries the cause:

| `pending_reason` | Meaning |
|---|---|
| `query_in_development` | Query is being authored or tested; future record update will replace it. |
| `awaiting_provider_telemetry` | Cloud provider doesn't yet expose the data needed. Pending provider capability. |
| `no_detection_surface` | No provider service offers sufficient telemetry today. Permanent / long-term gap. |
| `access_constraint` | Record author lacks the provider environment access to develop the query. |
| `pending_review` | Candidate query exists but is under security/accuracy review. |

A consumer **MUST NOT** deploy a detection that has `pending_reason`
set. A consumer **SHOULD** surface placeholders in operator-facing
dashboards as **detection coverage gaps**, not "no detection
needed".

## Query languages

| Value | Language |
|---|---|
| `cwli` | CloudWatch Logs Insights |
| `cloudwatch_filter` | CloudWatch Metric Filter pattern syntax |
| `kql` | Kusto Query Language (Azure Monitor + Sentinel) |
| `gcp_logging_filter` | GCP Cloud Logging filter syntax |
| `oci_logging_query` | OCI Logging query syntax |
| `lucene` | Lucene query syntax (Cloudflare + SIEM) |

Empty string is permitted when `pending_reason` is set.

## Slot substitution in queries

If a `query` body contains `{slot}` placeholders, a consumer
**SHOULD** substitute its named-variable values before deploying
the query — same rules as [template slot resolution](../resolution/).
Hardcoded and empty slots in the query follow the same conventions
as in templates.
