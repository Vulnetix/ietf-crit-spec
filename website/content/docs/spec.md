---
title: Spec Overview
weight: 1
---

A CRIT record is a JSON object that ties a single CVE to a single
**cloud resource template**, with the lifecycle and remediation
metadata an operator needs to act on it.

## Identity fields

| Field | Required | Notes |
|---|---|---|
| `vectorString` | yes | Canonical CVSS-style encoding of the other identity fields. Always recomputable from the structured fields; reviewers verify by round-trip. |
| `vuln_id` | yes | CVE-YYYY-NNNN, GHSA-xxxx, or vendor-issued bulletin ID (HCSEC-YYYY-NN, ALAS-YYYY-NNNN, etc.). |
| `provider` | yes | Spec-registered cloud provider (`aws`, `azure`, `gcp`, …). |
| `service` | yes | Provider-namespaced service slug (`ec2`, `eks`, `kubernetes_service`, …). |
| `resource_type` | yes | `instance`, `cluster`, `bucket`, `function`, etc. |

## Classification fields

| Field | Allowed values |
|---|---|
| `resource_lifecycle` | `ephemeral`, `stateful_managed`, `stateful_customer`, `config_only`, `global_control_plane` |
| `shared_responsibility` | `provider_only`, `customer_action_required`, `customer_only`, `shared` |
| `vex_status` | `affected`, `fixed`, `not_affected`, `under_investigation` |
| `fix_propagation` | `automatic`, `config_change`, `opt_in`, `version_update`, `redeploy`, `rebuild_and_redeploy`, `destroy_recreate`, `rolling_replace`, `no_fix_available` |
| `existing_deployments_remain_vulnerable` | boolean |

## Template fields

| Field | Notes |
|---|---|
| `template` | Resource locator with `{slot}` placeholders. Example: `arn:aws:eks:{region}:{account}:cluster/{resource-id}`. |
| `template_format` | `aws_arn`, `azure_resource_id`, `gcp_resource_name`, `cloudflare_locator`, `oracle_ocid`, plus per-provider extended formats. |

## Temporal fields

`temporal` carries lifecycle dates as `YYYY-MM-DD` strings:

- `vuln_published_date` (required)
- `provider_acknowledged_date`
- `provider_fix_date` (required when `vex_status="fixed"`)
- `customer_deadline_date`
- `customer_deadline_source`
- `service_available_date` (required)

## Remediation + detection

- `remediation_actions` — ordered list of operator-actionable steps,
  each with `type`, `title`, `description`, `auto_remediable`,
  `requires_downtime`, `stateful_impact`, `compensating_control`.
- `detections` — phase-tagged queries (`pre_fix`, `misconfiguration`,
  `post_fix`) that consumers run to find affected resources.
  Empty `query` requires `pending_reason`.

## Schema

Every CRIT record validates against
[`crit-record-v0.3.0.schema.json`](https://github.com/Vulnetix/ietf-crit-spec/blob/main/schemas/crit-record-v0.3.0.schema.json).
The reference implementation embeds it; the
[in-browser validator](../../validator/) loads it client-side via fetch.
