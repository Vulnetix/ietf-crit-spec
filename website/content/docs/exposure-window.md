---
title: Exposure Window
weight: 6
---

The **exposure window** is the interval during which a specific cloud
resource is in a vulnerable configuration. CRIT defines it formally
because, unlike package vulnerabilities, cloud resources have no
"installed version" to compare against a fixed bound — there is no
registry timestamp recording when a running EKS cluster was last
upgraded, and `provider_fix_date` does not by itself close the window
for any resource that already exists.

## Formal definition

The exposure window is the closed interval `[W_start, W_end]`.

### W_start

| Condition | W_start |
|---|---|
| `temporal.vulnerability_introduced_date` is present | use it (this is the canonical answer) |
| Otherwise | `temporal.vuln_published_date` |

When `vulnerability_introduced_date_estimated` is `true`, consumers
**SHOULD** indicate this in user-facing reporting so reviewers know
the start bound is approximate.

### W_end (record level)

`W_end` is computed at the **record** level from the producer's
classification fields. Per-resource adjustments come on top — see
[Per-resource](#per-resource) below.

| Record-level condition | W_end |
|---|---|
| `shared_responsibility = provider_only` AND `provider_fix_date` is present | `W_end = provider_fix_date`; window closed for **all** resources automatically. `existing_deployments_remain_vulnerable` MUST be `false`. |
| `shared_responsibility ∈ {customer_action_required, shared}` | undefined at record level. `provider_fix_date` opens remediation possibility but does not close the window. |
| `shared_responsibility = customer_only` | undefined. No `provider_fix_date`. |
| `fix_propagation = no_fix_available` | `W_end = null` (open). `provider_fix_date` MUST be absent. |
| `provider_fix_date` absent for any other reason | `W_end = null` (open). |

## Per-resource

When `existing_deployments_remain_vulnerable` is `true`, the
exposure window for a specific resource instance is **NOT** closed
by `provider_fix_date`. A consumer **MUST** apply per-resource
logic:

```
if resource.deployed_date < provider_fix_date
   AND existing_deployments_remain_vulnerable == true
   AND no confirmed remediation action recorded for this resource:
     resource.exposure_window_end = null  // open
```

A consumer **MUST** record a per-resource remediation event to close
the window for that resource. A consumer **MUST NOT** mark a
resource as remediated solely because `provider_fix_date` has
passed.

## Drift, rolling updates, channels

Three special cases the spec calls out:

- **Drift** — a resource that was remediated but whose configuration
  has drifted back to a vulnerable state. A `misconfiguration`-phase
  detection match is a **window-reopening event** (see
  [Detections](../detections/)). Consumers **MUST** treat it as such.
- **Rolling replacement** — for `fix_propagation = rolling_replace`,
  per-instance remediation completes at different times. Consumers
  track per-instance W_end, not a single record-level W_end.
- **Release channels** — for `comparison: channel_and_gte` (see
  [Provider Fix Version](../provider-fix-version/)), `W_end`
  depends on the resource's enrolled channel. A `note` field on
  `provider_fix_version` is **REQUIRED** when fix dates differ
  across channels.

## Why model the window?

SLA computation, breach windows for compliance audits, MTTR
reporting, and exploit-risk dashboards all need W_start and W_end
per-resource — not per-CVE. The CRIT exposure window is the
narrowest time-bound that lets a consumer answer "was this resource
exposed?" without reading the CVE prose.
