---
title: Security Considerations
weight: 12
---

CRIT carries operational signal that informs remediation decisions.
The same signal can mislead consumers if mis-modelled, mis-merged,
or mis-displayed. The IETF draft enumerates six classes of concern
that producers and consumers **MUST** account for.

## 1. Detection retention and drift

A consumer **MUST** keep `misconfiguration`-phase detections active
**indefinitely** once deployed — not just until the record's
`vex_status` flips to `fixed`. The drift those detections catch is
exactly the kind of regression a remediation event hides from
record-level state.

A confirmed `misconfiguration` match is a
[window-reopening event](../exposure-window/). Treat it the same as
the original publication date for SLA purposes for that resource.

## 2. Window mis-attribution

Treating `provider_fix_date` as the window-close timestamp is the
single most common mistake. It's only correct when:

- `shared_responsibility = provider_only` AND
- `existing_deployments_remain_vulnerable = false`

Outside that case, **per-resource remediation events** close the
window. A consumer that auto-closes records on `provider_fix_date`
will under-report exposure on every `customer_action_required` /
`shared` record.

See [Exposure Window](../exposure-window/) for the formal table.

## 3. Compensating controls

`remediation_actions[].compensating_control = true` indicates a
mitigation that **doesn't** restore the resource to a non-vulnerable
state — it lowers exploitation likelihood (e.g. an IP allowlist on
top of an unpatched service). Consumers **MUST NOT** treat a
compensating control as closing the exposure window. Display it as
a **risk-reducing measure**, not a remediation.

## 4. Wildcard enumeration

Wildcard templates (`{field=*}`) reveal the structural scope of a
consumer's cloud footprint. A consumer **MUST NOT** expose
unresolved wildcard templates in contexts where asset enumeration
is harmful — public dashboards, customer-shared reports, audit
exports for downstream parties, etc.

The hazard is that the wildcard tells the world "this entire class
of resource may be affected"; expanding it locally for inventory
comparison is fine, leaking it externally is not.

## 5. Version-string trust

Container image **tags** are mutable. A consumer that compares
`container_image` versions by tag alone can be fooled by a re-pushed
upstream tag that no longer matches the producer's intent.

Resolution rule (also enforced by [Provider Fix Version](../provider-fix-version/)):

- When `image_digest` is present, **MUST** verify by digest, not tag.
- When only `image_tag` is present, surface this as a confidence-
  reduction signal in operator-facing displays.

The same caveat applies to mutable platform images (AWS AMI alias
references, Azure image gallery `latest` tags) — pin to immutable
identifiers wherever the format allows.

## 6. Natural-key collision

A producer accepting CRIT records from multiple upstream sources
**MUST** enforce natural-key uniqueness before serving records.
Duplicate `(vuln_id, provider, service, resource_type)` tuples with
conflicting field values (different `fix_propagation`, different
`temporal.provider_fix_date`, etc.) cause consumers to make
incorrect remediation decisions.

Producers **SHOULD** define and expose a conflict-resolution
policy. The Vulnetix VDB pipeline's policy is documented in the
publisher: the most recent `generatedAt` wins; older records move
to `superseded/` for audit. Other producers are free to pick a
different rule, but the policy **MUST** be deterministic.

## Summary table

| Risk | Mitigation |
|---|---|
| Drift after remediation | Keep `misconfiguration` detections active indefinitely. |
| Premature window close | Track per-resource remediation events; only auto-close when `provider_only` + `existing_deployments_remain_vulnerable=false`. |
| Compensating control mistaken for fix | Don't close the window on compensating controls; display them as risk-reducing measures. |
| Wildcard leak | Don't expose unresolved wildcards externally. |
| Mutable image tag spoof | Verify by `image_digest` whenever present. |
| Natural-key collision | Producer enforces uniqueness with a deterministic conflict policy. |

A spec-conforming consumer's threat model assumes adversarial input
on every one of these axes. The validator surfaces the corresponding
warnings — but the operational behaviour is the consumer's
responsibility, not the validator's.
