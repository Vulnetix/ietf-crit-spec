---
title: Vector String
weight: 2
---

The CRIT vector string is a CVSS-style compact encoding of a record's
classification + identity fields. It is **deterministic** — given the
same structured fields, the encoder always produces the same string
and the parser is the inverse.

## Format

```
CRITv<semver>/<metric>:<value>[/...]#<vuln_id>:<service>:<resource_type>
```

Sample:

```
CRITv0.3.0/CP:AW/VS:FX/FP:RR/SR:SH/RL:SM/EV:T/PP:1719792000/SA:1514764800#CVE-2024-21626:eks:cluster
```

## Metric keys

The eight registered keys, in canonical order:

| Key | Field |
|---|---|
| `CP` | `provider` |
| `VS` | `vex_status` |
| `FP` | `fix_propagation` |
| `SR` | `shared_responsibility` |
| `RL` | `resource_lifecycle` |
| `EV` | `existing_deployments_remain_vulnerable` |
| `PP` | `vuln_published_date` (epoch seconds) |
| `SA` | `service_available_date` (epoch seconds) |

After the `#`: three positional colon-separated values —
`vuln_id`, `service`, `resource_type` — exactly mirroring the
record's natural key.

## Code → value tables

### `CP` — provider

| Code | Provider |
|---|---|
| `AW` | aws |
| `MA` | azure (Microsoft Azure) |
| `GC` | gcp |
| `CF` | cloudflare |
| `OC` | oracle (Oracle Cloud) |
| `SF` | salesforce |
| `SP` | sap |
| `SN` | servicenow |
| `IB` | ibm |
| `VM` | vmware |
| `AD` | adobe |
| `AK` | akamai |
| `AL` | alibaba |
| `AT` | atlassian |
| `DO` | digitalocean |
| `EL` | elastic |
| `FA` | fastly |
| `GL` | gitlab |
| `HC` | hashicorp |
| `HE` | hetzner |
| `LI` | linode |
| `MO` | mongodb |
| `OV` | ovh |
| `SO` | snowflake |
| `TS` | tailscale |
| `TC` | tencent |
| `TW` | twilio |
| `VC` | vercel |
| `VL` | vultr |
| `ZM` | zoom |

### `VS` — vex_status

| Code | Value | Meaning |
|---|---|---|
| `AF` | `affected` | The product is known to be affected by the CVE; no fix is yet available or applicable. |
| `FX` | `fixed` | A fix is available; `temporal.provider_fix_date` MUST be set. |
| `NA` | `not_affected` | The product is confirmed unaffected (typically because the vulnerable code path is unreachable or the resource type doesn't expose it). |
| `UI` | `under_investigation` | The producer has not yet determined affectedness. |

### `FP` — fix_propagation

| Code | Value | Meaning |
|---|---|---|
| `AU` | `automatic` | Provider deploys the fix; customer takes no action. |
| `CC` | `config_change` | Customer applies a configuration change (toggle, policy edit, IAM update) without redeploying compute. |
| `OI` | `opt_in` | Provider has shipped the fix but customers must explicitly opt in (e.g. enable a feature flag, switch channel). |
| `VU` | `version_update` | Customer upgrades the resource to a fixed version (kernel, agent, runtime, image tag). |
| `RD` | `redeploy` | Customer redeploys the resource without a version change (e.g. restart to pick up rotated keys). |
| `RR` | `rebuild_and_redeploy` | Customer rebuilds the resource from a fresh image / template AND redeploys. |
| `DC` | `destroy_recreate` | Customer destroys the resource and recreates it (state-impacting). |
| `RL` | `rolling_replace` | Provider or customer performs a rolling replacement across instances/nodes. |
| `NF` | `no_fix_available` | No fix exists; mitigation only. |

### `SR` — shared_responsibility

| Code | Value | Meaning |
|---|---|---|
| `PO` | `provider_only` | Provider owns the fix entirely; customer has nothing to do. |
| `CA` | `customer_action_required` | Customer must take action; the provider may have shipped the fix but customer-side adoption is required. |
| `CO` | `customer_only` | Provider has no role; the fix is entirely customer-owned (e.g. customer-installed software on a generic compute resource). |
| `SH` | `shared` | Both provider and customer must act. Common for managed-Kubernetes node pools, agent-based services, etc. |

### `RL` — resource_lifecycle

| Code | Value | Meaning |
|---|---|---|
| `EP` | `ephemeral` | Resources are short-lived (function invocations, container tasks, build runs); fixed-by-replacement on next launch. |
| `SM` | `stateful_managed` | Long-lived resources whose lifecycle the provider manages (managed databases, managed Kubernetes clusters); customer state survives provider-driven upgrades. |
| `SC` | `stateful_customer` | Long-lived resources the customer manages directly (VMs, dedicated servers, on-prem clusters); upgrades require customer action. |
| `CF` | `config_only` | The "resource" is a configuration object (DNS zone, WAF policy) with no compute backing; fix is a config edit. |
| `GC` | `global_control_plane` | Provider-wide control planes (IAM, KMS, billing, monitoring); fix lands once for everyone. |

### `EV` — existing_deployments_remain_vulnerable

| Code | Boolean | Meaning |
|---|---|---|
| `T` | `true` | Existing deployments stay vulnerable until the customer takes the remediation action. |
| `F` | `false` | The fix lands transparently and existing deployments are immediately covered. |

### `PP`, `SA` — temporal epochs

Both are int64 Unix-epoch seconds (UTC). Encoded as the integer
literal in the metric segment.

| Vector field | Record field |
|---|---|
| `PP` | `temporal.vuln_published_date` (parsed `YYYY-MM-DD` → epoch) |
| `SA` | `temporal.service_available_date` (parsed `YYYY-MM-DD` → epoch) |

A producer that lacks one of these dates SHOULD encode `0`; the
parser surfaces a `temporal_*_zero` warning so reviewers can
backfill.

## Round-trip rule

Every record's `vectorString` MUST be byte-equal to
`ComputeVector(parsed_fields)`. The validator runs this check by
parsing the vector, recomputing it from the structured fields, and
comparing strings. A mismatch is a reject-at-publish-time hard
failure.

## Why bother with a vector?

- **Compact wire format** — fits in CVE.org adp.metrics, in a Slack
  paste, in a header.
- **Signable** — short enough for a human to verify a hash; useful
  for chain-of-custody on advisories.
- **Greppable** — `CRITv0.3.0/CP:AW/.../#CVE-2024-` is a stable token
  for log/feed pipelines.
- **Versioned** — `CRITv<semver>` lets parsers reject vectors from a
  spec version they don't understand.

## Implementations

- **Go**: `github.com/Vulnetix/ietf-crit-spec.ComputeVector` /
  `ParseVector` / `ValidateVectorRoundTrip`.
- **JavaScript**: bundled in this site's
  [validator](../../validator/) — port of the Go reference. No deps.
