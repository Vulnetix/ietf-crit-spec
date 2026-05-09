---
title: Provider Fix Version
weight: 8
---

Cloud resources don't use package-style versioning. There's no
semver string to compare, no registry entry to look up, and no
universal version format that applies across providers — even within
a single provider. "Version" might be a Lambda runtime string, an
RDS engine version, a Kubernetes minor inside a release channel, a
container-image SHA, or a platform image creation date.

`provider_fix_version` is a **discriminated object** whose structure
is determined by the `version_type` discriminator. Each value
defines its own field set and a `comparison` operator that gives a
consumer everything needed to decide whether a deployed resource
meets the fix threshold.

## Envelope

| Field | Required | Description |
|---|---|---|
| `version_type` | yes | Discriminator. Determines which additional fields are present. |
| `comparison` | yes | How a consumer evaluates whether a deployed resource meets the threshold. |
| `auto_upgrade` | no | When `false`, the provider does **not** automatically apply this update. When `false`, `existing_deployments_remain_vulnerable` MUST be `true`. |
| `note` | no | Human-readable clarification. **Required** when a fix arrives at different dates across release channels. |

## Comparison operators

| Value | Meaning |
|---|---|
| `gte` | Deployed version ≥ declared version. Standard for monotonic version strings. |
| `exact` | Deployed version = declared version. Standard for content-addressed identifiers (image digests). |
| `channel_and_gte` | Deployed channel matches the declared channel AND deployed version within that channel ≥ declared. Used for staggered-channel rollouts (EKS standard/extended, AKS LTS, etc.). |
| `build_date_gte` | Deployed build/creation date ≥ declared date. For artefacts without a comparable version string (Cloudflare Workers, Lambda runtime build dates). |

## Per-provider version_type values

Per the spec dictionary; this list is non-exhaustive — a producer
**MAY** introduce additional values when the spec doesn't cover a
service shape, with a note explaining the discriminator semantics.

### AWS

| `version_type` | When to use |
|---|---|
| `runtime` | Lambda + runtime-based services (Lambda layers, App Runner). |
| `engine_version` | RDS, ElastiCache, Redshift. `auto_upgrade` indicates whether RDS auto-minor-version-upgrade is sufficient. |
| `ami` | EC2 + AMI-backed services. |
| `agent_version` | SSM Agent, CodeDeploy Agent, ECS Agent. |
| `kubernetes_version` | EKS. Pair with `comparison: channel_and_gte` for the EKS standard/extended split. |
| `container_image` | ECS tasks, Fargate. `image_digest` (SHA256) **RECOMMENDED** over `image_tag` — tags are mutable and **MUST NOT** be the sole verification method. |
| `managed_policy_version` | AWS-managed IAM policies. |

### Azure

| `version_type` | When to use |
|---|---|
| `api_version` | ARM API operations. |
| `kubernetes_version` | AKS clusters and node pools. Optional `node_image_version` for node-pool-level granularity. |
| `extension_version` | VM Extensions. |
| `os_image_version` | VM Scale Sets. |
| `runtime_version` | App Service, Azure Functions. |

### GCP

`engine_version`, `kubernetes_version` (GKE — `channel_and_gte`
for the GKE Rapid/Regular/Stable split), `runtime_version` (Cloud
Run, Cloud Functions), `os_image` (Compute Engine images),
`container_image` (Cloud Run, GKE).

### Cloudflare

`build_date_gte` is the dominant pattern — Workers and Pages don't
expose consumer-visible versions, only platform build dates.

### Oracle

`db_version` (Autonomous Database, MySQL HeatWave),
`engine_version` (BaseDB), `kubernetes_version` (OKE),
`shape_version` (Compute platforms).

## Examples

### EKS Kubernetes channel + version

```json
{
  "provider_fix_version": {
    "version_type": "kubernetes_version",
    "comparison": "channel_and_gte",
    "channel": "standard",
    "version": "1.28",
    "note": "EKS platform versions released after 2024-02-05 include containerd >= 1.7.13 with runc >= 1.1.12. Node groups must be updated independently."
  }
}
```

### ECS task with image digest

```json
{
  "provider_fix_version": {
    "version_type": "container_image",
    "comparison": "exact",
    "image_digest": "sha256:abc123…",
    "auto_upgrade": false
  }
}
```

`auto_upgrade: false` here forces
`existing_deployments_remain_vulnerable: true` per the conformance
rule — and the AWS-specific guidance applies: prefer `image_digest`
over `image_tag` because tags are mutable.

### RDS auto-minor-version

```json
{
  "provider_fix_version": {
    "version_type": "engine_version",
    "comparison": "gte",
    "engine": "postgres",
    "version": "14.11",
    "auto_upgrade": true
  }
}
```

`auto_upgrade: true` means RDS will lift the database to ≥14.11
during its maintenance window without customer action — `existing_
deployments_remain_vulnerable` is `false`.

## Conformance

Producers **MUST** set `auto_upgrade: false` whenever
`existing_deployments_remain_vulnerable` is `true` for that record;
the two flags are coupled. Consumers **MUST** prefer `image_digest`
over `image_tag` for `container_image` comparison when both are
present.
