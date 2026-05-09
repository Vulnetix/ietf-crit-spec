---
title: Resolution
weight: 7
---

How a consumer turns a CRIT `template` into a live provider
identifier (or an inventory query). Two layers of resolution apply:
**dictionary** resolution (which template do I use?) and **slot**
resolution (what values do I substitute?).

## Dictionary resolution

A consumer maps a record's natural key
`(provider, service, resource_type)` to a dictionary entry. The
spec defines a layered registry:

1. **Spec dictionary** — shipped in `ietf-crit-spec.embed.FS Dictionaries`.
   Authoritative for the providers and services it covers.
2. **Custom dictionary** — embedded in the record envelope when
   the producer needs a one-off entry not in spec. Validated
   against `crit-dictionary-v0.3.0.schema.json`.
3. **Local layer** — downstream consumer's own override layer
   (vdb-manager uses one for a small Azure / Cloudflare / Oracle
   slot residue not in spec yet).

A consumer **MUST** check the layers in order and take the first
hit. A custom dictionary entry overrides the spec; a local entry
overrides both.

If no entry resolves, the consumer **MUST** reject the record —
unresolvable natural keys cannot become live identifiers.

## Slot resolution order

Once a template is selected, slot substitution proceeds in this
exact order:

1. **Hardcoded slots** (`{field=literal}`) → replaced with the
   literal value. Consumers **MUST NOT** substitute alternatives.
2. **Empty slots** (`{field=}`) → replaced with the empty string.
3. **Named slots** (`{field}`) → replaced with consumer-supplied
   concrete values.
4. **Wildcard slots** (`{field=*}`) → **MUST NOT** be resolved to a
   live identifier. For inventory enumeration a consumer **MAY**
   expand a wildcard into the set of known values.

After step 3, the resulting string **MUST** be a valid identifier
conforming to the declared `template_format`. A consumer **MUST**
validate this (e.g. AWS ARN regex) and **MUST** reject a template
that fails post-substitution validation.

## Field resolution (per-record fields)

Beyond template slots, several **record fields** themselves resolve
per-consumer:

| Field | Resolution |
|---|---|
| `temporal.customer_deadline_date` | Compute SLAs against this when present. |
| `temporal.customer_deadline_source` | Identifies the policy regime — `cisa_kev`, `pci_dss`, `hipaa`, `sox`, `internal_policy`, or `other`. Required when `customer_deadline_date` is present. |
| `provider_fix_version.comparison` | Per-resource version comparison — see [Provider Fix Version](../provider-fix-version/). |
| `detections[*].query` | For named detection languages (e.g. `cwli`, `kql`), substitute the consumer's named-slot values into query placeholders before deploying. |

## Worked example

Record:

```json
{
  "provider": "aws",
  "service": "eks",
  "resource_type": "cluster",
  "template": "arn:aws:eks:{region}:{account}:cluster/{resource-id}",
  "template_format": "aws_arn"
}
```

Consumer-supplied values:

```
region      = us-east-1
account     = 123456789012
resource-id = production-eks-cluster
```

Resolved:

```
arn:aws:eks:us-east-1:123456789012:cluster/production-eks-cluster
```

The resolved string passes AWS-ARN format validation
(`arn:aws:<service>:<region>:<account-id>:<resource>`) so the
consumer **MAY** use it as a live API identifier (e.g. pass it to
`eks:DescribeCluster`).
