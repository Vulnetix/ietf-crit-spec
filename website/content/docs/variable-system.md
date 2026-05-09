---
title: Variable System (Template Slots)
weight: 5
---

A CRIT `template` is a provider identifier with zero or more **slots**.
Each slot is one of four normative states. The choice of state is
**not** determined by what the consumer happens to know — it is
determined by the semantics of the field for the given resource type.

## Slot syntax

```
arn:aws:eks:{region}:{account}:cluster/{resource-id}
```

The three `{…}` fragments above are slots. A consumer resolving this
template against its inventory substitutes concrete values per the
[resolution rules](../resolution/).

## The four slot states

### 1. Named variable — `{field}`

The slot represents a value the consumer **MUST** supply at
resolution time. A consumer **MUST NOT** assume any default; the
slot is empty until substituted.

```
arn:aws:ec2:{region}:{account}:instance/{resource-id}
```

Examples: `{region}`, `{account}`, `{resource-id}`,
`{cluster-name}`, `{database-id}`.

### 2. Wildcard — `{field=*}`

The slot represents "any value" — used when a fix applies to every
instance of a resource class regardless of identity. A consumer
**MUST NOT** resolve a wildcard template to a live provider
identifier; for inventory enumeration a consumer **MAY** expand the
wildcard to the set of known values.

```
arn:aws:eks:{region=*}:{account=*}:cluster/{resource-id=*}
```

Common when the vuln applies provider-wide (e.g. a control-plane
fix). Wildcards carry a security caveat — see
[Security Considerations](../security-considerations/).

### 3. Empty — `{field=}`

The slot is intentionally empty. Used when a provider identifier
doesn't include a region segment, or when an account-id slot is
not applicable for cross-account-managed resources.

```
arn:aws:s3:{region=}:{account=}:bucket/{resource-id}
```

A consumer substitutes the empty string; the surrounding literal
characters (e.g. `:` separators) remain.

### 4. Hardcoded — `{field=literal}`

The slot has a producer-required literal value that **MUST NOT** be
substituted with anything else. Used when the spec dictionary
mandates a specific value (AWS region hardcoding for global
services, for example).

```
arn:aws:iam:{region=}:{account}:role/{resource-id}
```

(`region=` here is the empty form, since IAM is global; a
hypothetical `{partition=aws}` would be the hardcoded form.)

## Slot selection rules (producer side)

A producer authoring a template **MUST** pick the slot state per
the field's semantics, not per producer convenience:

- If the field is **always** a fixed value for this resource type →
  hardcoded.
- If the field is **never present** in the canonical identifier for
  this resource type → empty.
- If the fix applies regardless of the field's value → wildcard.
- Otherwise → named.

Conformance: see [Producer Conformance](../conformance/).

## Why state matters

The state determines:

- Whether the consumer needs to ask the operator for a value
  (named only).
- Whether the template can be used as a live API identifier
  (named or hardcoded only after substitution).
- Whether the template represents an enumeration vs a single target
  (wildcard implies enumeration).

A spec-conforming validator checks slot syntax in the template and
cross-checks against the dictionary's `template` shape. The
[in-browser validator](../../validator/) surfaces malformed slots
as `template_format` errors.
