---
title: Provider Dictionaries
weight: 3
---

A dictionary binds a `(provider, service, resource_type)` tuple to:

- a `template` URL/ARN/locator with `{slot}` placeholders
- a `template_format` (e.g. `aws_arn`, `azure_resource_id`,
  `cloudflare_locator`, `oracle_ocid`)
- an optional `region_behavior` (`regional`, `global-only`, etc.)

Every CRIT record's natural key MUST resolve in some dictionary
layer; the validator rejects records that don't.

## Layered resolution

CRIT consumers stack three layers:

1. **Spec dictionary** — shipped in the spec library
   (`embed.FS Dictionaries`); covers AWS / Azure / GCP / Cloudflare /
   Oracle / Salesforce / SAP / ServiceNow plus 22 extended providers
   added in v0.3.0.
2. **Custom dictionary** — embedded in a CRIT envelope when a
   producer needs a one-off entry not in the spec or extended
   layers. Validated against `crit-dictionary-v0.3.0.schema.json`.
3. **Local layer** (downstream consumers only) — vendor-specific
   overrides that haven't been upstreamed. Used by vdb-manager for a
   small Azure/Cloudflare/Oracle slot residue not in the spec.

## Spec coverage (v0.3.0)

Tier-1 (always-in-spec, primary cloud providers):
**AWS, Azure, GCP, Cloudflare, Oracle, Salesforce, SAP, ServiceNow.**

Extended (Tier-2/3 providers absorbed in v0.3.0):
**Adobe, Akamai, Alibaba, Atlassian, DigitalOcean, Elastic, Fastly,
GitLab, HashiCorp, Hetzner, IBM, Linode, MongoDB, OVH, Snowflake,
Tailscale, Tencent, Twilio, Vercel, VMware, Vultr, Zoom.**

## Authoring a new dictionary

A dictionary file is a single JSON object:

```json
{
  "dictionary_version": "0.3.0",
  "provider": "myprovider",
  "entries": [
    {
      "service": "compute",
      "resource_type": "instance",
      "template": "https://api.myprovider.example/v1/compute/{instance-id}",
      "template_format": "myprovider_url",
      "region_behavior": "regional"
    }
  ]
}
```

Validate it via the [in-browser validator](../../validator/) before
opening a PR against
[ietf-crit-spec/dictionaries/](https://github.com/Vulnetix/ietf-crit-spec/tree/main/dictionaries).

## Custom dictionaries (per-record)

When a CRIT record needs a `(provider, service, resource_type)` not
in the spec layer, the producer embeds a `custom_dictionary` in the
envelope. The publisher revalidates against the spec schema before
upserting. See the validator's "envelope" mode for an example.
