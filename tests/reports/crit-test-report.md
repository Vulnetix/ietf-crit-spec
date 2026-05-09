---
title: CRIT Spec Conformance Report
date: 2026-05-09T03:06:51Z
verdict: WARN
total_checks: 80040
passed: 80027
failed: 0
warnings: 13
template_rules: 20
record_rules: 40
dictionaries: 30
samples: 3936
records: 33
---

# CRIT Spec Conformance Report

## Context

This report validates CRIT dictionary entries and sample records against [draft-vulnetix-crit-00](../drafts/draft-vulnetix-crit-00.xml).

**Date:** 2026-05-09 03:06:51 UTC  
**Verdict:** ⚠️ WARN  
**Total Checks:** 80040 | ✅ **Passed:** 80027 | ❌ **Failed:** 0 | ⚠️ **Warnings:** 13  

| Provider | Dictionary Entries | Template Samples | Sample Records |
|----------|------------------:|----------------:|---------------:|
| AWS | 250 | 1250 | 11 |
| Azure | 88 | 440 | 8 |
| GCP | 77 | 385 | 5 |
| Cloudflare | 43 | 215 | 4 |
| Oracle | 67 | 335 | 5 |
| Salesforce | 64 | 303 | 0 |
| SAP | 79 | 330 | 0 |
| ServiceNow | 69 | 345 | 0 |
| **Total** | **737** | **3603** | **33** |

```mermaid
graph LR
    subgraph "Cloud Hyperscalers"
        aws["<b>AWS</b> 250 entries · 11 records"]
        azure["<b>Azure</b> 88 entries · 8 records"]
        gcp["<b>GCP</b> 77 entries · 5 records"]
    end
    subgraph "Network & CDN"
        cloudflare["<b>Cloudflare</b> 43 entries · 4 records"]
    end
    subgraph "Enterprise Software"
        oracle["<b>Oracle</b> 67 entries · 5 records"]
    end
    subgraph "Enterprise SaaS"
        salesforce["<b>Salesforce</b> 64 entries · 0 records"]
        sap["<b>SAP</b> 79 entries · 0 records"]
        servicenow["<b>ServiceNow</b> 69 entries · 0 records"]
    end
```

```mermaid
pie title "Dictionary Entries by Provider"
    "AWS (250)" : 250
    "Azure (88)" : 88
    "GCP (77)" : 77
    "Cloudflare (43)" : 43
    "Oracle (67)" : 67
    "Salesforce (64)" : 64
    "SAP (79)" : 79
    "ServiceNow (69)" : 69
```

## Summary

| Suite | Rules | Samples | Checks | ✅ Passed | ❌ Failed | ⚠️ Warnings |
|-------|------:|--------:|-------:|----------:|----------:|------------:|
| Template Rules | 20 | 3936 | 78720 | 78720 | 0 | 0 |
| Sample Record Rules | 40 | 33 | 1320 | 1307 | 0 | 13 |

```mermaid
pie title "Overall Results (80040 checks)"
    "✅ Passed (80027)" : 80027
    "⚠️ Warnings (13)" : 13
```

## AWS

> 250 dictionary entries · 1250 template samples · 11 sample records

### Template Rules

| Status | Sec | Rule | ✅ Pass | ❌ Fail | Requirement |
|:------:|:---:|------|-------:|-------:|-------------|
| ✅ | 3.2 | `slot-delimiter-not-in-literal` | 1250 | 0 | Characters { and } MUST NOT appear outside slot expressions |
| ✅ | 3.3.1 | `named-var-no-default` | 1250 | 0 | Named variable MUST NOT be treated as implying any default value |
| ✅ | 3.3.1 | `named-var-requires-substitution` | 1250 | 0 | Named variable MUST substitute concrete value before using template as live identifier |
| ✅ | 3.3.2 | `wildcard-not-live-identifier` | 1250 | 0 | Wildcard MUST NOT be used as live identifier against provider API |
| ✅ | 3.3.4 | `hardcoded-value-as-is` | 1250 | 0 | Consumer MUST use hardcoded value as-is; MUST NOT substitute alternative value |
| ✅ | 3.4 | `slot-state-precedence` | 1250 | 0 | Producer MUST select slot state according to precedence |
| ✅ | 3.4 | `wildcard-not-fallback` | 1250 | 0 | Producer MUST NOT use wildcard as fallback when correct state is unknown |
| ✅ | 3.2 | `template-produces-valid-id` | 1250 | 0 | Conformant CRIT template MUST produce valid identifier after variable resolution |
| ✅ | 6.1 | `aws-global-region-hardcoded` | 1250 | 0 | AWS global-only services: region MUST be hardcoded to us-east-1 or empty |
| ✅ | 6.1 | `aws-regional-region-variable` | 1250 | 0 | AWS regional services: region MUST be named variable or wildcard, MUST NOT be empty |
| ✅ | 6.4 | `cloudflare-no-region-slot` | 1250 | 0 | Producer MUST NOT add region slot to Cloudflare templates |
| ✅ | 7.1 | `resolution-produces-valid-id` | 1250 | 0 | After variable resolution, result MUST be valid provider identifier |
| ✅ | 7.2 | `reserved-field-names-used` | 1250 | 0 | Producer MUST use reserved field names where applicable |
| ✅ | 5 | `template-field-valid-after-resolution` | 1250 | 0 | After all named variables substituted, result MUST be valid provider identifier for declared template_format |
| ✅ | 12.2 | `dictionary-entry-required-fields` | 1250 | 0 | All fields except notes are REQUIRED in dictionary entry |
| ✅ | 12.1.1 | `dictionary-tuple-resolves` | 1250 | 0 | (provider, service, resource_type) tuple MUST resolve to entry in conformant dictionary |
| ✅ | 9.1 | `service-key-lowercase-underscore` | 1250 | 0 | service field MUST match pattern ^[a-z][a-z0-9_]*$ |
| ✅ | 9.1 | `resource-type-valid-pattern` | 1250 | 0 | resource_type MUST match pattern ^[a-zA-Z][a-zA-Z0-9_/-]*$ |
| ✅ | 9.1 | `template-format-matches-provider` | 1250 | 0 | template_format MUST match provider |
| ✅ | 3.2 | `slot-syntax-abnf-valid` | 1250 | 0 | All slots MUST conform to ABNF grammar: field-name = 1*(ALPHA / DIGIT / "-" / "_") |

### Sample Record Rules

| Status | Level | Sec | Rule | ✅ Pass | ❌ Fail | ⚠️ Warn | Requirement |
|:------:|:-----:|:---:|------|-------:|-------:|--------:|-------------|
| ✅ | MUST | 4.1 | `dates-iso8601-format` | 11 | 0 | 0 | All date fields in temporal MUST be ISO 8601 full-date (YYYY-MM-DD) |
| ✅ | MUST | 4.1 | `natural-key-fields-present` | 11 | 0 | 0 | vuln_id, provider, service, resource_type MUST all be non-empty |
| ✅ | MUST | 9.1 | `service-key-lowercase-underscore` | 11 | 0 | 0 | service MUST match ^[a-z][a-z0-9_]*$ |
| ✅ | MUST | 9.1 | `resource-type-valid-pattern` | 11 | 0 | 0 | resource_type MUST match ^[a-zA-Z][a-zA-Z0-9_/-]*$ |
| ✅ | MUST | 9.1 | `template-format-matches-provider` | 11 | 0 | 0 | template_format MUST match provider |
| ✅ | MUST | 3.2 | `slot-syntax-abnf-valid` | 11 | 0 | 0 | All slots MUST conform to ABNF grammar |
| ✅ | MUST | 3.2 | `slot-delimiter-not-in-literal` | 11 | 0 | 0 | { and } MUST NOT appear outside slot expressions |
| ✅ | MUST | 6.1 | `aws-global-region-hardcoded` | 11 | 0 | 0 | AWS global-only: region MUST be hardcoded to us-east-1 or empty |
| ✅ | MUST | 6.1 | `aws-regional-region-variable` | 11 | 0 | 0 | AWS regional: region MUST be named-variable, MUST NOT be empty |
| ✅ | MUST | 6.4 | `cloudflare-no-region-slot` | 11 | 0 | 0 | Cloudflare templates MUST NOT have region slot |
| ✅ | MUST | 12.1.1 | `dictionary-tuple-resolves` | 11 | 0 | 0 | (provider, service, resource_type) MUST resolve in dictionary |
| ✅ | MUST | 4.3 | `customer-deadline-source-required` | 11 | 0 | 0 | customer_deadline_source REQUIRED when customer_deadline_date present |
| ✅ | MUST | 4.3 | `introduced-not-after-published` | 11 | 0 | 0 | vulnerability_introduced_date MUST NOT be after vuln_published_date |
| ✅ | MUST | 4.4.1 | `false-only-when-auto-provider` | 11 | 0 | 0 | existing_deployments_remain_vulnerable=false ONLY when automatic+provider_only |
| ✅ | MUST | 4.4.2 | `no-fix-no-provider-fix-date` | 11 | 0 | 0 | no_fix_available -> provider_fix_date MUST be absent |
| ✅ | MUST | 8.2 | `provider-only-fix-not-vulnerable` | 11 | 0 | 0 | provider_only + fix_date -> existing_deployments_remain_vulnerable MUST be false |
| ✅ | MUST | 4.4.3 | `sequence-unique-contiguous` | 11 | 0 | 0 | remediation_actions sequence MUST be unique and contiguous from 1 |
| ✅ | MUST | 4.4.3 | `downtime-range-when-required` | 11 | 0 | 0 | estimated_downtime_range_seconds REQUIRED when requires_downtime=true |
| ✅ | MUST | 4.4.3 | `compensating-only-means-affected` | 11 | 0 | 0 | All compensating actions -> vex_status MUST be affected |
| ✅ | MUST | 9.1 | `remediation-actions-present` | 11 | 0 | 0 | At least one remediation_actions for vex_status=affected or fixed |
| ✅ | MUST | 4.5.1 | `auto-upgrade-false-means-vulnerable` | 11 | 0 | 0 | auto_upgrade=false -> existing_deployments_remain_vulnerable MUST be true |
| ⚠️ | SHOULD | 4.6 | `detection-recommended` | 7 | 0 | 4 | vex_status=affected or fixed SHOULD include >=1 detection entry |
| ✅ | MUST | 4.6.3 | `misconfiguration-detection-for-opt-in` | 11 | 0 | 0 | opt_in or config_change MUST include misconfiguration-phase detection (placeholder with pending_reason accepted) |
| ✅ | MUST | 4.6.4 | `pending-reason-enum` | 11 | 0 | 0 | pending_reason MUST be a valid enum value when present |
| ✅ | MUST | 4.6.4 | `pending-reason-empty-query` | 11 | 0 | 0 | query MUST be empty string when pending_reason is set |
| ✅ | MUST | 4.6.4 | `no-empty-query-without-pending` | 11 | 0 | 0 | functional detection with empty query requires pending_reason |
| ✅ | MUST | 4.1.2 | `vector-string-parseable` | 11 | 0 | 0 | vectorString MUST be a parseable CRIT vector with valid known metrics |
| ✅ | MUST | 4.1.2 | `vector-provider-matches` | 11 | 0 | 0 | CP metric MUST match record provider field |
| ✅ | MUST | 4.1.2 | `vector-vex-matches` | 11 | 0 | 0 | VS metric MUST match record vex_status field |
| ✅ | MUST | 4.1.2 | `vector-propagation-matches` | 11 | 0 | 0 | FP metric MUST match record fix_propagation field |
| ✅ | MUST | 4.1.2 | `vector-responsibility-matches` | 11 | 0 | 0 | SR metric MUST match record shared_responsibility field |
| ✅ | MUST | 4.1.2 | `vector-lifecycle-matches` | 11 | 0 | 0 | RL metric MUST match record resource_lifecycle field |
| ✅ | MUST | 4.1.2 | `vector-existing-vuln-matches` | 11 | 0 | 0 | EV metric MUST match record existing_deployments_remain_vulnerable field |
| ✅ | MUST | 4.1.2 | `vector-qualifiers-match` | 11 | 0 | 0 | vector qualifiers MUST match record vuln_id, service, resource_type |
| ✅ | MUST | 4.1.2 | `vector-string-canonical` | 11 | 0 | 0 | vectorString MUST match canonical vector computed from record fields |
| ✅ | MUST | 4.1.2 | `vector-published-matches` | 11 | 0 | 0 | PP epoch MUST match temporal.vuln_published_date converted to UTC epoch |
| ✅ | MUST | 4.1.2 | `vector-service-avail-matches` | 11 | 0 | 0 | SA epoch MUST match temporal.service_available_date converted to UTC epoch |
| ✅ | MUST | 4.1.2 | `vector-metrics-order` | 11 | 0 | 0 | registered metrics MUST appear in canonical order CP VS FP SR RL EV PP SA |
| ✅ | MUST | 4.1.2 | `vector-unknown-tolerated` | 11 | 0 | 0 | consumer MUST NOT reject vectors with unknown metric keys |
| ✅ | MUST | 4.1.2 | `vector-missing-registered-rejected` | 11 | 0 | 0 | consumer MUST reject vectors missing a registered metric |

```mermaid
pie title "AWS — Record Rule Results (440 checks)"
    "✅ Passed (436)" : 436
    "⚠️ Warnings (4)" : 4
```

### Failures & Warnings

#### `detection-recommended` (4.6) &mdash; 4 ⚠️ warnings

| Service | Resource Type | Detail |
|---------|---------------|--------|
| lambda | function | vex_status=fixed but no detections |
| elb | loadbalancer | vex_status=fixed but no detections |
| ec2 | instance | vex_status=fixed but no detections |
| eks | cluster | vex_status=fixed but no detections |

## Azure

> 88 dictionary entries · 440 template samples · 8 sample records

### Template Rules

| Status | Sec | Rule | ✅ Pass | ❌ Fail | Requirement |
|:------:|:---:|------|-------:|-------:|-------------|
| ✅ | 3.2 | `slot-delimiter-not-in-literal` | 440 | 0 | Characters { and } MUST NOT appear outside slot expressions |
| ✅ | 3.3.1 | `named-var-no-default` | 440 | 0 | Named variable MUST NOT be treated as implying any default value |
| ✅ | 3.3.1 | `named-var-requires-substitution` | 440 | 0 | Named variable MUST substitute concrete value before using template as live identifier |
| ✅ | 3.3.2 | `wildcard-not-live-identifier` | 440 | 0 | Wildcard MUST NOT be used as live identifier against provider API |
| ✅ | 3.3.4 | `hardcoded-value-as-is` | 440 | 0 | Consumer MUST use hardcoded value as-is; MUST NOT substitute alternative value |
| ✅ | 3.4 | `slot-state-precedence` | 440 | 0 | Producer MUST select slot state according to precedence |
| ✅ | 3.4 | `wildcard-not-fallback` | 440 | 0 | Producer MUST NOT use wildcard as fallback when correct state is unknown |
| ✅ | 3.2 | `template-produces-valid-id` | 440 | 0 | Conformant CRIT template MUST produce valid identifier after variable resolution |
| ✅ | 6.1 | `aws-global-region-hardcoded` | 440 | 0 | AWS global-only services: region MUST be hardcoded to us-east-1 or empty |
| ✅ | 6.1 | `aws-regional-region-variable` | 440 | 0 | AWS regional services: region MUST be named variable or wildcard, MUST NOT be empty |
| ✅ | 6.4 | `cloudflare-no-region-slot` | 440 | 0 | Producer MUST NOT add region slot to Cloudflare templates |
| ✅ | 7.1 | `resolution-produces-valid-id` | 440 | 0 | After variable resolution, result MUST be valid provider identifier |
| ✅ | 7.2 | `reserved-field-names-used` | 440 | 0 | Producer MUST use reserved field names where applicable |
| ✅ | 5 | `template-field-valid-after-resolution` | 440 | 0 | After all named variables substituted, result MUST be valid provider identifier for declared template_format |
| ✅ | 12.2 | `dictionary-entry-required-fields` | 440 | 0 | All fields except notes are REQUIRED in dictionary entry |
| ✅ | 12.1.1 | `dictionary-tuple-resolves` | 440 | 0 | (provider, service, resource_type) tuple MUST resolve to entry in conformant dictionary |
| ✅ | 9.1 | `service-key-lowercase-underscore` | 440 | 0 | service field MUST match pattern ^[a-z][a-z0-9_]*$ |
| ✅ | 9.1 | `resource-type-valid-pattern` | 440 | 0 | resource_type MUST match pattern ^[a-zA-Z][a-zA-Z0-9_/-]*$ |
| ✅ | 9.1 | `template-format-matches-provider` | 440 | 0 | template_format MUST match provider |
| ✅ | 3.2 | `slot-syntax-abnf-valid` | 440 | 0 | All slots MUST conform to ABNF grammar: field-name = 1*(ALPHA / DIGIT / "-" / "_") |

### Sample Record Rules

| Status | Level | Sec | Rule | ✅ Pass | ❌ Fail | ⚠️ Warn | Requirement |
|:------:|:-----:|:---:|------|-------:|-------:|--------:|-------------|
| ✅ | MUST | 4.1 | `dates-iso8601-format` | 8 | 0 | 0 | All date fields in temporal MUST be ISO 8601 full-date (YYYY-MM-DD) |
| ✅ | MUST | 4.1 | `natural-key-fields-present` | 8 | 0 | 0 | vuln_id, provider, service, resource_type MUST all be non-empty |
| ✅ | MUST | 9.1 | `service-key-lowercase-underscore` | 8 | 0 | 0 | service MUST match ^[a-z][a-z0-9_]*$ |
| ✅ | MUST | 9.1 | `resource-type-valid-pattern` | 8 | 0 | 0 | resource_type MUST match ^[a-zA-Z][a-zA-Z0-9_/-]*$ |
| ✅ | MUST | 9.1 | `template-format-matches-provider` | 8 | 0 | 0 | template_format MUST match provider |
| ✅ | MUST | 3.2 | `slot-syntax-abnf-valid` | 8 | 0 | 0 | All slots MUST conform to ABNF grammar |
| ✅ | MUST | 3.2 | `slot-delimiter-not-in-literal` | 8 | 0 | 0 | { and } MUST NOT appear outside slot expressions |
| ✅ | MUST | 6.1 | `aws-global-region-hardcoded` | 8 | 0 | 0 | AWS global-only: region MUST be hardcoded to us-east-1 or empty |
| ✅ | MUST | 6.1 | `aws-regional-region-variable` | 8 | 0 | 0 | AWS regional: region MUST be named-variable, MUST NOT be empty |
| ✅ | MUST | 6.4 | `cloudflare-no-region-slot` | 8 | 0 | 0 | Cloudflare templates MUST NOT have region slot |
| ✅ | MUST | 12.1.1 | `dictionary-tuple-resolves` | 8 | 0 | 0 | (provider, service, resource_type) MUST resolve in dictionary |
| ✅ | MUST | 4.3 | `customer-deadline-source-required` | 8 | 0 | 0 | customer_deadline_source REQUIRED when customer_deadline_date present |
| ✅ | MUST | 4.3 | `introduced-not-after-published` | 8 | 0 | 0 | vulnerability_introduced_date MUST NOT be after vuln_published_date |
| ✅ | MUST | 4.4.1 | `false-only-when-auto-provider` | 8 | 0 | 0 | existing_deployments_remain_vulnerable=false ONLY when automatic+provider_only |
| ✅ | MUST | 4.4.2 | `no-fix-no-provider-fix-date` | 8 | 0 | 0 | no_fix_available -> provider_fix_date MUST be absent |
| ✅ | MUST | 8.2 | `provider-only-fix-not-vulnerable` | 8 | 0 | 0 | provider_only + fix_date -> existing_deployments_remain_vulnerable MUST be false |
| ✅ | MUST | 4.4.3 | `sequence-unique-contiguous` | 8 | 0 | 0 | remediation_actions sequence MUST be unique and contiguous from 1 |
| ✅ | MUST | 4.4.3 | `downtime-range-when-required` | 8 | 0 | 0 | estimated_downtime_range_seconds REQUIRED when requires_downtime=true |
| ✅ | MUST | 4.4.3 | `compensating-only-means-affected` | 8 | 0 | 0 | All compensating actions -> vex_status MUST be affected |
| ✅ | MUST | 9.1 | `remediation-actions-present` | 8 | 0 | 0 | At least one remediation_actions for vex_status=affected or fixed |
| ✅ | MUST | 4.5.1 | `auto-upgrade-false-means-vulnerable` | 8 | 0 | 0 | auto_upgrade=false -> existing_deployments_remain_vulnerable MUST be true |
| ⚠️ | SHOULD | 4.6 | `detection-recommended` | 5 | 0 | 3 | vex_status=affected or fixed SHOULD include >=1 detection entry |
| ✅ | MUST | 4.6.3 | `misconfiguration-detection-for-opt-in` | 8 | 0 | 0 | opt_in or config_change MUST include misconfiguration-phase detection (placeholder with pending_reason accepted) |
| ✅ | MUST | 4.6.4 | `pending-reason-enum` | 8 | 0 | 0 | pending_reason MUST be a valid enum value when present |
| ✅ | MUST | 4.6.4 | `pending-reason-empty-query` | 8 | 0 | 0 | query MUST be empty string when pending_reason is set |
| ✅ | MUST | 4.6.4 | `no-empty-query-without-pending` | 8 | 0 | 0 | functional detection with empty query requires pending_reason |
| ✅ | MUST | 4.1.2 | `vector-string-parseable` | 8 | 0 | 0 | vectorString MUST be a parseable CRIT vector with valid known metrics |
| ✅ | MUST | 4.1.2 | `vector-provider-matches` | 8 | 0 | 0 | CP metric MUST match record provider field |
| ✅ | MUST | 4.1.2 | `vector-vex-matches` | 8 | 0 | 0 | VS metric MUST match record vex_status field |
| ✅ | MUST | 4.1.2 | `vector-propagation-matches` | 8 | 0 | 0 | FP metric MUST match record fix_propagation field |
| ✅ | MUST | 4.1.2 | `vector-responsibility-matches` | 8 | 0 | 0 | SR metric MUST match record shared_responsibility field |
| ✅ | MUST | 4.1.2 | `vector-lifecycle-matches` | 8 | 0 | 0 | RL metric MUST match record resource_lifecycle field |
| ✅ | MUST | 4.1.2 | `vector-existing-vuln-matches` | 8 | 0 | 0 | EV metric MUST match record existing_deployments_remain_vulnerable field |
| ✅ | MUST | 4.1.2 | `vector-qualifiers-match` | 8 | 0 | 0 | vector qualifiers MUST match record vuln_id, service, resource_type |
| ✅ | MUST | 4.1.2 | `vector-string-canonical` | 8 | 0 | 0 | vectorString MUST match canonical vector computed from record fields |
| ✅ | MUST | 4.1.2 | `vector-published-matches` | 8 | 0 | 0 | PP epoch MUST match temporal.vuln_published_date converted to UTC epoch |
| ✅ | MUST | 4.1.2 | `vector-service-avail-matches` | 8 | 0 | 0 | SA epoch MUST match temporal.service_available_date converted to UTC epoch |
| ✅ | MUST | 4.1.2 | `vector-metrics-order` | 8 | 0 | 0 | registered metrics MUST appear in canonical order CP VS FP SR RL EV PP SA |
| ✅ | MUST | 4.1.2 | `vector-unknown-tolerated` | 8 | 0 | 0 | consumer MUST NOT reject vectors with unknown metric keys |
| ✅ | MUST | 4.1.2 | `vector-missing-registered-rejected` | 8 | 0 | 0 | consumer MUST reject vectors missing a registered metric |

```mermaid
pie title "Azure — Record Rule Results (320 checks)"
    "✅ Passed (317)" : 317
    "⚠️ Warnings (3)" : 3
```

### Failures & Warnings

#### `detection-recommended` (4.6) &mdash; 3 ⚠️ warnings

| Service | Resource Type | Detail |
|---------|---------------|--------|
| app_service | sites | vex_status=fixed but no detections |
| load_balancer | loadBalancers | vex_status=fixed but no detections |
| kubernetes_service | managedClusters | vex_status=fixed but no detections |

## GCP

> 77 dictionary entries · 385 template samples · 5 sample records

### Template Rules

| Status | Sec | Rule | ✅ Pass | ❌ Fail | Requirement |
|:------:|:---:|------|-------:|-------:|-------------|
| ✅ | 3.2 | `slot-delimiter-not-in-literal` | 385 | 0 | Characters { and } MUST NOT appear outside slot expressions |
| ✅ | 3.3.1 | `named-var-no-default` | 385 | 0 | Named variable MUST NOT be treated as implying any default value |
| ✅ | 3.3.1 | `named-var-requires-substitution` | 385 | 0 | Named variable MUST substitute concrete value before using template as live identifier |
| ✅ | 3.3.2 | `wildcard-not-live-identifier` | 385 | 0 | Wildcard MUST NOT be used as live identifier against provider API |
| ✅ | 3.3.4 | `hardcoded-value-as-is` | 385 | 0 | Consumer MUST use hardcoded value as-is; MUST NOT substitute alternative value |
| ✅ | 3.4 | `slot-state-precedence` | 385 | 0 | Producer MUST select slot state according to precedence |
| ✅ | 3.4 | `wildcard-not-fallback` | 385 | 0 | Producer MUST NOT use wildcard as fallback when correct state is unknown |
| ✅ | 3.2 | `template-produces-valid-id` | 385 | 0 | Conformant CRIT template MUST produce valid identifier after variable resolution |
| ✅ | 6.1 | `aws-global-region-hardcoded` | 385 | 0 | AWS global-only services: region MUST be hardcoded to us-east-1 or empty |
| ✅ | 6.1 | `aws-regional-region-variable` | 385 | 0 | AWS regional services: region MUST be named variable or wildcard, MUST NOT be empty |
| ✅ | 6.4 | `cloudflare-no-region-slot` | 385 | 0 | Producer MUST NOT add region slot to Cloudflare templates |
| ✅ | 7.1 | `resolution-produces-valid-id` | 385 | 0 | After variable resolution, result MUST be valid provider identifier |
| ✅ | 7.2 | `reserved-field-names-used` | 385 | 0 | Producer MUST use reserved field names where applicable |
| ✅ | 5 | `template-field-valid-after-resolution` | 385 | 0 | After all named variables substituted, result MUST be valid provider identifier for declared template_format |
| ✅ | 12.2 | `dictionary-entry-required-fields` | 385 | 0 | All fields except notes are REQUIRED in dictionary entry |
| ✅ | 12.1.1 | `dictionary-tuple-resolves` | 385 | 0 | (provider, service, resource_type) tuple MUST resolve to entry in conformant dictionary |
| ✅ | 9.1 | `service-key-lowercase-underscore` | 385 | 0 | service field MUST match pattern ^[a-z][a-z0-9_]*$ |
| ✅ | 9.1 | `resource-type-valid-pattern` | 385 | 0 | resource_type MUST match pattern ^[a-zA-Z][a-zA-Z0-9_/-]*$ |
| ✅ | 9.1 | `template-format-matches-provider` | 385 | 0 | template_format MUST match provider |
| ✅ | 3.2 | `slot-syntax-abnf-valid` | 385 | 0 | All slots MUST conform to ABNF grammar: field-name = 1*(ALPHA / DIGIT / "-" / "_") |

### Sample Record Rules

| Status | Level | Sec | Rule | ✅ Pass | ❌ Fail | ⚠️ Warn | Requirement |
|:------:|:-----:|:---:|------|-------:|-------:|--------:|-------------|
| ✅ | MUST | 4.1 | `dates-iso8601-format` | 5 | 0 | 0 | All date fields in temporal MUST be ISO 8601 full-date (YYYY-MM-DD) |
| ✅ | MUST | 4.1 | `natural-key-fields-present` | 5 | 0 | 0 | vuln_id, provider, service, resource_type MUST all be non-empty |
| ✅ | MUST | 9.1 | `service-key-lowercase-underscore` | 5 | 0 | 0 | service MUST match ^[a-z][a-z0-9_]*$ |
| ✅ | MUST | 9.1 | `resource-type-valid-pattern` | 5 | 0 | 0 | resource_type MUST match ^[a-zA-Z][a-zA-Z0-9_/-]*$ |
| ✅ | MUST | 9.1 | `template-format-matches-provider` | 5 | 0 | 0 | template_format MUST match provider |
| ✅ | MUST | 3.2 | `slot-syntax-abnf-valid` | 5 | 0 | 0 | All slots MUST conform to ABNF grammar |
| ✅ | MUST | 3.2 | `slot-delimiter-not-in-literal` | 5 | 0 | 0 | { and } MUST NOT appear outside slot expressions |
| ✅ | MUST | 6.1 | `aws-global-region-hardcoded` | 5 | 0 | 0 | AWS global-only: region MUST be hardcoded to us-east-1 or empty |
| ✅ | MUST | 6.1 | `aws-regional-region-variable` | 5 | 0 | 0 | AWS regional: region MUST be named-variable, MUST NOT be empty |
| ✅ | MUST | 6.4 | `cloudflare-no-region-slot` | 5 | 0 | 0 | Cloudflare templates MUST NOT have region slot |
| ✅ | MUST | 12.1.1 | `dictionary-tuple-resolves` | 5 | 0 | 0 | (provider, service, resource_type) MUST resolve in dictionary |
| ✅ | MUST | 4.3 | `customer-deadline-source-required` | 5 | 0 | 0 | customer_deadline_source REQUIRED when customer_deadline_date present |
| ✅ | MUST | 4.3 | `introduced-not-after-published` | 5 | 0 | 0 | vulnerability_introduced_date MUST NOT be after vuln_published_date |
| ✅ | MUST | 4.4.1 | `false-only-when-auto-provider` | 5 | 0 | 0 | existing_deployments_remain_vulnerable=false ONLY when automatic+provider_only |
| ✅ | MUST | 4.4.2 | `no-fix-no-provider-fix-date` | 5 | 0 | 0 | no_fix_available -> provider_fix_date MUST be absent |
| ✅ | MUST | 8.2 | `provider-only-fix-not-vulnerable` | 5 | 0 | 0 | provider_only + fix_date -> existing_deployments_remain_vulnerable MUST be false |
| ✅ | MUST | 4.4.3 | `sequence-unique-contiguous` | 5 | 0 | 0 | remediation_actions sequence MUST be unique and contiguous from 1 |
| ✅ | MUST | 4.4.3 | `downtime-range-when-required` | 5 | 0 | 0 | estimated_downtime_range_seconds REQUIRED when requires_downtime=true |
| ✅ | MUST | 4.4.3 | `compensating-only-means-affected` | 5 | 0 | 0 | All compensating actions -> vex_status MUST be affected |
| ✅ | MUST | 9.1 | `remediation-actions-present` | 5 | 0 | 0 | At least one remediation_actions for vex_status=affected or fixed |
| ✅ | MUST | 4.5.1 | `auto-upgrade-false-means-vulnerable` | 5 | 0 | 0 | auto_upgrade=false -> existing_deployments_remain_vulnerable MUST be true |
| ⚠️ | SHOULD | 4.6 | `detection-recommended` | 3 | 0 | 2 | vex_status=affected or fixed SHOULD include >=1 detection entry |
| ✅ | MUST | 4.6.3 | `misconfiguration-detection-for-opt-in` | 5 | 0 | 0 | opt_in or config_change MUST include misconfiguration-phase detection (placeholder with pending_reason accepted) |
| ✅ | MUST | 4.6.4 | `pending-reason-enum` | 5 | 0 | 0 | pending_reason MUST be a valid enum value when present |
| ✅ | MUST | 4.6.4 | `pending-reason-empty-query` | 5 | 0 | 0 | query MUST be empty string when pending_reason is set |
| ✅ | MUST | 4.6.4 | `no-empty-query-without-pending` | 5 | 0 | 0 | functional detection with empty query requires pending_reason |
| ✅ | MUST | 4.1.2 | `vector-string-parseable` | 5 | 0 | 0 | vectorString MUST be a parseable CRIT vector with valid known metrics |
| ✅ | MUST | 4.1.2 | `vector-provider-matches` | 5 | 0 | 0 | CP metric MUST match record provider field |
| ✅ | MUST | 4.1.2 | `vector-vex-matches` | 5 | 0 | 0 | VS metric MUST match record vex_status field |
| ✅ | MUST | 4.1.2 | `vector-propagation-matches` | 5 | 0 | 0 | FP metric MUST match record fix_propagation field |
| ✅ | MUST | 4.1.2 | `vector-responsibility-matches` | 5 | 0 | 0 | SR metric MUST match record shared_responsibility field |
| ✅ | MUST | 4.1.2 | `vector-lifecycle-matches` | 5 | 0 | 0 | RL metric MUST match record resource_lifecycle field |
| ✅ | MUST | 4.1.2 | `vector-existing-vuln-matches` | 5 | 0 | 0 | EV metric MUST match record existing_deployments_remain_vulnerable field |
| ✅ | MUST | 4.1.2 | `vector-qualifiers-match` | 5 | 0 | 0 | vector qualifiers MUST match record vuln_id, service, resource_type |
| ✅ | MUST | 4.1.2 | `vector-string-canonical` | 5 | 0 | 0 | vectorString MUST match canonical vector computed from record fields |
| ✅ | MUST | 4.1.2 | `vector-published-matches` | 5 | 0 | 0 | PP epoch MUST match temporal.vuln_published_date converted to UTC epoch |
| ✅ | MUST | 4.1.2 | `vector-service-avail-matches` | 5 | 0 | 0 | SA epoch MUST match temporal.service_available_date converted to UTC epoch |
| ✅ | MUST | 4.1.2 | `vector-metrics-order` | 5 | 0 | 0 | registered metrics MUST appear in canonical order CP VS FP SR RL EV PP SA |
| ✅ | MUST | 4.1.2 | `vector-unknown-tolerated` | 5 | 0 | 0 | consumer MUST NOT reject vectors with unknown metric keys |
| ✅ | MUST | 4.1.2 | `vector-missing-registered-rejected` | 5 | 0 | 0 | consumer MUST reject vectors missing a registered metric |

```mermaid
pie title "GCP — Record Rule Results (200 checks)"
    "✅ Passed (198)" : 198
    "⚠️ Warnings (2)" : 2
```

### Failures & Warnings

#### `detection-recommended` (4.6) &mdash; 2 ⚠️ warnings

| Service | Resource Type | Detail |
|---------|---------------|--------|
| compute | instance | vex_status=fixed but no detections |
| kubernetes_engine | cluster | vex_status=fixed but no detections |

## Cloudflare

> 43 dictionary entries · 215 template samples · 4 sample records

### Template Rules

| Status | Sec | Rule | ✅ Pass | ❌ Fail | Requirement |
|:------:|:---:|------|-------:|-------:|-------------|
| ✅ | 3.2 | `slot-delimiter-not-in-literal` | 215 | 0 | Characters { and } MUST NOT appear outside slot expressions |
| ✅ | 3.3.1 | `named-var-no-default` | 215 | 0 | Named variable MUST NOT be treated as implying any default value |
| ✅ | 3.3.1 | `named-var-requires-substitution` | 215 | 0 | Named variable MUST substitute concrete value before using template as live identifier |
| ✅ | 3.3.2 | `wildcard-not-live-identifier` | 215 | 0 | Wildcard MUST NOT be used as live identifier against provider API |
| ✅ | 3.3.4 | `hardcoded-value-as-is` | 215 | 0 | Consumer MUST use hardcoded value as-is; MUST NOT substitute alternative value |
| ✅ | 3.4 | `slot-state-precedence` | 215 | 0 | Producer MUST select slot state according to precedence |
| ✅ | 3.4 | `wildcard-not-fallback` | 215 | 0 | Producer MUST NOT use wildcard as fallback when correct state is unknown |
| ✅ | 3.2 | `template-produces-valid-id` | 215 | 0 | Conformant CRIT template MUST produce valid identifier after variable resolution |
| ✅ | 6.1 | `aws-global-region-hardcoded` | 215 | 0 | AWS global-only services: region MUST be hardcoded to us-east-1 or empty |
| ✅ | 6.1 | `aws-regional-region-variable` | 215 | 0 | AWS regional services: region MUST be named variable or wildcard, MUST NOT be empty |
| ✅ | 6.4 | `cloudflare-no-region-slot` | 215 | 0 | Producer MUST NOT add region slot to Cloudflare templates |
| ✅ | 7.1 | `resolution-produces-valid-id` | 215 | 0 | After variable resolution, result MUST be valid provider identifier |
| ✅ | 7.2 | `reserved-field-names-used` | 215 | 0 | Producer MUST use reserved field names where applicable |
| ✅ | 5 | `template-field-valid-after-resolution` | 215 | 0 | After all named variables substituted, result MUST be valid provider identifier for declared template_format |
| ✅ | 12.2 | `dictionary-entry-required-fields` | 215 | 0 | All fields except notes are REQUIRED in dictionary entry |
| ✅ | 12.1.1 | `dictionary-tuple-resolves` | 215 | 0 | (provider, service, resource_type) tuple MUST resolve to entry in conformant dictionary |
| ✅ | 9.1 | `service-key-lowercase-underscore` | 215 | 0 | service field MUST match pattern ^[a-z][a-z0-9_]*$ |
| ✅ | 9.1 | `resource-type-valid-pattern` | 215 | 0 | resource_type MUST match pattern ^[a-zA-Z][a-zA-Z0-9_/-]*$ |
| ✅ | 9.1 | `template-format-matches-provider` | 215 | 0 | template_format MUST match provider |
| ✅ | 3.2 | `slot-syntax-abnf-valid` | 215 | 0 | All slots MUST conform to ABNF grammar: field-name = 1*(ALPHA / DIGIT / "-" / "_") |

### Sample Record Rules

| Status | Level | Sec | Rule | ✅ Pass | ❌ Fail | ⚠️ Warn | Requirement |
|:------:|:-----:|:---:|------|-------:|-------:|--------:|-------------|
| ✅ | MUST | 4.1 | `dates-iso8601-format` | 4 | 0 | 0 | All date fields in temporal MUST be ISO 8601 full-date (YYYY-MM-DD) |
| ✅ | MUST | 4.1 | `natural-key-fields-present` | 4 | 0 | 0 | vuln_id, provider, service, resource_type MUST all be non-empty |
| ✅ | MUST | 9.1 | `service-key-lowercase-underscore` | 4 | 0 | 0 | service MUST match ^[a-z][a-z0-9_]*$ |
| ✅ | MUST | 9.1 | `resource-type-valid-pattern` | 4 | 0 | 0 | resource_type MUST match ^[a-zA-Z][a-zA-Z0-9_/-]*$ |
| ✅ | MUST | 9.1 | `template-format-matches-provider` | 4 | 0 | 0 | template_format MUST match provider |
| ✅ | MUST | 3.2 | `slot-syntax-abnf-valid` | 4 | 0 | 0 | All slots MUST conform to ABNF grammar |
| ✅ | MUST | 3.2 | `slot-delimiter-not-in-literal` | 4 | 0 | 0 | { and } MUST NOT appear outside slot expressions |
| ✅ | MUST | 6.1 | `aws-global-region-hardcoded` | 4 | 0 | 0 | AWS global-only: region MUST be hardcoded to us-east-1 or empty |
| ✅ | MUST | 6.1 | `aws-regional-region-variable` | 4 | 0 | 0 | AWS regional: region MUST be named-variable, MUST NOT be empty |
| ✅ | MUST | 6.4 | `cloudflare-no-region-slot` | 4 | 0 | 0 | Cloudflare templates MUST NOT have region slot |
| ✅ | MUST | 12.1.1 | `dictionary-tuple-resolves` | 4 | 0 | 0 | (provider, service, resource_type) MUST resolve in dictionary |
| ✅ | MUST | 4.3 | `customer-deadline-source-required` | 4 | 0 | 0 | customer_deadline_source REQUIRED when customer_deadline_date present |
| ✅ | MUST | 4.3 | `introduced-not-after-published` | 4 | 0 | 0 | vulnerability_introduced_date MUST NOT be after vuln_published_date |
| ✅ | MUST | 4.4.1 | `false-only-when-auto-provider` | 4 | 0 | 0 | existing_deployments_remain_vulnerable=false ONLY when automatic+provider_only |
| ✅ | MUST | 4.4.2 | `no-fix-no-provider-fix-date` | 4 | 0 | 0 | no_fix_available -> provider_fix_date MUST be absent |
| ✅ | MUST | 8.2 | `provider-only-fix-not-vulnerable` | 4 | 0 | 0 | provider_only + fix_date -> existing_deployments_remain_vulnerable MUST be false |
| ✅ | MUST | 4.4.3 | `sequence-unique-contiguous` | 4 | 0 | 0 | remediation_actions sequence MUST be unique and contiguous from 1 |
| ✅ | MUST | 4.4.3 | `downtime-range-when-required` | 4 | 0 | 0 | estimated_downtime_range_seconds REQUIRED when requires_downtime=true |
| ✅ | MUST | 4.4.3 | `compensating-only-means-affected` | 4 | 0 | 0 | All compensating actions -> vex_status MUST be affected |
| ✅ | MUST | 9.1 | `remediation-actions-present` | 4 | 0 | 0 | At least one remediation_actions for vex_status=affected or fixed |
| ✅ | MUST | 4.5.1 | `auto-upgrade-false-means-vulnerable` | 4 | 0 | 0 | auto_upgrade=false -> existing_deployments_remain_vulnerable MUST be true |
| ⚠️ | SHOULD | 4.6 | `detection-recommended` | 3 | 0 | 1 | vex_status=affected or fixed SHOULD include >=1 detection entry |
| ✅ | MUST | 4.6.3 | `misconfiguration-detection-for-opt-in` | 4 | 0 | 0 | opt_in or config_change MUST include misconfiguration-phase detection (placeholder with pending_reason accepted) |
| ✅ | MUST | 4.6.4 | `pending-reason-enum` | 4 | 0 | 0 | pending_reason MUST be a valid enum value when present |
| ✅ | MUST | 4.6.4 | `pending-reason-empty-query` | 4 | 0 | 0 | query MUST be empty string when pending_reason is set |
| ✅ | MUST | 4.6.4 | `no-empty-query-without-pending` | 4 | 0 | 0 | functional detection with empty query requires pending_reason |
| ✅ | MUST | 4.1.2 | `vector-string-parseable` | 4 | 0 | 0 | vectorString MUST be a parseable CRIT vector with valid known metrics |
| ✅ | MUST | 4.1.2 | `vector-provider-matches` | 4 | 0 | 0 | CP metric MUST match record provider field |
| ✅ | MUST | 4.1.2 | `vector-vex-matches` | 4 | 0 | 0 | VS metric MUST match record vex_status field |
| ✅ | MUST | 4.1.2 | `vector-propagation-matches` | 4 | 0 | 0 | FP metric MUST match record fix_propagation field |
| ✅ | MUST | 4.1.2 | `vector-responsibility-matches` | 4 | 0 | 0 | SR metric MUST match record shared_responsibility field |
| ✅ | MUST | 4.1.2 | `vector-lifecycle-matches` | 4 | 0 | 0 | RL metric MUST match record resource_lifecycle field |
| ✅ | MUST | 4.1.2 | `vector-existing-vuln-matches` | 4 | 0 | 0 | EV metric MUST match record existing_deployments_remain_vulnerable field |
| ✅ | MUST | 4.1.2 | `vector-qualifiers-match` | 4 | 0 | 0 | vector qualifiers MUST match record vuln_id, service, resource_type |
| ✅ | MUST | 4.1.2 | `vector-string-canonical` | 4 | 0 | 0 | vectorString MUST match canonical vector computed from record fields |
| ✅ | MUST | 4.1.2 | `vector-published-matches` | 4 | 0 | 0 | PP epoch MUST match temporal.vuln_published_date converted to UTC epoch |
| ✅ | MUST | 4.1.2 | `vector-service-avail-matches` | 4 | 0 | 0 | SA epoch MUST match temporal.service_available_date converted to UTC epoch |
| ✅ | MUST | 4.1.2 | `vector-metrics-order` | 4 | 0 | 0 | registered metrics MUST appear in canonical order CP VS FP SR RL EV PP SA |
| ✅ | MUST | 4.1.2 | `vector-unknown-tolerated` | 4 | 0 | 0 | consumer MUST NOT reject vectors with unknown metric keys |
| ✅ | MUST | 4.1.2 | `vector-missing-registered-rejected` | 4 | 0 | 0 | consumer MUST reject vectors missing a registered metric |

```mermaid
pie title "Cloudflare — Record Rule Results (160 checks)"
    "✅ Passed (159)" : 159
    "⚠️ Warnings (1)" : 1
```

### Failures & Warnings

#### `detection-recommended` (4.6) &mdash; 1 ⚠️ warnings

| Service | Resource Type | Detail |
|---------|---------------|--------|
| dns | zone | vex_status=fixed but no detections |

## Oracle

> 67 dictionary entries · 335 template samples · 5 sample records

### Template Rules

| Status | Sec | Rule | ✅ Pass | ❌ Fail | Requirement |
|:------:|:---:|------|-------:|-------:|-------------|
| ✅ | 3.2 | `slot-delimiter-not-in-literal` | 335 | 0 | Characters { and } MUST NOT appear outside slot expressions |
| ✅ | 3.3.1 | `named-var-no-default` | 335 | 0 | Named variable MUST NOT be treated as implying any default value |
| ✅ | 3.3.1 | `named-var-requires-substitution` | 335 | 0 | Named variable MUST substitute concrete value before using template as live identifier |
| ✅ | 3.3.2 | `wildcard-not-live-identifier` | 335 | 0 | Wildcard MUST NOT be used as live identifier against provider API |
| ✅ | 3.3.4 | `hardcoded-value-as-is` | 335 | 0 | Consumer MUST use hardcoded value as-is; MUST NOT substitute alternative value |
| ✅ | 3.4 | `slot-state-precedence` | 335 | 0 | Producer MUST select slot state according to precedence |
| ✅ | 3.4 | `wildcard-not-fallback` | 335 | 0 | Producer MUST NOT use wildcard as fallback when correct state is unknown |
| ✅ | 3.2 | `template-produces-valid-id` | 335 | 0 | Conformant CRIT template MUST produce valid identifier after variable resolution |
| ✅ | 6.1 | `aws-global-region-hardcoded` | 335 | 0 | AWS global-only services: region MUST be hardcoded to us-east-1 or empty |
| ✅ | 6.1 | `aws-regional-region-variable` | 335 | 0 | AWS regional services: region MUST be named variable or wildcard, MUST NOT be empty |
| ✅ | 6.4 | `cloudflare-no-region-slot` | 335 | 0 | Producer MUST NOT add region slot to Cloudflare templates |
| ✅ | 7.1 | `resolution-produces-valid-id` | 335 | 0 | After variable resolution, result MUST be valid provider identifier |
| ✅ | 7.2 | `reserved-field-names-used` | 335 | 0 | Producer MUST use reserved field names where applicable |
| ✅ | 5 | `template-field-valid-after-resolution` | 335 | 0 | After all named variables substituted, result MUST be valid provider identifier for declared template_format |
| ✅ | 12.2 | `dictionary-entry-required-fields` | 335 | 0 | All fields except notes are REQUIRED in dictionary entry |
| ✅ | 12.1.1 | `dictionary-tuple-resolves` | 335 | 0 | (provider, service, resource_type) tuple MUST resolve to entry in conformant dictionary |
| ✅ | 9.1 | `service-key-lowercase-underscore` | 335 | 0 | service field MUST match pattern ^[a-z][a-z0-9_]*$ |
| ✅ | 9.1 | `resource-type-valid-pattern` | 335 | 0 | resource_type MUST match pattern ^[a-zA-Z][a-zA-Z0-9_/-]*$ |
| ✅ | 9.1 | `template-format-matches-provider` | 335 | 0 | template_format MUST match provider |
| ✅ | 3.2 | `slot-syntax-abnf-valid` | 335 | 0 | All slots MUST conform to ABNF grammar: field-name = 1*(ALPHA / DIGIT / "-" / "_") |

### Sample Record Rules

| Status | Level | Sec | Rule | ✅ Pass | ❌ Fail | ⚠️ Warn | Requirement |
|:------:|:-----:|:---:|------|-------:|-------:|--------:|-------------|
| ✅ | MUST | 4.1 | `dates-iso8601-format` | 5 | 0 | 0 | All date fields in temporal MUST be ISO 8601 full-date (YYYY-MM-DD) |
| ✅ | MUST | 4.1 | `natural-key-fields-present` | 5 | 0 | 0 | vuln_id, provider, service, resource_type MUST all be non-empty |
| ✅ | MUST | 9.1 | `service-key-lowercase-underscore` | 5 | 0 | 0 | service MUST match ^[a-z][a-z0-9_]*$ |
| ✅ | MUST | 9.1 | `resource-type-valid-pattern` | 5 | 0 | 0 | resource_type MUST match ^[a-zA-Z][a-zA-Z0-9_/-]*$ |
| ✅ | MUST | 9.1 | `template-format-matches-provider` | 5 | 0 | 0 | template_format MUST match provider |
| ✅ | MUST | 3.2 | `slot-syntax-abnf-valid` | 5 | 0 | 0 | All slots MUST conform to ABNF grammar |
| ✅ | MUST | 3.2 | `slot-delimiter-not-in-literal` | 5 | 0 | 0 | { and } MUST NOT appear outside slot expressions |
| ✅ | MUST | 6.1 | `aws-global-region-hardcoded` | 5 | 0 | 0 | AWS global-only: region MUST be hardcoded to us-east-1 or empty |
| ✅ | MUST | 6.1 | `aws-regional-region-variable` | 5 | 0 | 0 | AWS regional: region MUST be named-variable, MUST NOT be empty |
| ✅ | MUST | 6.4 | `cloudflare-no-region-slot` | 5 | 0 | 0 | Cloudflare templates MUST NOT have region slot |
| ✅ | MUST | 12.1.1 | `dictionary-tuple-resolves` | 5 | 0 | 0 | (provider, service, resource_type) MUST resolve in dictionary |
| ✅ | MUST | 4.3 | `customer-deadline-source-required` | 5 | 0 | 0 | customer_deadline_source REQUIRED when customer_deadline_date present |
| ✅ | MUST | 4.3 | `introduced-not-after-published` | 5 | 0 | 0 | vulnerability_introduced_date MUST NOT be after vuln_published_date |
| ✅ | MUST | 4.4.1 | `false-only-when-auto-provider` | 5 | 0 | 0 | existing_deployments_remain_vulnerable=false ONLY when automatic+provider_only |
| ✅ | MUST | 4.4.2 | `no-fix-no-provider-fix-date` | 5 | 0 | 0 | no_fix_available -> provider_fix_date MUST be absent |
| ✅ | MUST | 8.2 | `provider-only-fix-not-vulnerable` | 5 | 0 | 0 | provider_only + fix_date -> existing_deployments_remain_vulnerable MUST be false |
| ✅ | MUST | 4.4.3 | `sequence-unique-contiguous` | 5 | 0 | 0 | remediation_actions sequence MUST be unique and contiguous from 1 |
| ✅ | MUST | 4.4.3 | `downtime-range-when-required` | 5 | 0 | 0 | estimated_downtime_range_seconds REQUIRED when requires_downtime=true |
| ✅ | MUST | 4.4.3 | `compensating-only-means-affected` | 5 | 0 | 0 | All compensating actions -> vex_status MUST be affected |
| ✅ | MUST | 9.1 | `remediation-actions-present` | 5 | 0 | 0 | At least one remediation_actions for vex_status=affected or fixed |
| ✅ | MUST | 4.5.1 | `auto-upgrade-false-means-vulnerable` | 5 | 0 | 0 | auto_upgrade=false -> existing_deployments_remain_vulnerable MUST be true |
| ⚠️ | SHOULD | 4.6 | `detection-recommended` | 2 | 0 | 3 | vex_status=affected or fixed SHOULD include >=1 detection entry |
| ✅ | MUST | 4.6.3 | `misconfiguration-detection-for-opt-in` | 5 | 0 | 0 | opt_in or config_change MUST include misconfiguration-phase detection (placeholder with pending_reason accepted) |
| ✅ | MUST | 4.6.4 | `pending-reason-enum` | 5 | 0 | 0 | pending_reason MUST be a valid enum value when present |
| ✅ | MUST | 4.6.4 | `pending-reason-empty-query` | 5 | 0 | 0 | query MUST be empty string when pending_reason is set |
| ✅ | MUST | 4.6.4 | `no-empty-query-without-pending` | 5 | 0 | 0 | functional detection with empty query requires pending_reason |
| ✅ | MUST | 4.1.2 | `vector-string-parseable` | 5 | 0 | 0 | vectorString MUST be a parseable CRIT vector with valid known metrics |
| ✅ | MUST | 4.1.2 | `vector-provider-matches` | 5 | 0 | 0 | CP metric MUST match record provider field |
| ✅ | MUST | 4.1.2 | `vector-vex-matches` | 5 | 0 | 0 | VS metric MUST match record vex_status field |
| ✅ | MUST | 4.1.2 | `vector-propagation-matches` | 5 | 0 | 0 | FP metric MUST match record fix_propagation field |
| ✅ | MUST | 4.1.2 | `vector-responsibility-matches` | 5 | 0 | 0 | SR metric MUST match record shared_responsibility field |
| ✅ | MUST | 4.1.2 | `vector-lifecycle-matches` | 5 | 0 | 0 | RL metric MUST match record resource_lifecycle field |
| ✅ | MUST | 4.1.2 | `vector-existing-vuln-matches` | 5 | 0 | 0 | EV metric MUST match record existing_deployments_remain_vulnerable field |
| ✅ | MUST | 4.1.2 | `vector-qualifiers-match` | 5 | 0 | 0 | vector qualifiers MUST match record vuln_id, service, resource_type |
| ✅ | MUST | 4.1.2 | `vector-string-canonical` | 5 | 0 | 0 | vectorString MUST match canonical vector computed from record fields |
| ✅ | MUST | 4.1.2 | `vector-published-matches` | 5 | 0 | 0 | PP epoch MUST match temporal.vuln_published_date converted to UTC epoch |
| ✅ | MUST | 4.1.2 | `vector-service-avail-matches` | 5 | 0 | 0 | SA epoch MUST match temporal.service_available_date converted to UTC epoch |
| ✅ | MUST | 4.1.2 | `vector-metrics-order` | 5 | 0 | 0 | registered metrics MUST appear in canonical order CP VS FP SR RL EV PP SA |
| ✅ | MUST | 4.1.2 | `vector-unknown-tolerated` | 5 | 0 | 0 | consumer MUST NOT reject vectors with unknown metric keys |
| ✅ | MUST | 4.1.2 | `vector-missing-registered-rejected` | 5 | 0 | 0 | consumer MUST reject vectors missing a registered metric |

```mermaid
pie title "Oracle — Record Rule Results (200 checks)"
    "✅ Passed (197)" : 197
    "⚠️ Warnings (3)" : 3
```

### Failures & Warnings

#### `detection-recommended` (4.6) &mdash; 3 ⚠️ warnings

| Service | Resource Type | Detail |
|---------|---------------|--------|
| autonomous_database | autonomousdatabase | vex_status=fixed but no detections |
| autonomous_database | autonomousdatabase | vex_status=fixed but no detections |
| oke | cluster | vex_status=fixed but no detections |

## Salesforce

> 64 dictionary entries · 303 template samples · 0 sample records

### Template Rules

| Status | Sec | Rule | ✅ Pass | ❌ Fail | Requirement |
|:------:|:---:|------|-------:|-------:|-------------|
| ✅ | 3.2 | `slot-delimiter-not-in-literal` | 303 | 0 | Characters { and } MUST NOT appear outside slot expressions |
| ✅ | 3.3.1 | `named-var-no-default` | 303 | 0 | Named variable MUST NOT be treated as implying any default value |
| ✅ | 3.3.1 | `named-var-requires-substitution` | 303 | 0 | Named variable MUST substitute concrete value before using template as live identifier |
| ✅ | 3.3.2 | `wildcard-not-live-identifier` | 303 | 0 | Wildcard MUST NOT be used as live identifier against provider API |
| ✅ | 3.3.4 | `hardcoded-value-as-is` | 303 | 0 | Consumer MUST use hardcoded value as-is; MUST NOT substitute alternative value |
| ✅ | 3.4 | `slot-state-precedence` | 303 | 0 | Producer MUST select slot state according to precedence |
| ✅ | 3.4 | `wildcard-not-fallback` | 303 | 0 | Producer MUST NOT use wildcard as fallback when correct state is unknown |
| ✅ | 3.2 | `template-produces-valid-id` | 303 | 0 | Conformant CRIT template MUST produce valid identifier after variable resolution |
| ✅ | 6.1 | `aws-global-region-hardcoded` | 303 | 0 | AWS global-only services: region MUST be hardcoded to us-east-1 or empty |
| ✅ | 6.1 | `aws-regional-region-variable` | 303 | 0 | AWS regional services: region MUST be named variable or wildcard, MUST NOT be empty |
| ✅ | 6.4 | `cloudflare-no-region-slot` | 303 | 0 | Producer MUST NOT add region slot to Cloudflare templates |
| ✅ | 7.1 | `resolution-produces-valid-id` | 303 | 0 | After variable resolution, result MUST be valid provider identifier |
| ✅ | 7.2 | `reserved-field-names-used` | 303 | 0 | Producer MUST use reserved field names where applicable |
| ✅ | 5 | `template-field-valid-after-resolution` | 303 | 0 | After all named variables substituted, result MUST be valid provider identifier for declared template_format |
| ✅ | 12.2 | `dictionary-entry-required-fields` | 303 | 0 | All fields except notes are REQUIRED in dictionary entry |
| ✅ | 12.1.1 | `dictionary-tuple-resolves` | 303 | 0 | (provider, service, resource_type) tuple MUST resolve to entry in conformant dictionary |
| ✅ | 9.1 | `service-key-lowercase-underscore` | 303 | 0 | service field MUST match pattern ^[a-z][a-z0-9_]*$ |
| ✅ | 9.1 | `resource-type-valid-pattern` | 303 | 0 | resource_type MUST match pattern ^[a-zA-Z][a-zA-Z0-9_/-]*$ |
| ✅ | 9.1 | `template-format-matches-provider` | 303 | 0 | template_format MUST match provider |
| ✅ | 3.2 | `slot-syntax-abnf-valid` | 303 | 0 | All slots MUST conform to ABNF grammar: field-name = 1*(ALPHA / DIGIT / "-" / "_") |

## SAP

> 79 dictionary entries · 330 template samples · 0 sample records

### Template Rules

| Status | Sec | Rule | ✅ Pass | ❌ Fail | Requirement |
|:------:|:---:|------|-------:|-------:|-------------|
| ✅ | 3.2 | `slot-delimiter-not-in-literal` | 330 | 0 | Characters { and } MUST NOT appear outside slot expressions |
| ✅ | 3.3.1 | `named-var-no-default` | 330 | 0 | Named variable MUST NOT be treated as implying any default value |
| ✅ | 3.3.1 | `named-var-requires-substitution` | 330 | 0 | Named variable MUST substitute concrete value before using template as live identifier |
| ✅ | 3.3.2 | `wildcard-not-live-identifier` | 330 | 0 | Wildcard MUST NOT be used as live identifier against provider API |
| ✅ | 3.3.4 | `hardcoded-value-as-is` | 330 | 0 | Consumer MUST use hardcoded value as-is; MUST NOT substitute alternative value |
| ✅ | 3.4 | `slot-state-precedence` | 330 | 0 | Producer MUST select slot state according to precedence |
| ✅ | 3.4 | `wildcard-not-fallback` | 330 | 0 | Producer MUST NOT use wildcard as fallback when correct state is unknown |
| ✅ | 3.2 | `template-produces-valid-id` | 330 | 0 | Conformant CRIT template MUST produce valid identifier after variable resolution |
| ✅ | 6.1 | `aws-global-region-hardcoded` | 330 | 0 | AWS global-only services: region MUST be hardcoded to us-east-1 or empty |
| ✅ | 6.1 | `aws-regional-region-variable` | 330 | 0 | AWS regional services: region MUST be named variable or wildcard, MUST NOT be empty |
| ✅ | 6.4 | `cloudflare-no-region-slot` | 330 | 0 | Producer MUST NOT add region slot to Cloudflare templates |
| ✅ | 7.1 | `resolution-produces-valid-id` | 330 | 0 | After variable resolution, result MUST be valid provider identifier |
| ✅ | 7.2 | `reserved-field-names-used` | 330 | 0 | Producer MUST use reserved field names where applicable |
| ✅ | 5 | `template-field-valid-after-resolution` | 330 | 0 | After all named variables substituted, result MUST be valid provider identifier for declared template_format |
| ✅ | 12.2 | `dictionary-entry-required-fields` | 330 | 0 | All fields except notes are REQUIRED in dictionary entry |
| ✅ | 12.1.1 | `dictionary-tuple-resolves` | 330 | 0 | (provider, service, resource_type) tuple MUST resolve to entry in conformant dictionary |
| ✅ | 9.1 | `service-key-lowercase-underscore` | 330 | 0 | service field MUST match pattern ^[a-z][a-z0-9_]*$ |
| ✅ | 9.1 | `resource-type-valid-pattern` | 330 | 0 | resource_type MUST match pattern ^[a-zA-Z][a-zA-Z0-9_/-]*$ |
| ✅ | 9.1 | `template-format-matches-provider` | 330 | 0 | template_format MUST match provider |
| ✅ | 3.2 | `slot-syntax-abnf-valid` | 330 | 0 | All slots MUST conform to ABNF grammar: field-name = 1*(ALPHA / DIGIT / "-" / "_") |

## ServiceNow

> 69 dictionary entries · 345 template samples · 0 sample records

### Template Rules

| Status | Sec | Rule | ✅ Pass | ❌ Fail | Requirement |
|:------:|:---:|------|-------:|-------:|-------------|
| ✅ | 3.2 | `slot-delimiter-not-in-literal` | 345 | 0 | Characters { and } MUST NOT appear outside slot expressions |
| ✅ | 3.3.1 | `named-var-no-default` | 345 | 0 | Named variable MUST NOT be treated as implying any default value |
| ✅ | 3.3.1 | `named-var-requires-substitution` | 345 | 0 | Named variable MUST substitute concrete value before using template as live identifier |
| ✅ | 3.3.2 | `wildcard-not-live-identifier` | 345 | 0 | Wildcard MUST NOT be used as live identifier against provider API |
| ✅ | 3.3.4 | `hardcoded-value-as-is` | 345 | 0 | Consumer MUST use hardcoded value as-is; MUST NOT substitute alternative value |
| ✅ | 3.4 | `slot-state-precedence` | 345 | 0 | Producer MUST select slot state according to precedence |
| ✅ | 3.4 | `wildcard-not-fallback` | 345 | 0 | Producer MUST NOT use wildcard as fallback when correct state is unknown |
| ✅ | 3.2 | `template-produces-valid-id` | 345 | 0 | Conformant CRIT template MUST produce valid identifier after variable resolution |
| ✅ | 6.1 | `aws-global-region-hardcoded` | 345 | 0 | AWS global-only services: region MUST be hardcoded to us-east-1 or empty |
| ✅ | 6.1 | `aws-regional-region-variable` | 345 | 0 | AWS regional services: region MUST be named variable or wildcard, MUST NOT be empty |
| ✅ | 6.4 | `cloudflare-no-region-slot` | 345 | 0 | Producer MUST NOT add region slot to Cloudflare templates |
| ✅ | 7.1 | `resolution-produces-valid-id` | 345 | 0 | After variable resolution, result MUST be valid provider identifier |
| ✅ | 7.2 | `reserved-field-names-used` | 345 | 0 | Producer MUST use reserved field names where applicable |
| ✅ | 5 | `template-field-valid-after-resolution` | 345 | 0 | After all named variables substituted, result MUST be valid provider identifier for declared template_format |
| ✅ | 12.2 | `dictionary-entry-required-fields` | 345 | 0 | All fields except notes are REQUIRED in dictionary entry |
| ✅ | 12.1.1 | `dictionary-tuple-resolves` | 345 | 0 | (provider, service, resource_type) tuple MUST resolve to entry in conformant dictionary |
| ✅ | 9.1 | `service-key-lowercase-underscore` | 345 | 0 | service field MUST match pattern ^[a-z][a-z0-9_]*$ |
| ✅ | 9.1 | `resource-type-valid-pattern` | 345 | 0 | resource_type MUST match pattern ^[a-zA-Z][a-zA-Z0-9_/-]*$ |
| ✅ | 9.1 | `template-format-matches-provider` | 345 | 0 | template_format MUST match provider |
| ✅ | 3.2 | `slot-syntax-abnf-valid` | 345 | 0 | All slots MUST conform to ABNF grammar: field-name = 1*(ALPHA / DIGIT / "-" / "_") |

---

*Generated by `crit-test` from [draft-vulnetix-crit-00](../drafts/draft-vulnetix-crit-00.xml)*

<!-- sha256: 2822ded0d91d97b10856f3ccd121dc228d2784479376b0255b35bdab207c1fbf -->
