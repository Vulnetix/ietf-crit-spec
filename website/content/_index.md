---
title: CRIT — Cloud Resource Identifier Templates
layout: hextra-home
---

{{< hextra/hero-badge link="https://github.com/Vulnetix/ietf-crit-spec" >}}
  <span>v0.3.0 — draft-vulnetix-crit-02</span>
  {{< icon name="arrow-circle-right" attributes="height=14" >}}
{{< /hextra/hero-badge >}}

<div class="hx-mt-8 hx-mb-8">
{{< hextra/hero-headline >}}
  Cloud Resource Identifier&nbsp;<br class="sm:hx-block hx-hidden" />Templates
{{< /hextra/hero-headline >}}
</div>

<div class="hx-mb-10">
{{< hextra/hero-subtitle >}}
  A machine-readable format for identifying cloud resources affected by&nbsp;<br class="sm:hx-block hx-hidden" />known vulnerabilities. CVSS-style for cloud-native CVEs.
{{< /hextra/hero-subtitle >}}
</div>

<div class="hx-mb-6 hx-flex hx-flex-wrap hx-gap-3">
  <a href="validator/" class="hx-inline-flex hx-items-center hx-justify-center hx-rounded-md hx-bg-primary-600 hx-text-white hx-px-5 hx-py-2.5 hx-text-sm hx-font-semibold hover:hx-bg-primary-700">Try the Validator</a>
  <a href="docs/" class="hx-inline-flex hx-items-center hx-justify-center hx-rounded-md hx-border hx-border-gray-300 dark:hx-border-neutral-700 hx-px-5 hx-py-2.5 hx-text-sm hx-font-semibold hover:hx-bg-gray-50 dark:hover:hx-bg-neutral-800">Read the Docs</a>
  <a href="https://www.vulnetix.com/crit" class="hx-inline-flex hx-items-center hx-justify-center hx-rounded-md hx-border hx-border-gray-300 dark:hx-border-neutral-700 hx-px-5 hx-py-2.5 hx-text-sm hx-font-semibold hover:hx-bg-gray-50 dark:hover:hx-bg-neutral-800" target="_blank" rel="noopener">Why CRIT — Stats &amp; Adoption →</a>
</div>

{{< hextra/feature-grid >}}
  {{< hextra/feature-card
    title="In-browser validator"
    subtitle="Paste a CRIT record or a CVE 5.x record with x_crit. Instant JSON Schema validation, vector round-trip checks, dictionary resolution. No data leaves your browser."
    link="validator/"
    class="hx-aspect-auto md:hx-aspect-[1.1/1] max-md:hx-min-h-[340px]"
  >}}

  {{< hextra/feature-card
    title="Vector strings"
    subtitle="CVSS-style compact encoding. CRITv0.3.0/CP:AW/VS:FX/FP:RR/SR:SH/RL:SM/EV:T/PP:.../SA:...#CVE-2024-21626:eks:cluster — deterministic, parseable, signable."
    link="docs/vector-string/"
    class="hx-aspect-auto md:hx-aspect-[1.1/1] max-md:hx-min-h-[340px]"
  >}}

  {{< hextra/feature-card
    title="30+ provider dictionaries"
    subtitle="AWS, Azure, GCP, Cloudflare, Oracle, Salesforce, SAP, ServiceNow plus 20+ extended providers covering Tier-2 IaaS and Tier-3 SaaS — all shipped in the spec library."
    link="docs/dictionaries/"
    class="hx-aspect-auto md:hx-aspect-[1.1/1] max-md:hx-min-h-[340px]"
  >}}

  {{< hextra/feature-card
    title="CVE 5.x ADP integration"
    subtitle="CRIT records embed in CVE 5.x via the ADP container's x_crit array. The validator parses both single-record and CVE-with-x_crit shapes."
    link="docs/adp-integration/"
  >}}

  {{< hextra/feature-card
    title="VEX-aware"
    subtitle="vex_status, fix_propagation, shared_responsibility, resource_lifecycle — all spec-bound enums with cross-field consistency rules the validator checks."
    link="docs/spec/"
  >}}

  {{< hextra/feature-card
    title="Open standard"
    subtitle="Independent submission to the IETF — draft-vulnetix-crit-02. Published under the Trust Provisions. Apache 2.0 implementation reference."
    link="https://datatracker.ietf.org/doc/draft-vulnetix-crit/"
  >}}
{{< /hextra/feature-grid >}}
