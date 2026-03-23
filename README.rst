=============================================
Cloud Resource Identifier Templates (CRIT)
=============================================

A machine-readable format for identifying cloud resources affected by known
vulnerabilities.

| **Specification:** ``draft-vulnetix-crit-00`` (Independent Submission, Informational)
| **Read:** ``build/draft-vulnetix-crit-00.html`` -- **Edit:** ``drafts/draft-vulnetix-crit-00.xml``
| **Author:** Christopher Daniel Langton, Vulnetix
| **Status:** Active development


Abstract
========

A CRIT record provides a machine-readable, parameterised template for locating
cloud-native resources affected by a known vulnerability. CRITs do not define
cloud resource identifier schemas; those are defined normatively by each cloud
provider. CRITs define a variable system for expressing partially-known or
consumer-resolved values within those provider-defined schemas, together with
temporal, remediation, and detection metadata sufficient to determine exposure
status and drive remediation workflows.

Each CRIT record is bound to exactly one vulnerability identifier.
Cross-provider and multi-resource-type coverage of a single vulnerability is
expressed as a set of CRIT records sharing the same vulnerability identifier,
each independently specifying the provider-specific fix details, propagation
mechanism, and detection strategy applicable to that resource type.


What CRIT Is --- and What It Is Not
====================================

If the problem could be described in one word, that word is **affected**.

For packages, "affected" is a version comparison: if the installed version
falls within the affected range, the package is vulnerable. Cloud resources
have no equivalent comparison. "Affected" is a function of four factors that
must be evaluated simultaneously: when the resource was deployed relative to
the fix, the fix propagation type, whether the consumer has acted, and whether
a previously applied remediation has been reverted by configuration drift.
No static identifier carries these factors. CRIT encodes all four.


CRIT Is
-------

- **A template engine for cloud-native resources.** Discovery requires
  interpolation of consumer-specific variables (account, region, resource ID)
  at resolution time. No static identifier can express this.

- **A solution to the "affected" problem.** It encodes deployment timing, fix
  propagation type, consumer action state, and configuration drift status ---
  everything required to determine whether a specific deployed resource is
  impacted.

- **A parameterisation layer over provider-native identifier schemas.** CRITs
  do not invent identifier formats. AWS ARNs, Azure Resource IDs, GCP Resource
  Names, Cloudflare Locators, and Oracle OCIDs are adopted as-is. CRIT
  parameterises them with variable slots.

- **An extension to existing vulnerability data formats.** CRIT integrates
  with CVEListv5 ADP containers and OSV schema using their existing extension
  mechanisms. It does not require changes to those specifications.

- **A machine-readable encoding of fix propagation, remediation actions,
  detection queries, and exposure window computation** --- the metadata that
  turns a vulnerability advisory into an actionable remediation workflow for
  cloud resources.


CRIT Is Not
-----------

- **Not an identifier.** Cloud resources already have identifiers. CRITs
  reference them; they do not define new ones. The CRIT vectorString is a
  natural composite key (replacing the UUID), not a resource identifier.

- **Not a replacement for CPE, PURL, CycloneDX, or SPDX.** Those standards
  solve identification, inventory, and risk prioritisation for build-from-source
  artifacts. CRIT complements them by addressing cloud resource scope where
  they do not apply.

- **Not a single string that can encode the full record.** The CRIT
  vectorString is a lossy compact encoding of 12 enumerable fields from a 30+
  field record. Descriptive values, detection queries, remediation action
  descriptions, provider-native templates, and consumer-specific variables
  cannot be represented in any static string. Any attempt to reduce CRIT to a
  single-string identifier discards the metadata that solves the problem.

- **Not a risk scoring or prioritisation system.** CRIT does not assign
  severity, CVSS scores, or risk rankings. Risk-based prioritisation signals
  (EPSS, CVSS, SSVC) remain complementary inputs to consumer tooling.

- **Not a replacement for cloud provider security advisories.** CRIT
  references provider advisories; it does not replace them. Provider advisory
  URLs and identifiers are carried as metadata within the record.

- **Not a software inventory or bill-of-materials format.** CRIT records
  describe how vulnerabilities affect cloud resources. They are not an
  inventory of deployed resources or a software composition.


Why Not PURL?
-------------

PURL succeeds because package identity is static:
``pkg:npm/@angular/core@12.3.1`` is the same string regardless of where the
package is installed. Cloud resource identity is not static. An RDS instance's
ARN contains an account ID, region, and resource ID that do not exist until the
resource is deployed. Even if a PURL were constructed at that granularity, it
would carry none of the information required to determine affected status: the
deployment date relative to the fix, the propagation mechanism, whether the
consumer has acted, or whether a configuration change has been reverted.

The ``pkg:cloud/`` convention observed in OSV is not a registered PURL type.
Regardless of the type scheme, a static string cannot express the interpolation
that discovery requires or the temporal and propagation logic that
affected-status determination demands.


Install
=======

``crit-validate`` checks CVE records containing CRIT extensions against the
specification rules. The binary embeds the Spec Default Dictionary (513 entries)
and the dictionary JSON Schema at build time -- no external files required.

.. code-block:: bash

   # Homebrew
   brew install vulnetix/tap/crit-validate   # first time
   brew upgrade crit-validate                # update

   # Go
   go install github.com/Vulnetix/ietf-crit-spec/cmd/crit-validate@latest

Then point it at a directory of CVE records:

.. code-block:: bash

   crit-validate --data data --report reports

To validate with additional custom dictionaries (e.g. for a new provider or
resource types not yet in the spec):

.. code-block:: bash

   crit-validate --data data --dictionary /path/to/my-dictionaries/

Custom dictionaries are validated against the embedded JSON Schema before being
merged with the built-in entries. They can supplement but not override the Spec
Default Dictionary.

Flags:

===============================  ====================================================
``--data <dir>``                 Directory of CVEListv5 JSON files to validate
``--dictionary <file-or-dir>``   Custom dictionary file or directory to merge with built-in
``--report <dir>``               Write dated Markdown report to the given directory
``--adp-short-name``             ADP short name to look for (default: ``VVD``)
``--no-fail``                    Exit 0 even when tests fail (report-only mode)
``--quiet``                      Suppress console output (only write report)
===============================  ====================================================

Convert between CRIT vector strings and JSON:

.. code-block:: bash

   # JSON sample → vector string
   crit-validate convert --from-json samples/aws/cve-2024-6387-ec2-openssh.json

   # Vector string → expanded JSON
   crit-validate convert --from-vector "CRITv0.2.0/CP:AW/VS:FX/FP:RR/SR:CA/RL:SC/EV:T/PP:1719792000/SA:1187740800#CVE-2024-6387:ec2:instance"


CRIT Vector String
==================

Each CRIT record carries a ``vectorString`` field -- a compact, deterministic
encoding of the record's classification and identity, modelled on CVSS vector
strings:

.. code-block:: text

   CRITv0.2.0/CP:AW/VS:FX/FP:RR/SR:CA/RL:SC/EV:T/PP:1719792000/SA:1514764800#CVE-2024-6387:ec2:instance

The vector has two parts separated by ``#``:

- **Metrics** (before ``#``): abbreviated enum values in fixed order --
  Cloud Provider (CP), VEX Status (VS), Fix Propagation (FP),
  Shared Responsibility (SR), Resource Lifecycle (RL),
  Existing Vulnerable (EV), Published Date epoch (PP),
  Service Available Date epoch (SA).
- **Qualifiers** (after ``#``): positional colon-separated literal values --
  vuln_id, service, resource_type.

Unknown metrics are tolerated by consumers for forward compatibility.
See the specification Section 4.1.2 for the full ABNF grammar and
metric registry tables.


The Vision
==========

In 1999, CVE gave the world a shared numbering system for vulnerabilities. CPE
gave the world a shared naming system for products. Together, those two
standards made Software Composition Analysis possible. Before CVE and CPE,
every vendor maintained proprietary vulnerability databases with proprietary
naming. After CVE and CPE, an entire industry emerged: the SCA vendor ecosystem
that underpins modern software security.

Cloud infrastructure has no equivalent. Until CRIT.

There are 513 distinct resource types across AWS, Azure, GCP, Cloudflare, and
Oracle in the CRIT dictionaries today. Not one of them can be expressed in CPE
or PURL in a way that a CSPM tool can use for automated vulnerability matching.
The result: Cloud Security Posture Management tools handle misconfigurations
and vendor insecure defaults. They check if your S3 bucket is public or your
security group allows ``0.0.0.0/0``. They flag insecure failure modes and
missing secure defaults. But nobody -- no vendor, no open-source tool, nobody
-- can do real numbered vulnerability scanning of cloud resources today.

When CVE-2024-6387 (regreSSHion) droped, a CSPM tool cannot tell you which of
your 400 EC2 instances across 12 regions were launched from AMIs that contain
the vulnerable OpenSSH build. When CVE-2024-21626 hits every managed Kubernetes
service simultaneously, there is no machine-readable way to express "this CVE
affects GKE clusters running runc < 1.1.12 and the fix propagates via version
update with auto-upgrade." That is the gap.

The entire cloud security industry has been locked into scanning for
configuration mistakes -- customer footguns and vendor footguns -- because there
has been no standard for expressing actual vulnerabilities in cloud-native
resources. Not misconfigurations. Not compliance drift. Real vulnerabilities
with CVE numbers, affected resource types, fix propagation semantics, and
exposure windows.

CRIT is to cloud resources what CVE and CPE was to software packages. It gives
the vulnerability ecosystem a machine-readable, standardised way to say "this
CVE affects this type of cloud resource, identified by this template, and here
is what you need to know about remediation." CRIT will unlock actual
vulnerability scanning for cloud, SaaS, and AI-hosted resources -- the missing
capability that turns CSPM from a configuration checker into a real
vulnerability management platform.


How CRIT Works
==============

CRIT has three core elements: **templates**, **slots**, and **dictionaries**.

Templates
---------

A CRIT template is a provider-native resource identifier with parameterised
variable slots. CRIT does not invent identifier formats. Each cloud provider
defines its own schema. CRIT parameterises them so that a single template can
represent all instances of a resource type.

===========  ==================  =============================================
Provider     Format              Example Template
===========  ==================  =============================================
AWS          ARN                 ``arn:aws:ec2:{region}:{account}:instance/{resource-id}``
Azure        Resource ID         ``/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Web/sites/{name}``
GCP          Resource Name       ``//container.googleapis.com/projects/{project}/locations/{location}/clusters/{cluster}``
Cloudflare   API Locator         ``com.cloudflare.api.account.{account_id}.zone.{id}``
Oracle       OCID                ``ocid1.instance.{realm=oc1}.{region}..{unique-id}``
===========  ==================  =============================================

Slots
-----

Each variable slot in a template expresses one of four semantic states:

+-------------------------+-----------------+------------------------------------------------+
| Syntax                  | State           | Meaning                                        |
+=========================+=================+================================================+
| ``{region}``            | Named Variable  | Consumer must supply a concrete value           |
+-------------------------+-----------------+------------------------------------------------+
| ``{region=us-east-1}``  | Hardcoded       | Fixed by the provider schema; use as-is         |
+-------------------------+-----------------+------------------------------------------------+
| ``{region=*}``          | Wildcard        | Match all values; inventory query pattern       |
+-------------------------+-----------------+------------------------------------------------+
| ``{zone=}``             | Empty           | Field structurally present but not applicable   |
+-------------------------+-----------------+------------------------------------------------+

Resolving a template replaces each slot with a concrete value:

.. code-block:: text

   Template:  arn:aws:ec2:{region}:{account}:instance/{resource-id}
   Resolved:  arn:aws:ec2:us-west-2:123456789012:instance/i-0abcdef1234567890

Hardcoded slots carry fixed values determined by the provider schema:

.. code-block:: text

   arn:aws:cloudfront:{region=us-east-1}:{account}:distribution/{resource-id}
                      ^^^^^^^^^^^^^^^^^ hardcoded: CloudFront is global, always us-east-1

Dictionaries
------------

CRIT ships default dictionaries -- JSON files cataloguing every known resource
type for each provider. The repository contains five dictionaries covering 512
resource types:

==========================  ===============
Dictionary                  Resource Types
==========================  ===============
``dictionaries/aws.json``           238
``dictionaries/azure.json``          88
``dictionaries/gcp.json``            77
``dictionaries/cloudflare.json``     43
``dictionaries/oracle.json``         67
==========================  ===============

Each dictionary entry maps a ``(service, resource_type)`` tuple to a template
and metadata:

.. code-block:: json

   {
     "service": "ec2",
     "resource_type": "instance",
     "template": "arn:aws:ec2:{region}:{account}:instance/{resource-id}",
     "template_format": "aws_arn",
     "region_behavior": "regional"
   }


Real-World Data
===============

CRIT in CVE Records
-------------------

In production, CRIT records live inside CVE_RECORD v5.1 ADP containers. The
``data/`` directory contains 17 complete CVE records with embedded CRIT data.
Here is the structure -- a Vulnetix VVD ADP container carries an ``x_crit``
array with one entry per affected provider and resource type:

.. code-block:: json

   {
     "dataType": "CVE_RECORD",
     "cveMetadata": {
       "cveId": "CVE-2024-6387",
       "state": "PUBLISHED"
     },
     "containers": {
       "cna": { "...": "CNA vulnerability data" },
       "adp": [
         { "...": "other ADP containers" },
         {
           "providerMetadata": {
             "orgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
             "shortName": "VVD"
           },
           "title": "Vulnetix Vulnerability Database Enrichment",
           "x_crit": [
             {
               "crit_version": "0.2.0",
               "vuln_id": "CVE-2024-6387",
               "provider": "aws",
               "service": "ec2",
               "resource_type": "instance",
               "template": "arn:aws:ec2:{region}:{account}:instance/{resource-id}",
               "template_format": "aws_arn",
               "fix_propagation": "rebuild_and_redeploy",
               "existing_deployments_remain_vulnerable": true
             },
             {
               "...": "additional provider/resource entries for this CVE"
             }
           ]
         }
       ]
     }
   }

The ``x_crit`` array can contain multiple records when a CVE affects resources
across different providers or resource types. Each record is self-contained
with its own template, fix propagation semantics, and remediation actions.

Use ``crit-validate`` to check these files:

.. code-block:: bash

   crit-validate --data data --report tests/reports

Per-Provider CRIT Records
-------------------------

The ``samples/`` directory contains 33 hand-authored CRIT records -- the
individual ``x_crit`` entries extracted into standalone files for testing and
reference. Three examples below show CRIT records for well-known
vulnerabilities.

**regreSSHion on AWS EC2 (CVE-2024-6387)**

The OpenSSH race condition RCE that affected every EC2 instance running
OpenSSH < 9.8p1:

.. code-block:: json

   {
     "crit_version": "0.2.0",
     "vuln_id": "CVE-2024-6387",
     "provider": "aws",
     "service": "ec2",
     "resource_type": "instance",
     "template": "arn:aws:ec2:{region}:{account}:instance/{resource-id}",
     "template_format": "aws_arn",
     "fix_propagation": "rebuild_and_redeploy",
     "existing_deployments_remain_vulnerable": true
   }

``fix_propagation: "rebuild_and_redeploy"`` combined with
``existing_deployments_remain_vulnerable: true`` tells a CSPM tool that
instances launched before the fix are still exposed and must be rebuilt from a
patched AMI. No automatic fix.

**HTTP/2 Rapid Reset on Cloudflare (CVE-2023-44487)**

The HTTP/2 protocol-level DDoS attack that hit 201 million requests per second:

.. code-block:: json

   {
     "crit_version": "0.2.0",
     "vuln_id": "CVE-2023-44487",
     "provider": "cloudflare",
     "service": "dns",
     "resource_type": "zone",
     "template": "com.cloudflare.api.account.{account_id}.zone.{id}",
     "template_format": "cloudflare_locator",
     "fix_propagation": "automatic",
     "existing_deployments_remain_vulnerable": false
   }

``fix_propagation: "automatic"`` with
``existing_deployments_remain_vulnerable: false`` -- Cloudflare deployed the
fix across its entire edge network. No customer action required. Every zone is
already protected.

**runc Container Escape on GKE (CVE-2024-21626)**

The runc working directory escape that affected every major managed Kubernetes
service:

.. code-block:: json

   {
     "crit_version": "0.2.0",
     "vuln_id": "CVE-2024-21626",
     "provider": "gcp",
     "service": "kubernetes_engine",
     "resource_type": "cluster",
     "template": "//container.googleapis.com/projects/{project}/locations/{location}/clusters/{cluster}",
     "template_format": "gcp_resource_name",
     "fix_propagation": "version_update",
     "existing_deployments_remain_vulnerable": true
   }

``fix_propagation: "version_update"`` -- GKE clusters with auto-upgrade
enabled receive the fix automatically during their next maintenance window.
Clusters with auto-upgrade disabled must be manually upgraded.


Contributing Dictionaries
=========================

Dictionary files live in ``dictionaries/`` and follow the schema at
``schemas/crit-dictionary-v0.2.0.schema.json``.

Adding a New Entry
------------------

1. Identify the provider-native resource identifier format from the provider's
   documentation (e.g. the ARN pattern from AWS docs).

2. Determine slot states for each field: which are consumer-supplied (named
   variable), which are fixed by the provider (hardcoded), which are
   structurally absent (empty).

3. Add the entry to the appropriate dictionary file:

   .. code-block:: json

      {
        "service": "new_service",
        "resource_type": "resource_name",
        "template": "arn:aws:newservice:{region}:{account}:resource/{resource-id}",
        "template_format": "aws_arn",
        "region_behavior": "regional"
      }

4. Ensure the ``(service, resource_type)`` tuple is unique within the file.

5. Validate:

   .. code-block:: bash

      just validate-dictionaries
      just validate-dictionaries-unique-keys

Adding Wordlists for New Slot Fields
-------------------------------------

If a new entry introduces slot field names not yet covered, add a wordlist:

.. code-block:: text

   tests/wordlists/<provider>/<field-name>.txt

Each file contains one value per line -- realistic but synthetic values. For
example, ``tests/wordlists/aws/region.txt`` contains AWS region identifiers
like ``us-east-1``, ``eu-west-2``, etc.

Run the full test suite to verify everything passes:

.. code-block:: bash

   just test


Writing Samples and Rules
=========================

Writing CRIT Samples
--------------------

Hand-authored CRIT records go in ``samples/<provider>/`` with the naming
convention:

.. code-block:: text

   samples/<provider>/cve-YYYY-NNNNN-<service>-<brief-description>.json

Each sample must include: ``crit_version``, ``id`` (UUID), ``vuln_id``,
``provider``, ``service``, ``resource_type``, ``template``,
``template_format``, ``temporal``, ``fix_propagation``,
``existing_deployments_remain_vulnerable``, and ``remediation_actions``.

Conformance Testing
-------------------

All spec conformance rules live in a single tool at
``tests/cmd/crit-test/main.go``. It generates template samples from
dictionaries + wordlists, then runs 60 rules in two suites:

- **Template Rules (20)** -- slot syntax, provider-specific constraints,
  template format validity, dictionary conformance
- **Sample Record Rules (28)** -- date formats, natural key integrity,
  temporal constraints, fix propagation logic, remediation action sequencing,
  CVSS validation, detection requirements, pending detection reason validation

Run the full spec test suite:

.. code-block:: bash

   just test-spec

Or directly with Go:

.. code-block:: bash

   go run ./tests/cmd/crit-test --report tests/reports

The tool produces a single consolidated Markdown report
(``YYYYMMDD-crit-test-report.md``) with Mermaid charts and per-rule results
for both suites. SHOULD-level rules produce warnings that do not affect exit
codes; only MUST-level failures cause a non-zero exit.

Schemas
-------

- ``schemas/crit-dictionary-v0.2.0.schema.json`` -- validates dictionary files;
  enforces per-provider ``template_format`` constraints and
  ``(service, resource_type)`` field patterns.
- ``schemas/crit-samples-v0.1.0.schema.json`` -- validates generated test
  samples output (``tests/CRIT-samples.json``).

Wordlists
---------

Wordlists in ``tests/wordlists/<provider>/<field>.txt`` provide realistic
synthetic values for template slot interpolation. The test generator reads
dictionaries and wordlists, then produces resolved identifiers using
round-robin selection across wordlist entries.


Developer Reference
===================

Prerequisites
-------------

.. note::

   - **Go 1.23+** -- test programs and ``crit-validate``
   - **xml2rfc** -- building the IETF draft (``pip install xml2rfc``)
   - **check-jsonschema** -- JSON Schema validation (``pip install check-jsonschema``)
   - **jq** -- dictionary uniqueness checks
   - **just** -- command runner (``cargo install just`` or platform package)

Setup
-----

.. code-block:: bash

   git clone https://github.com/Vulnetix/ietf-crit-spec.git
   cd ietf-crit-spec
   just setup-hooks

``just setup-hooks`` configures the pre-commit hook at ``.githooks/pre-commit``
which runs the full conformance test suite before every commit. Commits are
blocked if any rule fails.

Commands
--------

====================================  ===========================================================
Command                               Description
====================================  ===========================================================
``just test``                         Full test suite (spec rules + schema validation + CVE validation)
``just test-spec``                    Run all 48 spec conformance rules (generates samples, runs both suites)
``just test-validate-samples``        Validate ``CRIT-samples.json`` against its JSON schema
``just test-cve-crit``               Validate CVE+CRIT data files with ``crit-validate``
``just test-clean``                   Remove previous test report files
``just validate-all``                 XML draft validation + dictionary schema + uniqueness checks
``just build``                        Generate HTML and text RFC output in ``build/``
``just fetch-cve-data``              Download CVE records and inject VVD ADP containers from samples
``just setup-hooks``                  Configure git pre-commit hook
``just check``                        Validate XML draft syntax
``just clean``                        Remove generated output files
====================================  ===========================================================

Test Architecture
-----------------

Two Go programs drive the test infrastructure:

**crit-test** (``tests/cmd/crit-test/main.go``)
   Unified spec conformance test runner. Generates interpolated template
   samples from dictionaries + wordlists, then runs 60 rules in two suites:
   20 template-level rules (slot syntax, provider constraints, format validity)
   and 40 record-level rules (dates, natural keys, fix propagation, remediation
   sequencing, CVSS validation, detection requirements, pending detection
   reason validation). Produces a single
   consolidated Markdown report with Mermaid charts.

**crit-validate** (``cmd/crit-validate/main.go``)
   Validates CVEListv5 JSON files containing VVD ADP containers with ``x_crit``
   extensions. Checks CVE record structure, ADP container presence, and
   embedded CRIT record conformance. Installable via ``go install``.


For IETF Spec Editors
=====================

This is an independent submission targeting informational RFC status. The
source is in xml2rfc v3 format (RFC 7991bis schema) at
``drafts/draft-vulnetix-crit-00.xml``.

Building the Draft
------------------

.. code-block:: bash

   just check      # Validate XML (preptool, catches errors)
   just build      # Generate HTML + text output in build/
   just prep       # Run preptool to produce prepped XML
   just expand     # Expand all references to full XML

PR Expectations
---------------

- Editorial PRs should touch only files in ``drafts/``.
- Run ``just check`` before submitting to verify XML validates.
- Run ``just build`` to confirm HTML and text render correctly.
- PRs modifying normative text (MUST/SHOULD/MAY) should reference the relevant
  spec section anchor (e.g. ``anchor="vs-syntax"``, ``anchor="vs-states"``,
  ``anchor="dictionary-entry"``).
- Dictionary or sample changes that accompany spec text changes should include
  updated test results -- commit with ``just test`` passing via the pre-commit
  hook.

.. important::

   The pre-commit hook runs the full test suite automatically. If conformance
   tests fail, the commit will be blocked. This is intentional. Do not bypass
   the hook.


Repository Structure
====================

.. code-block:: text

   ietf-crit-spec/
     cmd/
       crit-validate/           CVE+CRIT validator (go install)
     drafts/                    IETF XML source (xml2rfc v3)
       draft-vulnetix-crit-00.xml
     dictionaries/              Provider service catalogs (JSON)
       aws.json                   238 resource types
       azure.json                  88 resource types
       cloudflare.json             43 resource types
       gcp.json                    77 resource types
       oracle.json                 67 resource types
     data/                      CVE records with embedded CRIT (CVEListv5)
       2021/                      1 record
       2023/                      2 records
       2024/                      14 records
     samples/                   33 hand-authored per-provider CRIT records
       aws/                       11 records
       azure/                      8 records
       cloudflare/                 4 records
       gcp/                        5 records
       oracle/                     5 records
     schemas/                   JSON Schema definitions
       crit-dictionary-v0.2.0.schema.json
       crit-samples-v0.1.0.schema.json
     tests/                     Go test infrastructure
       cmd/
         crit-test/               Unified conformance runner (60 rules, single report)
       wordlists/                Provider-specific synthetic test data
       CRIT-samples.json         Generated test samples (not committed)
       reports/                  Dated conformance reports
     build/                     Generated HTML/text RFC output
     justfile                   Command recipes
     .githooks/pre-commit       Conformance gate


Thank You
=========

If you have read this far, thank you. Genuinely.

This project exists because cloud security has a structural gap that affects
everyone who runs infrastructure in the cloud. The vulnerability ecosystem
built incredible tools for packages and operating systems over 25 years. Cloud
resources got left behind -- not because nobody cared, but because the
identifier problem is genuinely hard and nobody had defined a common format to
solve it.

CRIT is an attempt to fix that. It is an early-stage specification. The intial
dictionaries are a subset of a vast ecosystem. The test coverage will grow.
There are providers and resource types not yet represented. If you see something
missing, something wrong, or something that could be better, please open an issue
or submit a PR. Every contribution moves this forward.

Whether you are a CSPM vendor evaluating the format, a security researcher
interested in cloud vulnerability data, a cloud provider who wants to see your
services represented accurately, or someone who just finds this problem
interesting -- your time and attention are appreciated. This specification will
be better because you looked at it.
