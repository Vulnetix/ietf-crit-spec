/* CRIT in-browser validator
 *
 * Pure JS port of github.com/Vulnetix/ietf-crit-spec ComputeVector +
 * ParseVector + ValidateRecord, plus a CVE 5.x ADP/x_crit walker.
 *
 * Loads:
 *   /schemas/crit-record-v0.3.0.schema.json
 *   /schemas/crit-dictionary-v0.3.0.schema.json
 *   /dictionaries/<provider>.json
 *
 * Uses ajv 8 (loaded from CDN by the shortcode) for JSON Schema
 * validation. All work is client-side; nothing leaves the browser.
 */
(function () {
  'use strict';

  const DEFAULT_SPEC_VERSION = '0.3.0';
  // Spec versions whose schemas + vector codec are bundled. Order matters
  // for "best effort" fallback — newest first.
  const SUPPORTED_SPEC_VERSIONS = ['0.3.0', '0.2.0'];
  const VECTOR_PREFIX_RE = /^CRITv(\d+\.\d+\.\d+)\//;

  // ---------------------------------------------------------------------
  // Vector codec — port of critvector.go
  // ---------------------------------------------------------------------

  const providerToCode = {
    aws: 'AW', azure: 'MA', gcp: 'GC', cloudflare: 'CF', oracle: 'OC',
    salesforce: 'SF', sap: 'SP', servicenow: 'SN', ibm: 'IB', vmware: 'VM',
    adobe: 'AD', akamai: 'AK', alibaba: 'AL', atlassian: 'AT',
    digitalocean: 'DO', elastic: 'EL', fastly: 'FA', gitlab: 'GL',
    hashicorp: 'HC', hetzner: 'HE', linode: 'LI', mongodb: 'MO',
    ovh: 'OV', snowflake: 'SO', tailscale: 'TS', tencent: 'TC',
    twilio: 'TW', vercel: 'VC', vultr: 'VL', zoom: 'ZM',
  };
  const vexStatusToCode = {
    affected: 'AF', fixed: 'FX', not_affected: 'NA', under_investigation: 'UI',
  };
  const fixPropToCode = {
    automatic: 'AU', config_change: 'CC', opt_in: 'OI',
    version_update: 'VU', redeploy: 'RD', rebuild_and_redeploy: 'RR',
    destroy_recreate: 'DC', rolling_replace: 'RL', no_fix_available: 'NF',
  };
  const sharedRespToCode = {
    provider_only: 'PO', customer_action_required: 'CA',
    customer_only: 'CO', shared: 'SH',
  };
  const lifecycleToCode = {
    ephemeral: 'EP', stateful_managed: 'SM', stateful_customer: 'SC',
    config_only: 'CF', global_control_plane: 'GC',
  };

  function reverseMap(m) {
    const r = {};
    for (const k in m) r[m[k]] = k;
    return r;
  }
  const codeToProvider = reverseMap(providerToCode);
  const codeToVEXStatus = reverseMap(vexStatusToCode);
  const codeToFixProp = reverseMap(fixPropToCode);
  const codeToSharedResp = reverseMap(sharedRespToCode);
  const codeToLifecycle = reverseMap(lifecycleToCode);

  const REGISTERED_KEYS = ['CP', 'VS', 'FP', 'SR', 'RL', 'EV', 'PP', 'SA'];

  /** Extract the CRITv<x.y.z> version from a stored vectorString.
   *  Returns null when the prefix is missing or malformed.
   */
  function detectVectorVersion(s) {
    if (typeof s !== 'string') return null;
    const m = VECTOR_PREFIX_RE.exec(s);
    return m ? m[1] : null;
  }

  /** Encode a structured CRIT record's classification fields to a vector
   *  string. Round-trip semantics: when called from validation we pass
   *  the stored vector's version so the recompute produces a byte-equal
   *  string for any supported spec version. New records default to the
   *  highest supported version.
   */
  function computeVector(rec, version) {
    const v = version || DEFAULT_SPEC_VERSION;
    const cp = providerToCode[rec.provider];
    if (!cp) throw new Error(`unknown provider "${rec.provider}"`);
    const vs = vexStatusToCode[rec.vex_status];
    if (!vs) throw new Error(`unknown vex_status "${rec.vex_status}"`);
    const fp = fixPropToCode[rec.fix_propagation];
    if (!fp) throw new Error(`unknown fix_propagation "${rec.fix_propagation}"`);
    const sr = sharedRespToCode[rec.shared_responsibility];
    if (!sr) throw new Error(`unknown shared_responsibility "${rec.shared_responsibility}"`);
    const rl = lifecycleToCode[rec.resource_lifecycle];
    if (!rl) throw new Error(`unknown resource_lifecycle "${rec.resource_lifecycle}"`);
    const ev = rec.existing_deployments_remain_vulnerable ? 'T' : 'F';
    if (!rec.vuln_id) throw new Error('vuln_id is required');
    if (!rec.service) throw new Error('service is required');
    if (!rec.resource_type) throw new Error('resource_type is required');

    const pp = dateToEpoch(rec?.temporal?.vuln_published_date);
    const sa = dateToEpoch(rec?.temporal?.service_available_date);

    return `CRITv${v}/CP:${cp}/VS:${vs}/FP:${fp}/SR:${sr}/RL:${rl}/EV:${ev}/PP:${pp}/SA:${sa}#${rec.vuln_id}:${rec.service}:${rec.resource_type}`;
  }

  function dateToEpoch(d) {
    if (!d) return 0;
    const t = Date.parse(d);
    if (Number.isNaN(t)) return 0;
    return Math.floor(t / 1000);
  }

  /** Parse a vector string. Returns { fields, warnings, error }. */
  function parseVector(s) {
    const warnings = [];
    if (!s.includes('#')) {
      return { error: `missing '#' delimiter between metrics and qualifiers` };
    }
    const [metricsPart, qualPart] = s.split('#', 2).concat([s.slice(s.indexOf('#') + 1)]).slice(0, 2);
    const trueQual = s.slice(s.indexOf('#') + 1);
    if (!metricsPart.startsWith('CRITv')) {
      return { error: `vector must start with 'CRITv'` };
    }
    const segments = metricsPart.slice(5).split('/');
    if (segments.length < 2) return { error: 'vector must contain version and at least one metric' };
    const version = segments[0];
    const metricSegments = segments.slice(1);

    const quals = trueQual.split(':');
    if (quals.length !== 3) {
      return { error: `qualifiers must have exactly 3 colon-separated values, got ${quals.length}` };
    }

    const out = {
      crit_version: version,
      vuln_id: quals[0],
      service: quals[1],
      resource_type: quals[2],
      unknown_metrics: {},
    };
    const seen = new Set();

    for (const seg of metricSegments) {
      const idx = seg.indexOf(':');
      if (idx < 0) return { error: `malformed metric segment "${seg}"`, warnings };
      const key = seg.slice(0, idx);
      const val = seg.slice(idx + 1);

      if (!REGISTERED_KEYS.includes(key)) {
        out.unknown_metrics[key] = val;
        warnings.push({ code: 'unknown_metric', message: `unknown metric "${key}" with value "${val}"` });
        continue;
      }
      seen.add(key);

      switch (key) {
        case 'CP': {
          const v = codeToProvider[val];
          if (!v) return { error: `unknown CP code "${val}"`, warnings };
          out.provider = v; break;
        }
        case 'VS': {
          const v = codeToVEXStatus[val];
          if (!v) return { error: `unknown VS code "${val}"`, warnings };
          out.vex_status = v; break;
        }
        case 'FP': {
          const v = codeToFixProp[val];
          if (!v) return { error: `unknown FP code "${val}"`, warnings };
          out.fix_propagation = v; break;
        }
        case 'SR': {
          const v = codeToSharedResp[val];
          if (!v) return { error: `unknown SR code "${val}"`, warnings };
          out.shared_responsibility = v; break;
        }
        case 'RL': {
          const v = codeToLifecycle[val];
          if (!v) return { error: `unknown RL code "${val}"`, warnings };
          out.resource_lifecycle = v; break;
        }
        case 'EV':
          if (val === 'T') out.existing_deployments_remain_vulnerable = true;
          else if (val === 'F') out.existing_deployments_remain_vulnerable = false;
          else return { error: `unknown EV code "${val}"`, warnings };
          break;
        case 'PP': {
          const n = Number.parseInt(val, 10);
          if (!Number.isFinite(n)) return { error: `PP must be an integer epoch: "${val}"`, warnings };
          out.vuln_published_epoch = n; break;
        }
        case 'SA': {
          const n = Number.parseInt(val, 10);
          if (!Number.isFinite(n)) return { error: `SA must be an integer epoch: "${val}"`, warnings };
          out.service_available_epoch = n; break;
        }
      }
    }

    for (const k of REGISTERED_KEYS) {
      if (!seen.has(k)) {
        return { error: `vector missing required metric "${k}"`, warnings, fields: out };
      }
    }
    return { fields: out, warnings };
  }

  // ---------------------------------------------------------------------
  // Schema + dictionary loading
  // ---------------------------------------------------------------------

  // Providers whose dictionary we ship under /dictionaries/.
  const KNOWN_PROVIDERS = Object.keys(providerToCode).concat(['gcp']);

  let dictRegistry = null; // { "provider/service/resource_type": entry }
  let ajvInstance = null;
  // Per-version compiled record validators. Keys are spec versions
  // (e.g. "0.3.0", "0.2.0"). Values: { validate, schema }.
  const recordValidators = {};

  async function loadResources(baseURL) {
    if (Object.keys(recordValidators).length > 0 && dictRegistry) return;

    // The cdnjs UMD bundle exposes `window.ajv2020` as a module
    // namespace; the constructor lives on `.default` (or `.Ajv2020`).
    // Other delivery modes (jsdelivr, npm) can vary, so try several.
    const ns = window.Ajv2020 || window.ajv2020 || window.Ajv;
    const Ajv = (ns && (ns.default || ns.Ajv2020 || ns.Ajv)) || ns;
    if (typeof Ajv !== 'function') throw new Error('Ajv2020 not loaded; CDN blocked or wrong export shape');
    ajvInstance = new Ajv({ strict: false, allErrors: true });

    // Load every supported version's record schema in parallel.
    // Missing schemas (older versions removed from the repo) are
    // silently dropped — the validator falls back to "highest
    // supported" with a warning when an unknown version is encountered.
    const schemaResults = await Promise.allSettled(
      SUPPORTED_SPEC_VERSIONS.map((v) =>
        fetch(baseURL + 'schemas/crit-record-v' + v + '.schema.json').then((r) =>
          r.ok ? r.json().then((j) => ({ v, schema: j })) : null,
        ),
      ),
    );
    for (const res of schemaResults) {
      if (res.status !== 'fulfilled' || !res.value) continue;
      const { v, schema } = res.value;
      try {
        recordValidators[v] = { validate: ajvInstance.compile(schema), schema };
      } catch (e) {
        console.warn('failed to compile schema v' + v, e);
      }
    }
    if (Object.keys(recordValidators).length === 0) {
      throw new Error('no record schema versions loaded; check /schemas/ availability');
    }

    // Load dictionaries in parallel; missing ones are silently dropped.
    const dictResults = await Promise.allSettled(
      KNOWN_PROVIDERS.map((p) =>
        fetch(baseURL + 'dictionaries/' + p + '.json').then((r) => (r.ok ? r.json() : null)),
      ),
    );
    dictRegistry = {};
    for (const res of dictResults) {
      if (res.status !== 'fulfilled' || !res.value) continue;
      const dict = res.value;
      const provider = dict.provider;
      if (!provider || !Array.isArray(dict.entries)) continue;
      for (const e of dict.entries) {
        const key = `${provider}/${e.service}/${e.resource_type}`;
        dictRegistry[key] = { ...e, provider };
      }
    }
  }

  /** Pick the right schema validator for a record. Prefer the version
   *  detected from the record's vectorString; fall back to the highest
   *  supported version with a warning attached.
   */
  function pickValidator(rec) {
    const detected = detectVectorVersion(rec && rec.vectorString);
    if (detected && recordValidators[detected]) {
      return { validate: recordValidators[detected].validate, version: detected, fallback: false };
    }
    const fallback = SUPPORTED_SPEC_VERSIONS.find((v) => recordValidators[v]);
    if (!fallback) throw new Error('no schema versions available');
    return { validate: recordValidators[fallback].validate, version: fallback, fallback: true, detected };
  }

  // ---------------------------------------------------------------------
  // Record validator
  // ---------------------------------------------------------------------

  function validateRecord(rec) {
    const errors = [];
    const warnings = [];

    // 0. Pick the right schema version for this record.
    const picked = pickValidator(rec);
    if (picked.fallback) {
      const detected = picked.detected
        ? `vectorString version "${picked.detected}" is not bundled`
        : 'record has no vectorString to detect a version from';
      warnings.push({
        rule: 'schema_version',
        detail: `${detected}; validating against fallback v${picked.version} (supported: ${SUPPORTED_SPEC_VERSIONS.filter((v) => recordValidators[v]).join(', ')})`,
      });
    }

    // 1. JSON Schema (per detected version)
    const schemaOK = picked.validate(rec);
    if (!schemaOK) {
      for (const e of picked.validate.errors || []) {
        errors.push({ rule: `schema_v${picked.version}`, detail: `${e.instancePath || '/'} ${e.message}` });
      }
    }

    // 2. Vector recompute — preserve the stored vector's version so a
    // v0.2.0 record round-trips byte-equal even though the validator
    // ships v0.3.0 as the default. New records with no vectorString
    // skip this check and emit a warning.
    if (rec && typeof rec === 'object' && rec.vectorString) {
      try {
        const computed = computeVector(rec, picked.version);
        if (computed !== rec.vectorString) {
          errors.push({
            rule: 'vector_round_trip',
            detail: `vectorString mismatch:\n  stored:   ${rec.vectorString}\n  computed: ${computed}`,
          });
        }
      } catch (e) {
        errors.push({ rule: 'vector_compute', detail: String(e.message || e) });
      }
    } else {
      warnings.push({ rule: 'vector_compute', detail: 'no vectorString to round-trip' });
    }

    // 3. Dictionary resolution
    if (rec && rec.provider && rec.service && rec.resource_type) {
      const key = `${rec.provider}/${rec.service}/${rec.resource_type}`;
      const entry = dictRegistry[key];
      if (!entry) {
        warnings.push({
          rule: 'dictionary_resolved',
          detail: `(${rec.provider}, ${rec.service}, ${rec.resource_type}) not in spec dictionary; consumer must supply a custom_dictionary entry`,
        });
      } else if (entry.template !== rec.template) {
        warnings.push({
          rule: 'dictionary_template',
          detail: `template differs from spec dictionary:\n  record: ${rec.template}\n  spec:   ${entry.template}`,
        });
      }
    }

    // 4. Cross-field MUST rules
    if (rec && rec.vex_status === 'fixed' && !(rec.temporal && rec.temporal.provider_fix_date)) {
      errors.push({
        rule: 'temporal_provider_fix_date_required',
        detail: 'vex_status="fixed" requires temporal.provider_fix_date',
      });
    }
    if (Array.isArray(rec?.detections)) {
      rec.detections.forEach((d, i) => {
        if (!d.query && !d.pending_reason) {
          errors.push({
            rule: 'detection_pending_reason',
            detail: `detections[${i}].query is empty but pending_reason is missing`,
          });
        }
      });
    }

    return { errors, warnings, schemaOK };
  }

  function validateCVERecord(rec) {
    const out = { perRecord: [], errors: [], warnings: [] };
    if (rec.dataType !== 'CVE_RECORD') {
      out.errors.push({ rule: 'cve_data_type', detail: `expected dataType="CVE_RECORD", got "${rec.dataType}"` });
      return out;
    }
    const cveId = rec?.cveMetadata?.cveId;
    const state = rec?.cveMetadata?.state;
    if (!cveId) out.errors.push({ rule: 'cve_metadata', detail: 'cveMetadata.cveId missing' });

    const adps = rec?.containers?.adp;
    if (!Array.isArray(adps) || adps.length === 0) {
      out.errors.push({ rule: 'cve_adp_missing', detail: 'no ADP container — cannot find x_crit' });
      return out;
    }

    let foundXCrit = false;
    adps.forEach((adp, ai) => {
      const xc = adp.x_crit;
      if (!Array.isArray(xc) || xc.length === 0) return;
      foundXCrit = true;
      if (state !== 'PUBLISHED') {
        out.errors.push({
          rule: 'cve_state_required',
          detail: `cveMetadata.state="${state}" but containers.adp[${ai}].x_crit is present (MUST be "PUBLISHED")`,
        });
      }
      xc.forEach((critRec, ri) => {
        const result = validateRecord(critRec);
        if (cveId && critRec.vuln_id !== cveId) {
          result.errors.unshift({
            rule: 'vuln_id_match',
            detail: `x_crit[${ri}].vuln_id="${critRec.vuln_id}" but cveMetadata.cveId="${cveId}"`,
          });
        }
        out.perRecord.push({ adpIndex: ai, xcritIndex: ri, vulnId: critRec.vuln_id, ...result });
      });
    });

    if (!foundXCrit) {
      out.errors.push({ rule: 'no_x_crit', detail: 'no ADP entry carries an x_crit array' });
    }
    return out;
  }

  // ---------------------------------------------------------------------
  // Sample data
  // ---------------------------------------------------------------------

  const SAMPLES = {
    'record-aws-eks': {
      vectorString: 'CRITv0.3.0/CP:AW/VS:FX/FP:RL/SR:SH/RL:SM/EV:T/PP:1706659200/SA:1528243200#CVE-2024-21626:eks:cluster',
      vuln_id: 'CVE-2024-21626',
      provider: 'aws', service: 'eks', resource_type: 'cluster',
      resource_lifecycle: 'stateful_managed',
      shared_responsibility: 'shared',
      vex_status: 'fixed',
      template: 'arn:aws:eks:{region}:{account}:cluster/{resource-id}',
      template_format: 'aws_arn',
      fix_propagation: 'rolling_replace',
      existing_deployments_remain_vulnerable: true,
      temporal: {
        vuln_published_date: '2024-01-31',
        provider_acknowledged_date: '2024-01-31',
        provider_fix_date: '2024-02-05',
        service_available_date: '2018-06-06',
      },
      remediation_actions: [{
        sequence: 1, type: 'rolling_replace',
        title: 'Trigger rolling update of EKS managed node groups',
        description: 'aws eks update-nodegroup-version --cluster-name {resource-id} --nodegroup-name <nodegroup>',
        auto_remediable: true, requires_downtime: false,
        stateful_impact: 'none', compensating_control: false,
      }],
      detections: [{
        provider: 'aws', service: 'eks',
        query_language: '',
        query: '',
        detection_phase: 'pre_fix',
        description: 'List EKS node groups whose AMI release version predates 2024-02-05.',
        pending_reason: 'query_in_development',
      }],
    },
    'record-azure-aks': {
      vectorString: 'CRITv0.3.0/CP:MA/VS:FX/FP:VU/SR:CA/RL:SC/EV:T/PP:1706659200/SA:1528243200#CVE-2024-21626:kubernetes_service:managedClusters',
      vuln_id: 'CVE-2024-21626',
      provider: 'azure', service: 'kubernetes_service', resource_type: 'managedClusters',
      resource_lifecycle: 'stateful_customer',
      shared_responsibility: 'customer_action_required',
      vex_status: 'fixed',
      template: '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.ContainerService/managedClusters/{name}',
      template_format: 'azure_resource_id',
      fix_propagation: 'version_update',
      existing_deployments_remain_vulnerable: true,
      temporal: {
        vuln_published_date: '2024-01-31',
        provider_fix_date: '2024-02-05',
        service_available_date: '2018-06-06',
      },
      remediation_actions: [{
        sequence: 1, type: 'version_update',
        title: 'Upgrade AKS cluster node pool image',
        description: 'az aks nodepool upgrade --node-image-only',
        auto_remediable: false, requires_downtime: false,
        stateful_impact: 'none', compensating_control: false,
      }],
      detections: [{
        provider: 'azure', service: 'kubernetes_service',
        query_language: '',
        query: '',
        detection_phase: 'pre_fix',
        description: 'List AKS clusters whose node-image version predates 2024-02-05.',
        pending_reason: 'query_in_development',
      }],
    },
    'cve-with-xcrit': {
      dataType: 'CVE_RECORD',
      dataVersion: '5.1',
      cveMetadata: {
        cveId: 'CVE-2024-21626',
        assignerOrgId: '8254265b-2729-46b6-b9e3-3dfca2d5bfca',
        state: 'PUBLISHED',
        datePublished: '2024-01-31T22:25:00Z',
      },
      containers: {
        cna: { providerMetadata: { orgId: '8254265b-2729-46b6-b9e3-3dfca2d5bfca' }, descriptions: [{ lang: 'en', value: 'runc through 1.1.11 — file descriptor leak via WORKDIR.' }] },
        adp: [{
          providerMetadata: { orgId: '8d7b6f2a-0b1c-4f5d-a3e6-9c8d7e6f5a4b', shortName: 'Vulnetix' },
          x_crit: [
            null,
          ],
        }],
      },
    },
    'vector': 'CRITv0.3.0/CP:AW/VS:FX/FP:RL/SR:SH/RL:SM/EV:T/PP:1706659200/SA:1528243200#CVE-2024-21626:eks:cluster',
  };
  // Inline the AWS sample into the CVE-with-xcrit fixture so the demo works.
  SAMPLES['cve-with-xcrit'].containers.adp[0].x_crit[0] = SAMPLES['record-aws-eks'];

  // ---------------------------------------------------------------------
  // UI wiring
  // ---------------------------------------------------------------------

  function el(id) { return document.getElementById(id); }

  function renderSchemaStatus(target, ok, count) {
    const cls = ok ? 'ok' : 'fail';
    const label = ok ? 'PASS' : 'FAIL';
    target.innerHTML += `<div class="row"><span class="${cls}">${label}</span> JSON Schema (${count} error${count === 1 ? '' : 's'})</div>`;
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function renderValidation(target, label, result) {
    const total = result.errors.length;
    const warns = result.warnings.length;
    const cls = total === 0 ? 'ok' : 'fail';
    const headline = total === 0 ? 'PASS' : 'FAIL';
    target.innerHTML += `<div class="row"><span class="${cls}">${headline}</span> ${escapeHtml(label)} — ${total} error(s), ${warns} warning(s)</div>`;
    for (const e of result.errors) {
      target.innerHTML += `<div class="row"><span class="fail">  ✗ ${escapeHtml(e.rule)}</span><pre>${escapeHtml(e.detail)}</pre></div>`;
    }
    for (const w of result.warnings) {
      target.innerHTML += `<div class="row"><span class="warn">  ⚠ ${escapeHtml(w.rule)}</span><pre>${escapeHtml(w.detail)}</pre></div>`;
    }
  }

  async function run() {
    const input = el('crit-validator-input').value.trim();
    const results = el('crit-validator-results');
    const hint = el('crit-validator-hint');
    results.innerHTML = '';
    hint.textContent = '';

    if (!input) {
      results.innerHTML = '<div class="row info">Paste JSON or a CRITv0.3.0/... vector and click Validate.</div>';
      return;
    }

    const mode = currentMode();

    try {
      hint.textContent = 'loading schemas + dictionaries…';
      await loadResources(window.location.origin + '/');
      hint.textContent = '';
    } catch (e) {
      results.innerHTML = `<div class="row fail">FAIL — could not load schemas/dictionaries: ${escapeHtml(String(e.message || e))}</div>`;
      return;
    }

    if (mode === 'vector') {
      const parsed = parseVector(input);
      if (parsed.error) {
        results.innerHTML = `<div class="row fail">FAIL — ${escapeHtml(parsed.error)}</div>`;
        if (parsed.warnings && parsed.warnings.length) {
          for (const w of parsed.warnings) {
            results.innerHTML += `<div class="row warn">⚠ ${escapeHtml(w.message)}</div>`;
          }
        }
        return;
      }
      const f = parsed.fields;
      results.innerHTML = `<div class="row ok">PASS — vector parsed successfully</div>`;
      const expanded = {
        crit_version: f.crit_version,
        provider: f.provider,
        vex_status: f.vex_status,
        fix_propagation: f.fix_propagation,
        shared_responsibility: f.shared_responsibility,
        resource_lifecycle: f.resource_lifecycle,
        existing_deployments_remain_vulnerable: f.existing_deployments_remain_vulnerable,
        vuln_published_epoch: f.vuln_published_epoch,
        vuln_published_iso: new Date(f.vuln_published_epoch * 1000).toISOString().slice(0, 10),
        service_available_epoch: f.service_available_epoch,
        service_available_iso: new Date(f.service_available_epoch * 1000).toISOString().slice(0, 10),
        vuln_id: f.vuln_id,
        service: f.service,
        resource_type: f.resource_type,
      };
      results.innerHTML += `<details open><summary>Decoded fields</summary><pre>${escapeHtml(JSON.stringify(expanded, null, 2))}</pre></details>`;
      if (parsed.warnings && parsed.warnings.length) {
        for (const w of parsed.warnings) {
          results.innerHTML += `<div class="row warn">⚠ ${escapeHtml(w.message)}</div>`;
        }
      }
      return;
    }

    // record + cve modes both expect JSON
    let parsed;
    try { parsed = JSON.parse(input); } catch (e) {
      results.innerHTML = `<div class="row fail">FAIL — not valid JSON: ${escapeHtml(String(e.message || e))}</div>`;
      return;
    }

    if (mode === 'cve') {
      const cveResult = validateCVERecord(parsed);
      if (cveResult.errors.length) {
        cveResult.errors.forEach((e) => {
          results.innerHTML += `<div class="row fail">✗ ${escapeHtml(e.rule)} — ${escapeHtml(e.detail)}</div>`;
        });
      }
      if (cveResult.perRecord.length === 0) {
        results.innerHTML += `<div class="row info">No x_crit records found.</div>`;
        return;
      }
      cveResult.perRecord.forEach((r) => {
        renderValidation(results, `adp[${r.adpIndex}].x_crit[${r.xcritIndex}] — ${r.vulnId}`, { errors: r.errors, warnings: r.warnings, schemaOK: r.schemaOK });
      });
      return;
    }

    // record mode
    const result = validateRecord(parsed);
    renderValidation(results, parsed.vuln_id || '(record)', result);
  }

  function currentMode() {
    const active = document.querySelector('.crit-validator__tabs button[aria-selected="true"]');
    return active ? active.dataset.mode : 'record';
  }

  function setMode(mode) {
    document.querySelectorAll('.crit-validator__tabs button').forEach((b) => {
      b.setAttribute('aria-selected', b.dataset.mode === mode ? 'true' : 'false');
    });
    const placeholders = {
      record: 'Paste a CRIT record JSON (single envelope) and click Validate.',
      cve: 'Paste a CVE 5.x JSON record carrying x_crit in containers.adp[].x_crit[].',
      vector: 'Paste a vector string, e.g. CRITv0.3.0/CP:AW/VS:FX/...',
    };
    el('crit-validator-input').placeholder = placeholders[mode] || '';
  }

  function loadSample(name) {
    const sample = SAMPLES[name];
    if (!sample) return;
    if (typeof sample === 'string') {
      setMode('vector');
      el('crit-validator-input').value = sample;
    } else if (sample.dataType === 'CVE_RECORD') {
      setMode('cve');
      el('crit-validator-input').value = JSON.stringify(sample, null, 2);
    } else {
      setMode('record');
      el('crit-validator-input').value = JSON.stringify(sample, null, 2);
    }
  }

  document.addEventListener('DOMContentLoaded', function () {
    if (!el('crit-validator')) return;
    document.querySelectorAll('.crit-validator__tabs button').forEach((b) => {
      b.addEventListener('click', () => setMode(b.dataset.mode));
    });
    document.querySelectorAll('.crit-validator__samples button').forEach((b) => {
      b.addEventListener('click', () => loadSample(b.dataset.sample));
    });
    el('crit-validator-run').addEventListener('click', run);
    el('crit-validator-clear').addEventListener('click', () => {
      el('crit-validator-input').value = '';
      el('crit-validator-results').innerHTML = '';
      el('crit-validator-hint').textContent = '';
    });
  });
})();
