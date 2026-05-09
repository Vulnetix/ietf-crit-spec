// Package critspec provides the CRIT vector string encoder, decoder, and
// validator.  A CRIT vector string is a compact, deterministic, CVSS-style
// encoding of the classification and identity fields of a CRIT record.
//
// Format:
//
//	CRITv<semver>/<metric>:<value>[/...]#<vuln_id>:<service>:<resource_type>
//
// Example:
//
//	CRITv0.3.0/CP:AW/VS:FX/FP:RR/SR:CA/RL:SC/EV:T/PP:1719792000/SA:1514764800#CVE-2024-6387:ec2:instance
package critspec

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// CRITVector holds the decoded fields of a CRIT vector string.
// ---------------------------------------------------------------------------

// CRITVector represents the structured fields decoded from a CRIT vector string.
type CRITVector struct {
	CRITVersion    string
	Provider       string // expanded value, e.g. "aws"
	VEXStatus      string // expanded value, e.g. "fixed"
	FixPropagation string
	SharedResp     string
	Lifecycle      string
	ExistingVuln   bool
	VulnPublished  int64 // epoch seconds
	ServiceAvail   int64 // epoch seconds
	VulnID         string
	Service        string
	ResourceType   string
	UnknownMetrics map[string]string // unknown metric key → raw value
}

// Warning is a non-fatal diagnostic emitted during parsing.
type Warning struct {
	Code    string // "unknown_metric" or "did_you_mean"
	Message string
}

// ---------------------------------------------------------------------------
// Forward maps: full value → abbreviated code
// ---------------------------------------------------------------------------

var providerToCode = map[string]string{
	"aws":          "AW",
	"azure":        "MA",
	"gcp":          "GC",
	"cloudflare":   "CF",
	"oracle":       "OC",
	"salesforce":   "SF",
	"sap":          "SP",
	"servicenow":   "SN",
	"ibm":          "IB",
	"vmware":       "VM",
	"adobe":        "AD",
	"akamai":       "AK",
	"alibaba":      "AL",
	"atlassian":    "AT",
	"digitalocean": "DO",
	"elastic":      "EL",
	"fastly":       "FA",
	"gitlab":       "GL",
	"hetzner":      "HE",
	"linode":       "LI",
	"mongodb":      "MO",
	"ovh":          "OV",
	"snowflake":    "SO",
	"tailscale":    "TS",
	"tencent":      "TC",
	"twilio":       "TW",
	"vercel":       "VC",
	"vultr":        "VL",
	"zoom":         "ZM",
	"hashicorp":    "HC",
}

var vexStatusToCode = map[string]string{
	"affected":            "AF",
	"fixed":               "FX",
	"not_affected":        "NA",
	"under_investigation": "UI",
}

var fixPropToCode = map[string]string{
	"automatic":            "AU",
	"config_change":        "CC",
	"opt_in":               "OI",
	"version_update":       "VU",
	"redeploy":             "RD",
	"rebuild_and_redeploy": "RR",
	"destroy_recreate":     "DC",
	"rolling_replace":      "RL",
	"no_fix_available":     "NF",
}

var sharedRespToCode = map[string]string{
	"provider_only":            "PO",
	"customer_action_required": "CA",
	"customer_only":            "CO",
	"shared":                   "SH",
}

var lifecycleToCode = map[string]string{
	"ephemeral":            "EP",
	"stateful_managed":     "SM",
	"stateful_customer":    "SC",
	"config_only":          "CF",
	"global_control_plane": "GC",
}

// ---------------------------------------------------------------------------
// Reverse maps: abbreviated code → full value
// ---------------------------------------------------------------------------

var codeToProvider = reverseMap(providerToCode)
var codeToVEXStatus = reverseMap(vexStatusToCode)
var codeToFixProp = reverseMap(fixPropToCode)
var codeToSharedResp = reverseMap(sharedRespToCode)
var codeToLifecycle = reverseMap(lifecycleToCode)

func reverseMap(m map[string]string) map[string]string {
	r := make(map[string]string, len(m))
	for k, v := range m {
		r[v] = k
	}
	return r
}

// registeredKeys is the canonical ordered list of registered metric keys.
var registeredKeys = []string{"CP", "VS", "FP", "SR", "RL", "EV", "PP", "SA"}

// registeredKeySet is a lookup set for registered keys.
var registeredKeySet = func() map[string]bool {
	s := make(map[string]bool, len(registeredKeys))
	for _, k := range registeredKeys {
		s[k] = true
	}
	return s
}()

// ---------------------------------------------------------------------------
// ComputeVector builds a canonical CRIT vector string from structured fields.
// ---------------------------------------------------------------------------

// ComputeVector builds the canonical CRIT vector string from a CRITVector.
func ComputeVector(v CRITVector) (string, error) {
	cp, ok := providerToCode[v.Provider]
	if !ok {
		return "", fmt.Errorf("unknown provider %q", v.Provider)
	}
	vs, ok := vexStatusToCode[v.VEXStatus]
	if !ok {
		return "", fmt.Errorf("unknown vex_status %q", v.VEXStatus)
	}
	fp, ok := fixPropToCode[v.FixPropagation]
	if !ok {
		return "", fmt.Errorf("unknown fix_propagation %q", v.FixPropagation)
	}
	sr, ok := sharedRespToCode[v.SharedResp]
	if !ok {
		return "", fmt.Errorf("unknown shared_responsibility %q", v.SharedResp)
	}
	rl, ok := lifecycleToCode[v.Lifecycle]
	if !ok {
		return "", fmt.Errorf("unknown resource_lifecycle %q", v.Lifecycle)
	}
	ev := "F"
	if v.ExistingVuln {
		ev = "T"
	}
	if v.VulnID == "" {
		return "", errors.New("vuln_id is required")
	}
	if v.Service == "" {
		return "", errors.New("service is required")
	}
	if v.ResourceType == "" {
		return "", errors.New("resource_type is required")
	}
	if v.CRITVersion == "" {
		return "", errors.New("crit_version is required")
	}

	return fmt.Sprintf("CRITv%s/CP:%s/VS:%s/FP:%s/SR:%s/RL:%s/EV:%s/PP:%d/SA:%d#%s:%s:%s",
		v.CRITVersion,
		cp, vs, fp, sr, rl, ev,
		v.VulnPublished, v.ServiceAvail,
		v.VulnID, v.Service, v.ResourceType,
	), nil
}

// ---------------------------------------------------------------------------
// ParseVector decodes a CRIT vector string back to structured fields.
// ---------------------------------------------------------------------------

// ParseVector decodes a CRIT vector string. Unknown metric keys are collected
// in UnknownMetrics and reported as warnings but do not cause an error. An
// error is returned only when a registered metric is missing or the format is
// invalid.
func ParseVector(s string) (*CRITVector, []Warning, error) {
	// Split on '#' → metrics part and qualifiers part.
	parts := strings.SplitN(s, "#", 2)
	if len(parts) != 2 {
		return nil, nil, errors.New("missing '#' delimiter between metrics and qualifiers")
	}
	metricsPart, qualPart := parts[0], parts[1]

	// Parse prefix: CRITv<semver>/...
	if !strings.HasPrefix(metricsPart, "CRITv") {
		return nil, nil, errors.New("vector must start with 'CRITv'")
	}
	metricsPart = metricsPart[5:] // strip "CRITv"

	segments := strings.Split(metricsPart, "/")
	if len(segments) < 2 {
		return nil, nil, errors.New("vector must contain version and at least one metric")
	}
	version := segments[0]
	metricSegments := segments[1:]

	// Parse qualifiers: positional colon-separated values.
	quals := strings.SplitN(qualPart, ":", 3)
	if len(quals) != 3 {
		return nil, nil, fmt.Errorf("qualifiers must have exactly 3 colon-separated values, got %d", len(quals))
	}

	v := &CRITVector{
		CRITVersion:    version,
		VulnID:         quals[0],
		Service:        quals[1],
		ResourceType:   quals[2],
		UnknownMetrics: make(map[string]string),
	}
	var warnings []Warning

	// Track which registered keys we've seen.
	seen := make(map[string]bool, len(registeredKeys))

	for _, seg := range metricSegments {
		kv := strings.SplitN(seg, ":", 2)
		if len(kv) != 2 {
			return nil, warnings, fmt.Errorf("malformed metric segment %q", seg)
		}
		key, val := kv[0], kv[1]

		if !registeredKeySet[key] {
			v.UnknownMetrics[key] = val
			w := Warning{Code: "unknown_metric", Message: fmt.Sprintf("unknown metric %q with value %q", key, val)}
			if suggestion, ok := SuggestMetric(key); ok {
				w = Warning{Code: "did_you_mean", Message: fmt.Sprintf("unknown metric %q, did you mean %q?", key, suggestion)}
			}
			warnings = append(warnings, w)
			continue
		}

		seen[key] = true
		var err error
		var found bool
		switch key {
		case "CP":
			v.Provider, found = codeToProvider[val]
			if !found {
				err = fmt.Errorf("unknown CP code %q", val)
			}
		case "VS":
			v.VEXStatus, found = codeToVEXStatus[val]
			if !found {
				err = fmt.Errorf("unknown VS code %q", val)
			}
		case "FP":
			v.FixPropagation, found = codeToFixProp[val]
			if !found {
				err = fmt.Errorf("unknown FP code %q", val)
			}
		case "SR":
			v.SharedResp, found = codeToSharedResp[val]
			if !found {
				err = fmt.Errorf("unknown SR code %q", val)
			}
		case "RL":
			v.Lifecycle, found = codeToLifecycle[val]
			if !found {
				err = fmt.Errorf("unknown RL code %q", val)
			}
		case "EV":
			switch val {
			case "T":
				v.ExistingVuln = true
			case "F":
				v.ExistingVuln = false
			default:
				err = fmt.Errorf("unknown EV code %q", val)
			}
		case "PP":
			v.VulnPublished, err = strconv.ParseInt(val, 10, 64)
			if err != nil {
				err = fmt.Errorf("PP must be an integer epoch: %w", err)
			}
		case "SA":
			v.ServiceAvail, err = strconv.ParseInt(val, 10, 64)
			if err != nil {
				err = fmt.Errorf("SA must be an integer epoch: %w", err)
			}
		}
		if err != nil {
			return nil, warnings, err
		}
	}

	// Check all registered keys are present.
	for _, k := range registeredKeys {
		if !seen[k] {
			msg := fmt.Sprintf("missing registered metric %q", k)
			// Check if any unknown metric is close.
			for uk := range v.UnknownMetrics {
				if suggestion, ok := SuggestMetric(uk); ok && suggestion == k {
					msg += fmt.Sprintf(" (%q was provided, did you mean %q?)", uk, k)
					break
				}
			}
			return nil, warnings, errors.New(msg)
		}
	}

	// Verify canonical ordering of registered keys.
	regIdx := 0
	for _, seg := range metricSegments {
		kv := strings.SplitN(seg, ":", 2)
		key := kv[0]
		if !registeredKeySet[key] {
			continue
		}
		if key != registeredKeys[regIdx] {
			return nil, warnings, fmt.Errorf("registered metrics out of order: expected %q at position %d, got %q", registeredKeys[regIdx], regIdx, key)
		}
		regIdx++
	}

	return v, warnings, nil
}

// ---------------------------------------------------------------------------
// ValidateVector checks that a vector string matches expected record fields.
// ---------------------------------------------------------------------------

// ValidateVector checks that vectorString matches the canonical vector
// computed from the given CRITVector fields.
func ValidateVector(vectorString string, expected CRITVector) error {
	canonical, err := ComputeVector(expected)
	if err != nil {
		return fmt.Errorf("cannot compute expected vector: %w", err)
	}
	// Compare only the canonical portion (ignore unknown metrics the producer
	// may have appended).
	parsed, _, err := ParseVector(vectorString)
	if err != nil {
		return fmt.Errorf("cannot parse vectorString: %w", err)
	}
	parsedCanonical, err := ComputeVector(*parsed)
	if err != nil {
		return fmt.Errorf("cannot recompute vector from parsed fields: %w", err)
	}
	if parsedCanonical != canonical {
		return fmt.Errorf("vectorString does not match record fields:\n  got:      %s\n  expected: %s", parsedCanonical, canonical)
	}
	return nil
}

// ---------------------------------------------------------------------------
// SuggestMetric returns a "did you mean?" suggestion for unknown metric keys.
// ---------------------------------------------------------------------------

// SuggestMetric checks if an unknown metric key is within Levenshtein distance
// 2 of any registered key and returns the closest match.
func SuggestMetric(unknown string) (string, bool) {
	best := ""
	bestDist := 2 // threshold: only suggest if distance ≤ 1
	for _, k := range registeredKeys {
		d := levenshtein(unknown, k)
		if d < bestDist {
			bestDist = d
			best = k
		}
	}
	if best != "" {
		return best, true
	}
	return "", false
}

func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min(curr[j-1]+1, min(prev[j]+1, prev[j-1]+cost))
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}
