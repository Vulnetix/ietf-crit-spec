// crit-test is the unified CRIT spec conformance test tool.
// It generates interpolated template samples from dictionaries + wordlists,
// runs 20 template-level rules and 28 record-level rules against hand-authored
// samples, and produces a single consolidated Markdown report.
//
// Usage:
//
//	go run ./tests/cmd/crit-test [flags]
//
// Flags:
//
//	--report <dir>   Write YYYYMMDD-crit-test-report.md to directory
//	--no-fail        Exit 0 even on MUST failures
//	--quiet          Suppress console output
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

type slotInfo struct {
	raw       string
	fieldName string
	state     string // named-variable, hardcoded, empty, wildcard
	value     string
}

type Dictionary struct {
	Provider string      `json:"provider"`
	Entries  []DictEntry `json:"entries"`
}

type DictEntry struct {
	Service        string `json:"service"`
	ResourceType   string `json:"resource_type"`
	Template       string `json:"template"`
	TemplateFormat string `json:"template_format"`
	RegionBehavior string `json:"region_behavior"`
}

type DictKey struct {
	Provider, Service, ResourceType string
}

type RuleResult struct {
	Pass, Fail, Warn int
}

type Failure struct {
	RuleName, Section, Level string
	Provider, Service, ResourceType string
	Detail, FilePath string
}

// ---------------------------------------------------------------------------
// Generated sample types
// ---------------------------------------------------------------------------

type Sample struct {
	Provider       string            `json:"provider"`
	Service        string            `json:"service"`
	ResourceType   string            `json:"resource_type"`
	Template       string            `json:"template"`
	TemplateFormat string            `json:"template_format"`
	RegionBehavior string            `json:"region_behavior"`
	SlotValues     map[string]string `json:"slot_values"`
	Resolved       string            `json:"resolved"`
}

type SamplesOutput struct {
	Schema      string                         `json:"$schema"`
	GeneratedAt string                         `json:"generated_at"`
	Wordlists   map[string]map[string][]string `json:"wordlists"`
	Samples     []Sample                       `json:"samples"`
}

// ---------------------------------------------------------------------------
// CRIT record types (hand-authored samples)
// ---------------------------------------------------------------------------

type CRITRecord struct {
	CritVersion                         string              `json:"crit_version"`
	ID                                  string              `json:"id"`
	VulnID                              string              `json:"vuln_id"`
	Provider                            string              `json:"provider"`
	Service                             string              `json:"service"`
	ResourceType                        string              `json:"resource_type"`
	ResourceLifecycle                   string              `json:"resource_lifecycle"`
	SharedResponsibility                string              `json:"shared_responsibility"`
	VexStatus                           string              `json:"vex_status"`
	Template                            string              `json:"template"`
	TemplateFormat                      string              `json:"template_format"`
	Temporal                            Temporal             `json:"temporal"`
	FixPropagation                      string              `json:"fix_propagation"`
	ExistingDeploymentsRemainVulnerable bool                 `json:"existing_deployments_remain_vulnerable"`
	ProviderFixVersion                  *ProviderFixVersion  `json:"provider_fix_version,omitempty"`
	RemediationActions                  []RemediationAction  `json:"remediation_actions"`
	Detections                          []Detection          `json:"detections,omitempty"`
	ProviderAdvisory                    *ProviderAdvisory    `json:"provider_advisory,omitempty"`
	FilePath                            string               `json:"-"`
}

type Temporal struct {
	VulnerabilityIntroducedDate          *string `json:"vulnerability_introduced_date,omitempty"`
	VulnerabilityIntroducedDateEstimated *bool   `json:"vulnerability_introduced_date_estimated,omitempty"`
	VulnPublishedDate                    string  `json:"vuln_published_date"`
	ProviderAcknowledgedDate             *string `json:"provider_acknowledged_date,omitempty"`
	ProviderFixDate                      *string `json:"provider_fix_date,omitempty"`
	CustomerDeadlineDate                 *string `json:"customer_deadline_date,omitempty"`
	CustomerDeadlineSource               *string `json:"customer_deadline_source,omitempty"`
	ServiceAvailableDate                 *string `json:"service_available_date,omitempty"`
}

type ProviderFixVersion struct {
	VersionType string  `json:"version_type"`
	Comparison  string  `json:"comparison"`
	Version     *string `json:"version,omitempty"`
	Channel     *string `json:"channel,omitempty"`
	BuildDate   *string `json:"build_date,omitempty"`
	AutoUpgrade *bool   `json:"auto_upgrade,omitempty"`
	Note        *string `json:"note,omitempty"`
}

type RemediationAction struct {
	Sequence                      int            `json:"sequence"`
	Type                          string         `json:"type"`
	Title                         string         `json:"title"`
	Description                   string         `json:"description"`
	AutoRemediable                bool           `json:"auto_remediable"`
	RequiresDowntime              bool           `json:"requires_downtime"`
	EstimatedDowntimeRangeSeconds *DowntimeRange `json:"estimated_downtime_range_seconds,omitempty"`
	CompensatingControl           bool           `json:"compensating_control"`
}

type DowntimeRange struct{ Min, Max int }

type Detection struct {
	Provider       string  `json:"provider"`
	Service        string  `json:"service"`
	QueryLanguage  string  `json:"query_language"`
	Query          string  `json:"query"`
	DetectionPhase string  `json:"detection_phase"`
	Description    string  `json:"description"`
	PendingReason  *string `json:"pending_reason,omitempty"`
}

type ProviderAdvisory struct {
	AdvisoryID         *string  `json:"advisory_id,omitempty"`
	AdvisoryURL        *string  `json:"advisory_url,omitempty"`
	ProviderSeverity   *string  `json:"provider_severity,omitempty"`
	ProviderCVSSScore  *float64 `json:"provider_cvss_score,omitempty"`
	ProviderCVSSVector *string  `json:"provider_cvss_vector,omitempty"`
}

// ---------------------------------------------------------------------------
// Rule types (separate for template vs record)
// ---------------------------------------------------------------------------

type TemplateRule struct {
	Section, Name, Requirement string
	Check                      func(s *Sample) (bool, string)
}

type RecordRule struct {
	Section, Name, Level, Requirement string
	Check                             func(rec *CRITRecord) (bool, string)
}

type SuiteResult struct {
	Name        string
	RuleCount   int
	SampleCount int
	TotalPass   int
	TotalFail   int
	TotalWarn   int
	Results     map[string]*RuleResult
	Failures    []Failure
}

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

var (
	slotRegex      = regexp.MustCompile(`\{([^}]*)\}`)
	fieldNameRe    = regexp.MustCompile(`^[A-Za-z0-9\-_]+$`)
	literalValueRe = regexp.MustCompile(`^[A-Za-z0-9\-_.:]+$`)
	serviceKeyRe   = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	resourceTypeRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_/\-]*$`)
	dateRe         = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	cvss31Re       = regexp.MustCompile(`^CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]$`)
	cvss40Re       = regexp.MustCompile(`^CVSS:4\.0/`)
)

var providerFormatMap = map[string]string{
	"aws": "aws_arn", "azure": "azure_resource_id", "gcp": "gcp_resource_name",
	"cloudflare": "cloudflare_locator", "oracle": "oracle_ocid",
}

var providerPrefixes = map[string]string{
	"aws": "arn:aws:", "azure": "/subscriptions/", "gcp": "//",
	"cloudflare": "com.cloudflare.", "oracle": "ocid1.",
}

var knownSlotFiles = map[string]map[string]bool{
	"aws":        {"region": true, "account": true, "resource-id": true},
	"azure":      {"subscriptionId": true, "resourceGroup": true, "name": true},
	"gcp":        {"project": true, "location": true, "zone": true, "region": true, "resource-id": true},
	"cloudflare": {"account_id": true, "id": true},
	"oracle":     {"region": true, "unique-id": true},
}

var dictLookup map[DictKey]DictEntry

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

func parseSlots(template string) []slotInfo {
	matches := slotRegex.FindAllStringSubmatch(template, -1)
	var slots []slotInfo
	for _, m := range matches {
		si := slotInfo{raw: m[0]}
		desc := m[1]
		if strings.Contains(desc, "=") {
			parts := strings.SplitN(desc, "=", 2)
			si.fieldName = parts[0]
			switch val := parts[1]; {
			case val == "*":
				si.state = "wildcard"
				si.value = "*"
			case val == "":
				si.state = "empty"
			default:
				si.state = "hardcoded"
				si.value = val
			}
		} else {
			si.fieldName = desc
			si.state = "named-variable"
		}
		slots = append(slots, si)
	}
	return slots
}

func isValidDate(s string) bool {
	if !dateRe.MatchString(s) {
		return false
	}
	_, err := time.Parse("2006-01-02", s)
	return err == nil
}

func collectDates(t *Temporal) map[string]string {
	dates := make(map[string]string)
	if t.VulnPublishedDate != "" {
		dates["vuln_published_date"] = t.VulnPublishedDate
	}
	if t.VulnerabilityIntroducedDate != nil {
		dates["vulnerability_introduced_date"] = *t.VulnerabilityIntroducedDate
	}
	if t.ProviderAcknowledgedDate != nil {
		dates["provider_acknowledged_date"] = *t.ProviderAcknowledgedDate
	}
	if t.ProviderFixDate != nil {
		dates["provider_fix_date"] = *t.ProviderFixDate
	}
	if t.CustomerDeadlineDate != nil {
		dates["customer_deadline_date"] = *t.CustomerDeadlineDate
	}
	if t.ServiceAvailableDate != nil {
		dates["service_available_date"] = *t.ServiceAvailableDate
	}
	return dates
}

func escapeMarkdown(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ")
}

func findDir(candidates ...string) string {
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c
		}
	}
	return ""
}

func wordlistFile(provider, slotName string) string {
	if knownSlotFiles[provider][slotName] {
		return slotName
	}
	return "resource-id"
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

func loadDictionaries(dictDir string) ([]*Dictionary, map[DictKey]DictEntry, error) {
	lookup := make(map[DictKey]DictEntry)
	files, err := filepath.Glob(filepath.Join(dictDir, "*.json"))
	if err != nil || len(files) == 0 {
		return nil, nil, fmt.Errorf("no dictionary files in %s", dictDir)
	}
	var dicts []*Dictionary
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, nil, fmt.Errorf("reading %s: %w", f, err)
		}
		var dict Dictionary
		if err := json.Unmarshal(data, &dict); err != nil {
			return nil, nil, fmt.Errorf("parsing %s: %w", f, err)
		}
		dicts = append(dicts, &dict)
		for _, e := range dict.Entries {
			lookup[DictKey{dict.Provider, e.Service, e.ResourceType}] = e
		}
	}
	return dicts, lookup, nil
}

func loadWordlists(provider, baseDir string) (map[string][]string, error) {
	dir := filepath.Join(baseDir, "wordlists", provider)
	wl := make(map[string][]string)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading wordlist dir %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".txt")
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", e.Name(), err)
		}
		var values []string
		for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				values = append(values, l)
			}
		}
		if len(values) > 0 {
			wl[name] = values
		}
	}
	return wl, nil
}

func loadSampleRecords(samplesDir string) ([]CRITRecord, error) {
	var records []CRITRecord
	err := filepath.WalkDir(samplesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		var rec CRITRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return fmt.Errorf("parsing %s: %w", path, err)
		}
		rec.FilePath = path
		records = append(records, rec)
		return nil
	})
	return records, err
}

// ---------------------------------------------------------------------------
// Sample generation
// ---------------------------------------------------------------------------

func generateSamples(dicts []*Dictionary, testsDir string) ([]Sample, error) {
	providerWordlists := make(map[string]map[string][]string)
	for _, p := range []string{"aws", "azure", "gcp", "cloudflare", "oracle"} {
		wl, err := loadWordlists(p, testsDir)
		if err != nil {
			return nil, fmt.Errorf("loading wordlists for %s: %w", p, err)
		}
		providerWordlists[p] = wl
	}

	var samples []Sample
	for _, dict := range dicts {
		wl := providerWordlists[dict.Provider]
		for _, entry := range dict.Entries {
			slots := parseSlots(entry.Template)
			maxLen := 1
			for _, s := range slots {
				if s.state == "named-variable" {
					if vals, ok := wl[wordlistFile(dict.Provider, s.fieldName)]; ok && len(vals) > maxLen {
						maxLen = len(vals)
					}
				}
			}
			cap := 5
			if maxLen < cap {
				cap = maxLen
			}
			for i := 0; i < cap; i++ {
				resolved := entry.Template
				slotValues := make(map[string]string)
				for _, s := range slots {
					var val string
					switch s.state {
					case "hardcoded":
						val = s.value
					case "empty":
						val = ""
					case "wildcard":
						val = "*"
					case "named-variable":
						if vals, ok := wl[wordlistFile(dict.Provider, s.fieldName)]; ok && len(vals) > 0 {
							val = vals[i%len(vals)]
						} else {
							val = "MISSING_WORDLIST"
						}
					}
					slotValues[s.fieldName] = val
					resolved = strings.Replace(resolved, s.raw, val, 1)
				}
				samples = append(samples, Sample{
					Provider: dict.Provider, Service: entry.Service, ResourceType: entry.ResourceType,
					Template: entry.Template, TemplateFormat: entry.TemplateFormat,
					RegionBehavior: entry.RegionBehavior, SlotValues: slotValues, Resolved: resolved,
				})
			}
		}
	}
	return samples, nil
}

// ---------------------------------------------------------------------------
// Template rules (20)
// ---------------------------------------------------------------------------

func defineTemplateRules() []TemplateRule {
	return []TemplateRule{
		{"3.2", "slot-delimiter-not-in-literal", "Characters { and } MUST NOT appear outside slot expressions", func(s *Sample) (bool, string) {
			stripped := slotRegex.ReplaceAllString(s.Template, "")
			if strings.ContainsAny(stripped, "{}") {
				return false, "stray { or } outside slot expressions"
			}
			return true, ""
		}},
		{"3.3.1", "named-var-no-default", "Named variable MUST NOT be treated as implying any default value", func(s *Sample) (bool, string) {
			for _, si := range parseSlots(s.Template) {
				if si.state == "named-variable" {
					if val, ok := s.SlotValues[si.fieldName]; !ok || val == "" {
						return false, fmt.Sprintf("named variable %s has no value supplied", si.fieldName)
					}
				}
			}
			return true, ""
		}},
		{"3.3.1", "named-var-requires-substitution", "Named variable MUST substitute concrete value before using template as live identifier", func(s *Sample) (bool, string) {
			if slotRegex.MatchString(s.Resolved) {
				return false, fmt.Sprintf("unresolved slot in: %s", s.Resolved)
			}
			return true, ""
		}},
		{"3.3.2", "wildcard-not-live-identifier", "Wildcard MUST NOT be used as live identifier against provider API", func(s *Sample) (bool, string) {
			for _, si := range parseSlots(s.Template) {
				if si.state == "wildcard" {
					if !strings.Contains(s.Resolved, "*") {
						return false, "wildcard slot resolved to concrete value"
					}
				}
			}
			return true, ""
		}},
		{"3.3.4", "hardcoded-value-as-is", "Consumer MUST use hardcoded value as-is; MUST NOT substitute alternative value", func(s *Sample) (bool, string) {
			for _, si := range parseSlots(s.Template) {
				if si.state == "hardcoded" {
					if actual, ok := s.SlotValues[si.fieldName]; !ok || actual != si.value {
						return false, fmt.Sprintf("hardcoded %s=%s was changed to %s", si.fieldName, si.value, actual)
					}
				}
			}
			return true, ""
		}},
		{"3.4", "slot-state-precedence", "Producer MUST select slot state according to precedence", func(s *Sample) (bool, string) {
			if s.Provider == "aws" && s.RegionBehavior == "global-only" {
				for _, si := range parseSlots(s.Template) {
					if si.fieldName == "region" && si.state != "hardcoded" {
						return false, fmt.Sprintf("AWS global-only region is %s, expected hardcoded", si.state)
					}
				}
			}
			if s.Provider == "oracle" {
				for _, si := range parseSlots(s.Template) {
					if si.fieldName == "realm" && si.state != "hardcoded" {
						return false, fmt.Sprintf("Oracle realm is %s, expected hardcoded", si.state)
					}
				}
			}
			return true, ""
		}},
		{"3.4", "wildcard-not-fallback", "Producer MUST NOT use wildcard as fallback when correct state is unknown", func(s *Sample) (bool, string) {
			for _, si := range parseSlots(s.Template) {
				if si.state == "wildcard" && s.RegionBehavior == "global-only" && si.fieldName == "region" {
					return false, "global-only uses wildcard for region instead of hardcoded"
				}
			}
			return true, ""
		}},
		{"3.2", "template-produces-valid-id", "Conformant CRIT template MUST produce valid identifier after variable resolution", func(s *Sample) (bool, string) {
			prefix := providerPrefixes[s.Provider]
			if s.Resolved == "" || !strings.HasPrefix(s.Resolved, prefix) {
				return false, fmt.Sprintf("resolved %q missing prefix %q", s.Resolved, prefix)
			}
			return true, ""
		}},
		{"6.1", "aws-global-region-hardcoded", "AWS global-only services: region MUST be hardcoded to us-east-1", func(s *Sample) (bool, string) {
			if s.Provider != "aws" || s.RegionBehavior != "global-only" {
				return true, ""
			}
			for _, si := range parseSlots(s.Template) {
				if si.fieldName == "region" && (si.state != "hardcoded" || si.value != "us-east-1") {
					return false, fmt.Sprintf("region=%s(%s), expected hardcoded=us-east-1", si.state, si.value)
				}
			}
			return true, ""
		}},
		{"6.1", "aws-regional-region-variable", "AWS regional services: region MUST be named variable or wildcard, MUST NOT be empty", func(s *Sample) (bool, string) {
			if s.Provider != "aws" || s.RegionBehavior != "regional" {
				return true, ""
			}
			for _, si := range parseSlots(s.Template) {
				if si.fieldName == "region" && (si.state == "empty" || si.state == "hardcoded") {
					return false, fmt.Sprintf("regional AWS region is %s", si.state)
				}
			}
			return true, ""
		}},
		{"6.4", "cloudflare-no-region-slot", "Producer MUST NOT add region slot to Cloudflare templates", func(s *Sample) (bool, string) {
			if s.Provider != "cloudflare" {
				return true, ""
			}
			for _, si := range parseSlots(s.Template) {
				if si.fieldName == "region" {
					return false, "Cloudflare template contains region slot"
				}
			}
			return true, ""
		}},
		{"7.1", "resolution-produces-valid-id", "After variable resolution, result MUST be valid provider identifier", func(s *Sample) (bool, string) {
			if s.Resolved == "" || strings.Contains(s.Resolved, "MISSING_WORDLIST") {
				return false, "resolved value empty or contains MISSING_WORDLIST"
			}
			if remaining := slotRegex.FindAllString(s.Resolved, -1); len(remaining) > 0 {
				return false, fmt.Sprintf("unresolved slots: %v", remaining)
			}
			return true, ""
		}},
		{"7.2", "reserved-field-names-used", "Producer MUST use reserved field names where applicable", func(s *Sample) (bool, string) {
			names := make(map[string]bool)
			for _, si := range parseSlots(s.Template) {
				names[si.fieldName] = true
			}
			switch s.Provider {
			case "aws":
				if !names["region"] || !names["account"] {
					return false, "AWS template missing region or account"
				}
			case "azure":
				if !names["subscriptionId"] || !names["resourceGroup"] || !names["name"] {
					return false, "Azure template missing subscriptionId, resourceGroup, or name"
				}
			case "oracle":
				if !names["realm"] {
					return false, "Oracle template missing realm"
				}
			}
			return true, ""
		}},
		{"5", "template-field-valid-after-resolution", "After all named variables substituted, result MUST be valid provider identifier for declared template_format", func(s *Sample) (bool, string) {
			prefix := providerPrefixes[s.Provider]
			if !strings.HasPrefix(s.Resolved, prefix) {
				return false, fmt.Sprintf("resolved missing %s prefix", s.TemplateFormat)
			}
			if s.TemplateFormat == "aws_arn" {
				if parts := strings.SplitN(s.Resolved, ":", 6); len(parts) < 6 {
					return false, fmt.Sprintf("aws_arn needs >=6 colon parts, got %d", len(parts))
				}
			}
			return true, ""
		}},
		{"12.2", "dictionary-entry-required-fields", "All fields except notes are REQUIRED in dictionary entry", func(s *Sample) (bool, string) {
			if s.Service == "" || s.ResourceType == "" || s.Template == "" || s.TemplateFormat == "" || s.RegionBehavior == "" {
				return false, "missing required field"
			}
			return true, ""
		}},
		{"12.1.1", "dictionary-tuple-resolves", "(provider, service, resource_type) tuple MUST resolve to entry in conformant dictionary", func(s *Sample) (bool, string) {
			if s.Provider == "" || s.Service == "" || s.ResourceType == "" {
				return false, "incomplete tuple"
			}
			return true, ""
		}},
		{"9.1", "service-key-lowercase-underscore", "service field MUST match pattern ^[a-z][a-z0-9_]*$", func(s *Sample) (bool, string) {
			if !serviceKeyRe.MatchString(s.Service) {
				return false, fmt.Sprintf("service %q invalid", s.Service)
			}
			return true, ""
		}},
		{"9.1", "resource-type-valid-pattern", "resource_type MUST match pattern ^[a-zA-Z][a-zA-Z0-9_/-]*$", func(s *Sample) (bool, string) {
			if !resourceTypeRe.MatchString(s.ResourceType) {
				return false, fmt.Sprintf("resource_type %q invalid", s.ResourceType)
			}
			return true, ""
		}},
		{"9.1", "template-format-matches-provider", "template_format MUST match provider", func(s *Sample) (bool, string) {
			if expected := providerFormatMap[s.Provider]; expected != "" && s.TemplateFormat != expected {
				return false, fmt.Sprintf("expected %s, got %s", expected, s.TemplateFormat)
			}
			return true, ""
		}},
		{"3.2", "slot-syntax-abnf-valid", "All slots MUST conform to ABNF grammar: field-name = 1*(ALPHA / DIGIT / \"-\" / \"_\")", func(s *Sample) (bool, string) {
			for _, si := range parseSlots(s.Template) {
				if !fieldNameRe.MatchString(si.fieldName) {
					return false, fmt.Sprintf("field-name %q invalid", si.fieldName)
				}
				if si.state == "hardcoded" && !literalValueRe.MatchString(si.value) {
					return false, fmt.Sprintf("literal-value %q invalid", si.value)
				}
			}
			return true, ""
		}},
	}
}

// ---------------------------------------------------------------------------
// Record rules (25)
// ---------------------------------------------------------------------------

func defineRecordRules() []RecordRule {
	return []RecordRule{
		{"4.1", "dates-iso8601-format", "MUST", "All date fields in temporal MUST be ISO 8601 full-date (YYYY-MM-DD)", func(rec *CRITRecord) (bool, string) {
			for name, val := range collectDates(&rec.Temporal) {
				if val != "" && !isValidDate(val) {
					return false, fmt.Sprintf("temporal.%s=%q invalid date", name, val)
				}
			}
			return true, ""
		}},
		{"4.1", "natural-key-fields-present", "MUST", "vuln_id, provider, service, resource_type MUST all be non-empty", func(rec *CRITRecord) (bool, string) {
			if rec.VulnID == "" || rec.Provider == "" || rec.Service == "" || rec.ResourceType == "" {
				return false, "natural key field is empty"
			}
			return true, ""
		}},
		{"9.1", "service-key-lowercase-underscore", "MUST", "service MUST match ^[a-z][a-z0-9_]*$", func(rec *CRITRecord) (bool, string) {
			if !serviceKeyRe.MatchString(rec.Service) {
				return false, fmt.Sprintf("service %q invalid", rec.Service)
			}
			return true, ""
		}},
		{"9.1", "resource-type-valid-pattern", "MUST", "resource_type MUST match ^[a-zA-Z][a-zA-Z0-9_/-]*$", func(rec *CRITRecord) (bool, string) {
			if !resourceTypeRe.MatchString(rec.ResourceType) {
				return false, fmt.Sprintf("resource_type %q invalid", rec.ResourceType)
			}
			return true, ""
		}},
		{"9.1", "template-format-matches-provider", "MUST", "template_format MUST match provider", func(rec *CRITRecord) (bool, string) {
			if expected := providerFormatMap[rec.Provider]; expected != "" && rec.TemplateFormat != expected {
				return false, fmt.Sprintf("expected %s, got %s", expected, rec.TemplateFormat)
			}
			return true, ""
		}},
		{"3.2", "slot-syntax-abnf-valid", "MUST", "All slots MUST conform to ABNF grammar", func(rec *CRITRecord) (bool, string) {
			for _, si := range parseSlots(rec.Template) {
				if !fieldNameRe.MatchString(si.fieldName) {
					return false, fmt.Sprintf("field-name %q invalid", si.fieldName)
				}
				if si.state == "hardcoded" && !literalValueRe.MatchString(si.value) {
					return false, fmt.Sprintf("literal-value %q invalid", si.value)
				}
			}
			return true, ""
		}},
		{"3.2", "slot-delimiter-not-in-literal", "MUST", "{ and } MUST NOT appear outside slot expressions", func(rec *CRITRecord) (bool, string) {
			if strings.ContainsAny(slotRegex.ReplaceAllString(rec.Template, ""), "{}") {
				return false, "stray { or } outside slot expressions"
			}
			return true, ""
		}},
		{"6.1", "aws-global-region-hardcoded", "MUST", "AWS global-only: region MUST be hardcoded to us-east-1", func(rec *CRITRecord) (bool, string) {
			if rec.Provider != "aws" {
				return true, ""
			}
			if entry, ok := dictLookup[DictKey{rec.Provider, rec.Service, rec.ResourceType}]; !ok || entry.RegionBehavior != "global-only" {
				return true, ""
			}
			for _, si := range parseSlots(rec.Template) {
				if si.fieldName == "region" && (si.state != "hardcoded" || si.value != "us-east-1") {
					return false, fmt.Sprintf("region=%s(%s), expected hardcoded=us-east-1", si.state, si.value)
				}
			}
			return true, ""
		}},
		{"6.1", "aws-regional-region-variable", "MUST", "AWS regional: region MUST be named-variable, MUST NOT be empty", func(rec *CRITRecord) (bool, string) {
			if rec.Provider != "aws" {
				return true, ""
			}
			if entry, ok := dictLookup[DictKey{rec.Provider, rec.Service, rec.ResourceType}]; !ok || entry.RegionBehavior != "regional" {
				return true, ""
			}
			for _, si := range parseSlots(rec.Template) {
				if si.fieldName == "region" && (si.state == "empty" || si.state == "hardcoded") {
					return false, fmt.Sprintf("regional AWS region is %s", si.state)
				}
			}
			return true, ""
		}},
		{"6.4", "cloudflare-no-region-slot", "MUST", "Cloudflare templates MUST NOT have region slot", func(rec *CRITRecord) (bool, string) {
			if rec.Provider != "cloudflare" {
				return true, ""
			}
			for _, si := range parseSlots(rec.Template) {
				if si.fieldName == "region" {
					return false, "Cloudflare template contains region slot"
				}
			}
			return true, ""
		}},
		{"12.1.1", "dictionary-tuple-resolves", "MUST", "(provider, service, resource_type) MUST resolve in dictionary", func(rec *CRITRecord) (bool, string) {
			if _, ok := dictLookup[DictKey{rec.Provider, rec.Service, rec.ResourceType}]; !ok {
				return false, fmt.Sprintf("(%s, %s, %s) not in dictionaries", rec.Provider, rec.Service, rec.ResourceType)
			}
			return true, ""
		}},
		{"4.3", "customer-deadline-source-required", "MUST", "customer_deadline_source REQUIRED when customer_deadline_date present", func(rec *CRITRecord) (bool, string) {
			if rec.Temporal.CustomerDeadlineDate != nil && *rec.Temporal.CustomerDeadlineDate != "" {
				if rec.Temporal.CustomerDeadlineSource == nil || *rec.Temporal.CustomerDeadlineSource == "" {
					return false, "customer_deadline_date present but source missing"
				}
			}
			return true, ""
		}},
		{"4.3", "introduced-not-after-published", "MUST", "vulnerability_introduced_date MUST NOT be after vuln_published_date", func(rec *CRITRecord) (bool, string) {
			if rec.Temporal.VulnerabilityIntroducedDate == nil {
				return true, ""
			}
			intro, e1 := time.Parse("2006-01-02", *rec.Temporal.VulnerabilityIntroducedDate)
			pub, e2 := time.Parse("2006-01-02", rec.Temporal.VulnPublishedDate)
			if e1 != nil || e2 != nil {
				return true, ""
			}
			if intro.After(pub) {
				return false, fmt.Sprintf("introduced %s after published %s", *rec.Temporal.VulnerabilityIntroducedDate, rec.Temporal.VulnPublishedDate)
			}
			return true, ""
		}},
		{"4.4.1", "false-only-when-auto-provider", "MUST", "existing_deployments_remain_vulnerable=false ONLY when automatic+provider_only", func(rec *CRITRecord) (bool, string) {
			if !rec.ExistingDeploymentsRemainVulnerable && (rec.FixPropagation != "automatic" || rec.SharedResponsibility != "provider_only") {
				return false, fmt.Sprintf("false but propagation=%s responsibility=%s", rec.FixPropagation, rec.SharedResponsibility)
			}
			return true, ""
		}},
		{"4.4.2", "no-fix-no-provider-fix-date", "MUST", "no_fix_available -> provider_fix_date MUST be absent", func(rec *CRITRecord) (bool, string) {
			if rec.FixPropagation == "no_fix_available" && rec.Temporal.ProviderFixDate != nil && *rec.Temporal.ProviderFixDate != "" {
				return false, fmt.Sprintf("no_fix_available but provider_fix_date=%s", *rec.Temporal.ProviderFixDate)
			}
			return true, ""
		}},
		{"8.2", "provider-only-fix-not-vulnerable", "MUST", "provider_only + fix_date -> existing_deployments_remain_vulnerable MUST be false", func(rec *CRITRecord) (bool, string) {
			if rec.SharedResponsibility == "provider_only" && rec.Temporal.ProviderFixDate != nil && *rec.Temporal.ProviderFixDate != "" && rec.ExistingDeploymentsRemainVulnerable {
				return false, "provider_only with fix_date but vulnerable=true"
			}
			return true, ""
		}},
		{"4.4.3", "sequence-unique-contiguous", "MUST", "remediation_actions sequence MUST be unique and contiguous from 1", func(rec *CRITRecord) (bool, string) {
			if len(rec.RemediationActions) == 0 {
				return true, ""
			}
			seen := make(map[int]bool)
			for _, a := range rec.RemediationActions {
				if seen[a.Sequence] {
					return false, fmt.Sprintf("duplicate sequence %d", a.Sequence)
				}
				seen[a.Sequence] = true
			}
			for i := 1; i <= len(rec.RemediationActions); i++ {
				if !seen[i] {
					return false, fmt.Sprintf("missing sequence %d", i)
				}
			}
			return true, ""
		}},
		{"4.4.3", "downtime-range-when-required", "MUST", "estimated_downtime_range_seconds REQUIRED when requires_downtime=true", func(rec *CRITRecord) (bool, string) {
			for _, a := range rec.RemediationActions {
				if a.RequiresDowntime && a.EstimatedDowntimeRangeSeconds == nil {
					return false, fmt.Sprintf("action seq %d requires_downtime but no range", a.Sequence)
				}
			}
			return true, ""
		}},
		{"4.4.3", "compensating-only-means-affected", "MUST", "All compensating actions -> vex_status MUST be affected", func(rec *CRITRecord) (bool, string) {
			if len(rec.RemediationActions) == 0 {
				return true, ""
			}
			all := true
			for _, a := range rec.RemediationActions {
				if !a.CompensatingControl {
					all = false
					break
				}
			}
			if all && rec.VexStatus != "affected" {
				return false, fmt.Sprintf("all compensating but vex_status=%s", rec.VexStatus)
			}
			return true, ""
		}},
		{"9.1", "remediation-actions-present", "MUST", "At least one remediation_actions for vex_status=affected or fixed", func(rec *CRITRecord) (bool, string) {
			if (rec.VexStatus == "affected" || rec.VexStatus == "fixed") && len(rec.RemediationActions) == 0 {
				return false, fmt.Sprintf("vex_status=%s but no actions", rec.VexStatus)
			}
			return true, ""
		}},
		{"4.5.1", "auto-upgrade-false-means-vulnerable", "MUST", "auto_upgrade=false -> existing_deployments_remain_vulnerable MUST be true", func(rec *CRITRecord) (bool, string) {
			if rec.ProviderFixVersion != nil && rec.ProviderFixVersion.AutoUpgrade != nil && !*rec.ProviderFixVersion.AutoUpgrade && !rec.ExistingDeploymentsRemainVulnerable {
				return false, "auto_upgrade=false but vulnerable=false"
			}
			return true, ""
		}},
		{"4.6", "detection-recommended", "SHOULD", "vex_status=affected or fixed SHOULD include >=1 detection entry", func(rec *CRITRecord) (bool, string) {
			if (rec.VexStatus == "affected" || rec.VexStatus == "fixed") && len(rec.Detections) == 0 {
				return false, fmt.Sprintf("vex_status=%s but no detections", rec.VexStatus)
			}
			return true, ""
		}},
		{"4.6.3", "misconfiguration-detection-for-opt-in", "MUST", "opt_in or config_change MUST include misconfiguration-phase detection (placeholder with pending_reason accepted)", func(rec *CRITRecord) (bool, string) {
			if rec.FixPropagation != "opt_in" && rec.FixPropagation != "config_change" {
				return true, ""
			}
			for _, d := range rec.Detections {
				if d.DetectionPhase == "misconfiguration" {
					return true, ""
				}
			}
			return false, fmt.Sprintf("propagation=%s but no misconfiguration detection", rec.FixPropagation)
		}},
		{"4.6.4", "pending-reason-enum", "MUST", "pending_reason MUST be a valid enum value when present", func(rec *CRITRecord) (bool, string) {
			valid := map[string]bool{
				"query_in_development":        true,
				"awaiting_provider_telemetry": true,
				"no_detection_surface":        true,
				"access_constraint":           true,
				"pending_review":              true,
			}
			for i, d := range rec.Detections {
				if d.PendingReason != nil && !valid[*d.PendingReason] {
					return false, fmt.Sprintf("detections[%d].pending_reason=%q not in enum", i, *d.PendingReason)
				}
			}
			return true, ""
		}},
		{"4.6.4", "pending-reason-empty-query", "MUST", "query MUST be empty string when pending_reason is set", func(rec *CRITRecord) (bool, string) {
			for i, d := range rec.Detections {
				if d.PendingReason != nil && d.Query != "" {
					return false, fmt.Sprintf("detections[%d] has pending_reason but non-empty query", i)
				}
			}
			return true, ""
		}},
		{"4.6.4", "no-empty-query-without-pending", "MUST", "functional detection with empty query requires pending_reason", func(rec *CRITRecord) (bool, string) {
			for i, d := range rec.Detections {
				if d.PendingReason == nil && d.Query == "" {
					return false, fmt.Sprintf("detections[%d] has empty query without pending_reason", i)
				}
			}
			return true, ""
		}},
		{"4.7", "cvss-score-range", "MUST", "provider_cvss_score MUST be in [0.0, 10.0] when present", func(rec *CRITRecord) (bool, string) {
			if rec.ProviderAdvisory == nil || rec.ProviderAdvisory.ProviderCVSSScore == nil {
				return true, ""
			}
			s := *rec.ProviderAdvisory.ProviderCVSSScore
			if s < 0.0 || s > 10.0 {
				return false, fmt.Sprintf("score=%.1f outside [0.0, 10.0]", s)
			}
			return true, ""
		}},
		{"4.7", "cvss-vector-format", "MUST", "provider_cvss_vector MUST conform to CVSS v3.1 or v4.0 format", func(rec *CRITRecord) (bool, string) {
			if rec.ProviderAdvisory == nil || rec.ProviderAdvisory.ProviderCVSSVector == nil {
				return true, ""
			}
			v := *rec.ProviderAdvisory.ProviderCVSSVector
			if !cvss31Re.MatchString(v) && !cvss40Re.MatchString(v) {
				return false, fmt.Sprintf("vector %q invalid format", v)
			}
			return true, ""
		}},
	}
}

// ---------------------------------------------------------------------------
// Run suites
// ---------------------------------------------------------------------------

func runTemplateSuite(samples []Sample, rules []TemplateRule) *SuiteResult {
	sr := &SuiteResult{Name: "Template Rules", RuleCount: len(rules), SampleCount: len(samples), Results: make(map[string]*RuleResult)}
	for _, r := range rules {
		sr.Results[r.Name] = &RuleResult{}
	}
	for i := range samples {
		s := &samples[i]
		for _, rule := range rules {
			pass, detail := rule.Check(s)
			rr := sr.Results[rule.Name]
			if pass {
				rr.Pass++
				sr.TotalPass++
			} else {
				rr.Fail++
				sr.TotalFail++
				sr.Failures = append(sr.Failures, Failure{
					RuleName: rule.Name, Section: rule.Section, Level: "MUST",
					Provider: s.Provider, Service: s.Service, ResourceType: s.ResourceType, Detail: detail,
				})
			}
		}
	}
	return sr
}

func runRecordSuite(records []CRITRecord, rules []RecordRule) *SuiteResult {
	sr := &SuiteResult{Name: "Sample Record Rules", RuleCount: len(rules), SampleCount: len(records), Results: make(map[string]*RuleResult)}
	for _, r := range rules {
		sr.Results[r.Name] = &RuleResult{}
	}
	for i := range records {
		rec := &records[i]
		for _, rule := range rules {
			pass, detail := rule.Check(rec)
			rr := sr.Results[rule.Name]
			if pass {
				rr.Pass++
				sr.TotalPass++
			} else if rule.Level == "SHOULD" {
				rr.Warn++
				sr.TotalWarn++
				sr.Failures = append(sr.Failures, Failure{
					RuleName: rule.Name, Section: rule.Section, Level: rule.Level,
					Provider: rec.Provider, Service: rec.Service, ResourceType: rec.ResourceType,
					Detail: detail, FilePath: rec.FilePath,
				})
			} else {
				rr.Fail++
				sr.TotalFail++
				sr.Failures = append(sr.Failures, Failure{
					RuleName: rule.Name, Section: rule.Section, Level: rule.Level,
					Provider: rec.Provider, Service: rec.Service, ResourceType: rec.ResourceType,
					Detail: detail, FilePath: rec.FilePath,
				})
			}
		}
	}
	return sr
}

// ---------------------------------------------------------------------------
// Console output
// ---------------------------------------------------------------------------

func printSuiteConsole(sr *SuiteResult, ruleNames []string, ruleSections map[string]string, ruleReqs map[string]string) {
	fmt.Printf("\n=== %s (%d rules x %d samples) ===\n", sr.Name, sr.RuleCount, sr.SampleCount)
	fmt.Println(strings.Repeat("-", 130))
	for _, f := range sr.Failures {
		label := "FAIL"
		if f.Level == "SHOULD" {
			label = "WARN"
		}
		st := fmt.Sprintf("%s/%s", f.Service, f.ResourceType)
		if len(st) > 28 {
			st = st[:25] + "..."
		}
		d := f.Detail
		if len(d) > 50 {
			d = d[:47] + "..."
		}
		fmt.Printf("%-6s | %-6s | %-38s | %-12s | %-28s | %s\n", label, f.Section, f.RuleName, f.Provider, st, d)
	}
	fmt.Println(strings.Repeat("-", 130))
	for _, name := range ruleNames {
		rr := sr.Results[name]
		status := "PASS"
		if rr.Fail > 0 {
			status = "FAIL"
		} else if rr.Warn > 0 {
			status = "WARN"
		}
		req := ruleReqs[name]
		if len(req) > 40 {
			req = req[:37] + "..."
		}
		fmt.Printf("%-6s | %-6s | %-38s | %5d | %5d | %5d | %s\n", status, ruleSections[name], name, rr.Pass, rr.Fail, rr.Warn, req)
	}
	fmt.Printf("TOTAL: %d passed, %d failed, %d warnings\n", sr.TotalPass, sr.TotalFail, sr.TotalWarn)
}

// ---------------------------------------------------------------------------
// Markdown report
// ---------------------------------------------------------------------------

func writeConsolidatedReport(path string, tplSuite, recSuite *SuiteResult, tplRules []TemplateRule, recRules []RecordRule, now time.Time) error {
	var b strings.Builder
	totalPass := tplSuite.TotalPass + recSuite.TotalPass
	totalFail := tplSuite.TotalFail + recSuite.TotalFail
	totalWarn := tplSuite.TotalWarn + recSuite.TotalWarn
	totalChecks := totalPass + totalFail + totalWarn

	verdict := "PASS"
	if totalFail > 0 {
		verdict = "FAIL"
	} else if totalWarn > 0 {
		verdict = "WARN"
	}

	b.WriteString("# CRIT Spec Conformance Report\n\n")
	fmt.Fprintf(&b, "**Date:** %s  \n", now.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(&b, "**Verdict:** %s  \n", verdict)
	fmt.Fprintf(&b, "**Total Checks:** %d | **Passed:** %d | **Failed:** %d | **Warnings:** %d  \n\n", totalChecks, totalPass, totalFail, totalWarn)

	// Summary table
	b.WriteString("## Summary\n\n")
	b.WriteString("| Suite | Rules | Samples | Checks | Passed | Failed | Warnings |\n")
	b.WriteString("|-------|------:|--------:|-------:|-------:|-------:|---------:|\n")
	fmt.Fprintf(&b, "| Template Rules | %d | %d | %d | %d | %d | %d |\n",
		tplSuite.RuleCount, tplSuite.SampleCount, tplSuite.TotalPass+tplSuite.TotalFail, tplSuite.TotalPass, tplSuite.TotalFail, tplSuite.TotalWarn)
	fmt.Fprintf(&b, "| Sample Record Rules | %d | %d | %d | %d | %d | %d |\n\n",
		recSuite.RuleCount, recSuite.SampleCount, recSuite.TotalPass+recSuite.TotalFail+recSuite.TotalWarn, recSuite.TotalPass, recSuite.TotalFail, recSuite.TotalWarn)

	// Template suite section
	writeSuiteSection(&b, tplSuite, tplRules, nil)

	// Record suite section
	writeSuiteSection(&b, recSuite, nil, recRules)

	b.WriteString("---\n\n")
	b.WriteString("*Generated by `crit-test` from [draft-vulnetix-crit-01](../drafts/draft-vulnetix-crit-01.xml)*\n")

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("creating report dir: %w", err)
	}
	return os.WriteFile(path, []byte(b.String()), 0644)
}

func writeSuiteSection(b *strings.Builder, sr *SuiteResult, tplRules []TemplateRule, recRules []RecordRule) {
	fmt.Fprintf(b, "## %s\n\n", sr.Name)

	// Pie chart
	b.WriteString("```mermaid\n")
	fmt.Fprintf(b, "pie title \"%s\"\n", sr.Name)
	fmt.Fprintf(b, "    \"Pass\" : %d\n", sr.TotalPass)
	fmt.Fprintf(b, "    \"Fail\" : %d\n", sr.TotalFail)
	if sr.TotalWarn > 0 {
		fmt.Fprintf(b, "    \"Warn\" : %d\n", sr.TotalWarn)
	}
	b.WriteString("```\n\n")

	// Provider breakdown
	provSamples := make(map[string]int)
	provFail := make(map[string]int)
	provWarn := make(map[string]int)
	for _, f := range sr.Failures {
		if f.Level == "SHOULD" {
			provWarn[f.Provider]++
		} else {
			provFail[f.Provider]++
		}
	}
	// Count samples per provider from failures+passes — use rule count to derive
	// We don't have direct sample-level provider info here, so compute from results
	providers := []string{"aws", "azure", "gcp", "cloudflare", "oracle"}

	hasProviders := false
	for _, f := range sr.Failures {
		if f.Provider != "" {
			hasProviders = true
			break
		}
	}

	if hasProviders {
		// Count unique provider occurrences from samples
		// For template suite: each sample has a provider, total checks = samples * rules
		// We estimate from failures. A better approach: pass provider counts directly.
		// For now, show the failure breakdown.
		b.WriteString("### Failures by Provider\n\n")
		b.WriteString("| Provider | Failed | Warnings |\n")
		b.WriteString("|----------|-------:|---------:|\n")
		for _, p := range providers {
			if provFail[p]+provWarn[p] > 0 {
				fmt.Fprintf(b, "| %s | %d | %d |\n", p, provFail[p], provWarn[p])
			}
		}
		if len(provFail)+len(provWarn) == 0 {
			b.WriteString("| *(none)* | 0 | 0 |\n")
		}
		b.WriteString("\n")
		_ = provSamples
	}

	// Rule results table
	b.WriteString("### Rule Results\n\n")
	if recRules != nil {
		b.WriteString("| Status | Level | Sec | Rule | Pass | Fail | Warn | Requirement |\n")
		b.WriteString("|:------:|:-----:|:---:|------|-----:|-----:|-----:|-------------|\n")
		for _, r := range recRules {
			rr := sr.Results[r.Name]
			status := "PASS"
			if rr.Fail > 0 {
				status = "FAIL"
			} else if rr.Warn > 0 {
				status = "WARN"
			}
			fmt.Fprintf(b, "| %s | %s | %s | `%s` | %d | %d | %d | %s |\n",
				status, r.Level, r.Section, r.Name, rr.Pass, rr.Fail, rr.Warn, escapeMarkdown(r.Requirement))
		}
	} else if tplRules != nil {
		b.WriteString("| Status | Sec | Rule | Pass | Fail | Requirement |\n")
		b.WriteString("|:------:|:---:|------|-----:|-----:|-------------|\n")
		for _, r := range tplRules {
			rr := sr.Results[r.Name]
			status := "PASS"
			if rr.Fail > 0 {
				status = "FAIL"
			}
			fmt.Fprintf(b, "| %s | %s | `%s` | %d | %d | %s |\n",
				status, r.Section, r.Name, rr.Pass, rr.Fail, escapeMarkdown(r.Requirement))
		}
	}
	b.WriteString("\n")

	// Failures
	if len(sr.Failures) > 0 {
		b.WriteString("### Failures & Warnings\n\n")
		failsByRule := make(map[string][]Failure)
		for _, f := range sr.Failures {
			failsByRule[f.RuleName] = append(failsByRule[f.RuleName], f)
		}
		names := make([]string, 0, len(failsByRule))
		for k := range failsByRule {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, name := range names {
			ff := failsByRule[name]
			label := "failures"
			if ff[0].Level == "SHOULD" {
				label = "warnings"
			}
			fmt.Fprintf(b, "#### `%s` (%s) &mdash; %d %s\n\n", name, ff[0].Section, len(ff), label)
			b.WriteString("| Provider | Service | Resource Type | Detail |\n")
			b.WriteString("|----------|---------|---------------|--------|\n")
			cap := 20
			for i, f := range ff {
				if i >= cap {
					fmt.Fprintf(b, "| ... | ... | ... | *%d more omitted* |\n", len(ff)-cap)
					break
				}
				d := escapeMarkdown(f.Detail)
				if len(d) > 70 {
					d = d[:67] + "..."
				}
				fmt.Fprintf(b, "| %s | %s | %s | %s |\n", f.Provider, f.Service, f.ResourceType, d)
			}
			b.WriteString("\n")
		}
	}
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	reportDir := flag.String("report", "", "Write YYYYMMDD-crit-test-report.md to this directory")
	noFail := flag.Bool("no-fail", false, "Exit 0 even on MUST failures")
	quiet := flag.Bool("quiet", false, "Suppress console output")
	flag.Parse()

	// Locate directories — running from project root: `go run ./tests/cmd/crit-test`
	dictDir := findDir("dictionaries")
	if dictDir == "" {
		fmt.Fprintln(os.Stderr, "Error: cannot find dictionaries/ directory")
		os.Exit(1)
	}
	testsDir := findDir("tests")
	if testsDir == "" {
		fmt.Fprintln(os.Stderr, "Error: cannot find tests/ directory")
		os.Exit(1)
	}
	samplesDir := findDir("samples")
	if samplesDir == "" {
		fmt.Fprintln(os.Stderr, "Error: cannot find samples/ directory")
		os.Exit(1)
	}

	// Load dictionaries
	dicts, lookup, err := loadDictionaries(dictDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	dictLookup = lookup

	// === Phase 1: Generate samples ===
	samples, err := generateSamples(dicts, testsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating samples: %v\n", err)
		os.Exit(1)
	}

	// Write CRIT-samples.json (for schema validation step)
	samplesOut := SamplesOutput{
		Schema: "../schemas/crit-samples-v0.1.0.schema.json", GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Wordlists: make(map[string]map[string][]string), Samples: samples,
	}
	for _, p := range []string{"aws", "azure", "gcp", "cloudflare", "oracle"} {
		wl, _ := loadWordlists(p, testsDir)
		samplesOut.Wordlists[p] = wl
	}
	samplesJSON, _ := json.MarshalIndent(samplesOut, "", "  ")
	outPath := filepath.Join(testsDir, "CRIT-samples.json")
	if err := os.WriteFile(outPath, samplesJSON, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", outPath, err)
		os.Exit(1)
	}
	if !*quiet {
		fmt.Printf("Generated %d template samples -> %s\n", len(samples), outPath)
	}

	// === Phase 2: Run template rules ===
	tplRules := defineTemplateRules()
	tplSuite := runTemplateSuite(samples, tplRules)

	// === Phase 3: Run record rules ===
	records, err := loadSampleRecords(samplesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading sample records: %v\n", err)
		os.Exit(1)
	}
	recRules := defineRecordRules()
	recSuite := runRecordSuite(records, recRules)

	// === Console output ===
	if !*quiet {
		// Template suite
		tplNames := make([]string, len(tplRules))
		tplSecs := make(map[string]string)
		tplReqs := make(map[string]string)
		for i, r := range tplRules {
			tplNames[i] = r.Name
			tplSecs[r.Name] = r.Section
			tplReqs[r.Name] = r.Requirement
		}
		printSuiteConsole(tplSuite, tplNames, tplSecs, tplReqs)

		// Record suite
		recNames := make([]string, len(recRules))
		recSecs := make(map[string]string)
		recReqs := make(map[string]string)
		for i, r := range recRules {
			recNames[i] = r.Name
			recSecs[r.Name] = r.Section
			recReqs[r.Name] = r.Requirement
		}
		printSuiteConsole(recSuite, recNames, recSecs, recReqs)

		// Grand total
		totalP := tplSuite.TotalPass + recSuite.TotalPass
		totalF := tplSuite.TotalFail + recSuite.TotalFail
		totalW := tplSuite.TotalWarn + recSuite.TotalWarn
		fmt.Printf("\n=== Grand Total: %d passed, %d failed, %d warnings ===\n", totalP, totalF, totalW)
	}

	// === Report ===
	now := time.Now().UTC()
	if *reportDir != "" {
		reportFile := filepath.Join(*reportDir, now.Format("20060102")+"-crit-test-report.md")
		if err := writeConsolidatedReport(reportFile, tplSuite, recSuite, tplRules, recRules, now); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing report: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\nReport written to %s\n", reportFile)
	}

	if (tplSuite.TotalFail+recSuite.TotalFail) > 0 && !*noFail {
		os.Exit(1)
	}
}
