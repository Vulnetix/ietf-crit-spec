// crit-validate validates CVEListv5 JSON files containing Vulnetix VVD ADP
// containers with x_crit extensions against the CRIT specification
// (draft-vulnetix-crit-00).
//
// The binary embeds the Spec Default Dictionary and the dictionary JSON Schema
// at build time. Custom dictionaries provided via --dictionary are validated
// against the embedded schema and merged with the built-in entries before
// rule evaluation.
//
// Install:
//
//	go install github.com/Vulnetix/ietf-crit-spec/cmd/crit-validate@latest
//
// Usage:
//
//	crit-validate --data <dir> [--dictionary <file-or-dir>] [--report <dir>] [--adp-short-name <name>] [--no-fail] [--quiet]
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

	critspec "github.com/Vulnetix/ietf-crit-spec"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// ---------------------------------------------------------------------------
// CVEListv5 types
// ---------------------------------------------------------------------------

type CVERecord struct {
	DataType    string      `json:"dataType"`
	DataVersion string      `json:"dataVersion"`
	CVEMetadata CVEMetadata `json:"cveMetadata"`
	Containers  Containers  `json:"containers"`
	FilePath    string      `json:"-"`
}

type CVEMetadata struct {
	CVEID             string  `json:"cveId"`
	AssignerOrgID     string  `json:"assignerOrgId"`
	State             string  `json:"state"`
	AssignerShortName *string `json:"assignerShortName,omitempty"`
	DatePublished     *string `json:"datePublished,omitempty"`
}

type Containers struct {
	CNA json.RawMessage `json:"cna"`
	ADP []ADPContainer  `json:"adp,omitempty"`
}

type ADPContainer struct {
	ProviderMetadata ProviderMetadata `json:"providerMetadata"`
	Title            *string          `json:"title,omitempty"`
	XCrit            []CRITRecord     `json:"x_crit,omitempty"`
}

type ProviderMetadata struct {
	OrgID     string  `json:"orgId"`
	ShortName *string `json:"shortName,omitempty"`
}

// ---------------------------------------------------------------------------
// CRIT record types (embedded in x_crit)
// ---------------------------------------------------------------------------

type CRITRecord struct {
	VectorString                        string              `json:"vectorString"`
	VulnID                              string              `json:"vuln_id"`
	Provider                            string              `json:"provider"`
	Service                             string              `json:"service"`
	ResourceType                        string              `json:"resource_type"`
	ResourceLifecycle                   string              `json:"resource_lifecycle"`
	SharedResponsibility                string              `json:"shared_responsibility"`
	VexStatus                           string              `json:"vex_status"`
	Template                            string              `json:"template"`
	TemplateFormat                      string              `json:"template_format"`
	Temporal                            Temporal            `json:"temporal"`
	FixPropagation                      string              `json:"fix_propagation"`
	ExistingDeploymentsRemainVulnerable bool                `json:"existing_deployments_remain_vulnerable"`
	ProviderFixVersion                  *ProviderFixVersion `json:"provider_fix_version,omitempty"`
	RemediationActions                  []RemediationAction `json:"remediation_actions"`
	Detections                          []Detection         `json:"detections,omitempty"`
	ProviderAdvisory                    *ProviderAdvisory   `json:"provider_advisory,omitempty"`
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

type DowntimeRange struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

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
	AdvisoryID  *string `json:"advisory_id,omitempty"`
	AdvisoryURL *string `json:"advisory_url,omitempty"`
}

// ---------------------------------------------------------------------------
// Dictionary types
// ---------------------------------------------------------------------------

type DictionaryFile struct {
	DictionaryVersion string            `json:"dictionary_version"`
	Provider          string            `json:"provider"`
	Entries           []DictionaryEntry `json:"entries"`
}

type DictionaryEntry struct {
	Service        string `json:"service"`
	ResourceType   string `json:"resource_type"`
	Template       string `json:"template"`
	TemplateFormat string `json:"template_format"`
	RegionBehavior string `json:"region_behavior"`
}

// DictionaryLookup maps "provider|service|resource_type" to DictionaryEntry.
type DictionaryLookup map[string]DictionaryEntry

func dictKey(provider, service, resourceType string) string {
	return provider + "|" + service + "|" + resourceType
}

// ---------------------------------------------------------------------------
// Rule types
// ---------------------------------------------------------------------------

type Rule struct {
	Section     string
	Name        string
	Requirement string
	Check       func(rec *CVERecord) (bool, string)
}

type RuleResult struct {
	Pass int
	Fail int
}

type Failure struct {
	RuleName string
	Section  string
	CVEID    string
	Detail   string
	FilePath string
}

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

var (
	cveIDRe       = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)
	dataVersionRe = regexp.MustCompile(`^5\.\d+`)
	serviceKeyRe  = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	dateRe        = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

var providerFormatMap = map[string]string{
	"aws": "aws_arn", "azure": "azure_resource_id", "gcp": "gcp_resource_name",
	"cloudflare": "cloudflare_locator", "oracle": "oracle_ocid",
}

// adpShortName is the ADP container shortName to look for. Set via --adp-short-name flag.
var adpShortName = "VVD"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func findADP(rec *CVERecord) *ADPContainer {
	for i := range rec.Containers.ADP {
		adp := &rec.Containers.ADP[i]
		if adp.ProviderMetadata.ShortName != nil && *adp.ProviderMetadata.ShortName == adpShortName {
			return adp
		}
	}
	return nil
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

// ---------------------------------------------------------------------------
// Dictionary loading
// ---------------------------------------------------------------------------

// loadBuiltinDictionaries reads the Spec Default Dictionary from the embedded
// filesystem compiled into the binary.
func loadBuiltinDictionaries() (DictionaryLookup, error) {
	lookup := make(DictionaryLookup)
	entries, err := fs.ReadDir(critspec.Dictionaries, "dictionaries")
	if err != nil {
		return nil, fmt.Errorf("reading embedded dictionaries: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := fs.ReadFile(critspec.Dictionaries, "dictionaries/"+entry.Name())
		if err != nil {
			return nil, fmt.Errorf("reading embedded %s: %w", entry.Name(), err)
		}
		var df DictionaryFile
		if err := json.Unmarshal(data, &df); err != nil {
			return nil, fmt.Errorf("parsing embedded %s: %w", entry.Name(), err)
		}
		for _, e := range df.Entries {
			lookup[dictKey(df.Provider, e.Service, e.ResourceType)] = e
		}
	}
	return lookup, nil
}

// compileDictionarySchema compiles the embedded JSON Schema for validating
// dictionary files.
func compileDictionarySchema() (*jsonschema.Schema, error) {
	var schemaDoc any
	if err := json.Unmarshal(critspec.DictionarySchema, &schemaDoc); err != nil {
		return nil, fmt.Errorf("parsing embedded schema: %w", err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("schema.json", schemaDoc); err != nil {
		return nil, fmt.Errorf("adding schema resource: %w", err)
	}
	return c.Compile("schema.json")
}

// validateDictionaryFile validates raw JSON bytes against the compiled
// dictionary schema and returns a descriptive error on failure.
func validateDictionaryFile(sch *jsonschema.Schema, data []byte, filename string) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("%s: invalid JSON: %w", filename, err)
	}
	if err := sch.Validate(v); err != nil {
		return fmt.Errorf("%s: schema validation failed: %w", filename, err)
	}
	return nil
}

// loadExternalDictionaries reads dictionary files from a path (file or
// directory), validates each against the schema, and returns the entries.
func loadExternalDictionaries(path string, sch *jsonschema.Schema) (DictionaryLookup, error) {
	lookup := make(DictionaryLookup)

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("--dictionary %q: %w", path, err)
	}

	var files []string
	if info.IsDir() {
		dirEntries, err := os.ReadDir(path)
		if err != nil {
			return nil, fmt.Errorf("reading directory %s: %w", path, err)
		}
		for _, de := range dirEntries {
			if !de.IsDir() && strings.HasSuffix(de.Name(), ".json") {
				files = append(files, filepath.Join(path, de.Name()))
			}
		}
	} else {
		files = []string{path}
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("--dictionary %q: no JSON files found", path)
	}

	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", f, err)
		}
		if err := validateDictionaryFile(sch, data, f); err != nil {
			return nil, err
		}
		var df DictionaryFile
		if err := json.Unmarshal(data, &df); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", f, err)
		}
		for _, e := range df.Entries {
			lookup[dictKey(df.Provider, e.Service, e.ResourceType)] = e
		}
	}
	return lookup, nil
}

// mergeDictionaries returns a new lookup containing all entries from builtin
// plus any additional entries from external. External entries supplement but
// do not override builtin entries.
func mergeDictionaries(builtin, external DictionaryLookup) DictionaryLookup {
	merged := make(DictionaryLookup, len(builtin)+len(external))
	for k, v := range builtin {
		merged[k] = v
	}
	for k, v := range external {
		if _, exists := merged[k]; !exists {
			merged[k] = v
		}
	}
	return merged
}

// ---------------------------------------------------------------------------
// CVE record loading
// ---------------------------------------------------------------------------

func loadCVERecords(dataDir string) ([]CVERecord, error) {
	var records []CVERecord
	err := filepath.WalkDir(dataDir, func(path string, d fs.DirEntry, err error) error {
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
		var rec CVERecord
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
// Rules
// ---------------------------------------------------------------------------

func defineRules(dict DictionaryLookup) []Rule {
	return []Rule{
		// --- CVEListv5 Structural ---
		{
			Section: "10.1", Name: "cve-record-data-type",
			Requirement: "dataType MUST be \"CVE_RECORD\"",
			Check: func(rec *CVERecord) (bool, string) {
				if rec.DataType != "CVE_RECORD" {
					return false, fmt.Sprintf("dataType=%q, expected CVE_RECORD", rec.DataType)
				}
				return true, ""
			},
		},
		{
			Section: "10.1", Name: "cve-record-data-version",
			Requirement: "dataVersion MUST match CVEListv5 version (^5\\.\\d+)",
			Check: func(rec *CVERecord) (bool, string) {
				if !dataVersionRe.MatchString(rec.DataVersion) {
					return false, fmt.Sprintf("dataVersion=%q does not match ^5.\\d+", rec.DataVersion)
				}
				return true, ""
			},
		},
		{
			Section: "10.1", Name: "cve-id-format",
			Requirement: "cveMetadata.cveId MUST match ^CVE-[0-9]{4}-[0-9]{4,19}$",
			Check: func(rec *CVERecord) (bool, string) {
				if !cveIDRe.MatchString(rec.CVEMetadata.CVEID) {
					return false, fmt.Sprintf("cveId=%q invalid format", rec.CVEMetadata.CVEID)
				}
				return true, ""
			},
		},
		{
			Section: "10.1", Name: "cve-state-published",
			Requirement: "cveMetadata.state MUST be PUBLISHED for records containing x_crit data",
			Check: func(rec *CVERecord) (bool, string) {
				if findADP(rec) != nil && rec.CVEMetadata.State != "PUBLISHED" {
					return false, fmt.Sprintf("state=%q but record contains x_crit data", rec.CVEMetadata.State)
				}
				return true, ""
			},
		},
		{
			Section: "10.1", Name: "cve-assigner-org-id-present",
			Requirement: "cveMetadata.assignerOrgId MUST be non-empty",
			Check: func(rec *CVERecord) (bool, string) {
				if rec.CVEMetadata.AssignerOrgID == "" {
					return false, "assignerOrgId is empty"
				}
				return true, ""
			},
		},
		{
			Section: "10.1", Name: "adp-provider-metadata-present",
			Requirement: "Each ADP container MUST have providerMetadata with non-empty orgId",
			Check: func(rec *CVERecord) (bool, string) {
				for i, adp := range rec.Containers.ADP {
					if adp.ProviderMetadata.OrgID == "" {
						return false, fmt.Sprintf("adp[%d] missing providerMetadata.orgId", i)
					}
				}
				return true, ""
			},
		},

		// --- VVD ADP + x_crit (Section 10.1.1) ---
		{
			Section: "10.1.1", Name: "adp-container-present",
			Requirement: "CVE record MUST contain an ADP container matching --adp-short-name",
			Check: func(rec *CVERecord) (bool, string) {
				if findADP(rec) == nil {
					return false, fmt.Sprintf("no ADP container with shortName=%q found", adpShortName)
				}
				return true, ""
			},
		},
		{
			Section: "10.1.1", Name: "x-crit-array-present",
			Requirement: "ADP container MUST contain non-empty x_crit array",
			Check: func(rec *CVERecord) (bool, string) {
				vvd := findADP(rec)
				if vvd == nil {
					return true, "" // adp-container-present will catch this
				}
				if len(vvd.XCrit) == 0 {
					return false, fmt.Sprintf("%s ADP has empty or missing x_crit array", adpShortName)
				}
				return true, ""
			},
		},
		{
			Section: "10.1.1", Name: "x-crit-vuln-id-matches-cve",
			Requirement: "Each x_crit entry vuln_id MUST match cveMetadata.cveId",
			Check: func(rec *CVERecord) (bool, string) {
				vvd := findADP(rec)
				if vvd == nil {
					return true, ""
				}
				for i, cr := range vvd.XCrit {
					if cr.VulnID != rec.CVEMetadata.CVEID {
						return false, fmt.Sprintf("x_crit[%d].vuln_id=%q != cveId=%q", i, cr.VulnID, rec.CVEMetadata.CVEID)
					}
				}
				return true, ""
			},
		},
		{
			Section: "10.1.1", Name: "x-crit-natural-key-unique",
			Requirement: "No two x_crit entries MAY share same (vuln_id, provider, service, resource_type) tuple",
			Check: func(rec *CVERecord) (bool, string) {
				vvd := findADP(rec)
				if vvd == nil {
					return true, ""
				}
				seen := make(map[string]bool)
				for i, cr := range vvd.XCrit {
					key := fmt.Sprintf("%s|%s|%s|%s", cr.VulnID, cr.Provider, cr.Service, cr.ResourceType)
					if seen[key] {
						return false, fmt.Sprintf("x_crit[%d] duplicate natural key: %s/%s/%s", i, cr.Provider, cr.Service, cr.ResourceType)
					}
					seen[key] = true
				}
				return true, ""
			},
		},
		{
			Section: "10.1.1", Name: "x-crit-one-per-natural-key",
			Requirement: "x_crit array MUST contain one entry per natural key tuple applicable to the CVE",
			Check: func(rec *CVERecord) (bool, string) {
				vvd := findADP(rec)
				if vvd == nil {
					return true, ""
				}
				for i, cr := range vvd.XCrit {
					if cr.VulnID == "" || cr.Provider == "" || cr.Service == "" || cr.ResourceType == "" {
						return false, fmt.Sprintf("x_crit[%d] incomplete natural key: vuln_id=%q provider=%q service=%q resource_type=%q",
							i, cr.VulnID, cr.Provider, cr.Service, cr.ResourceType)
					}
				}
				return true, ""
			},
		},

		// --- Embedded CRIT record validation ---
		{
			Section: "9.1", Name: "x-crit-service-key-pattern",
			Requirement: "Each x_crit entry service MUST match ^[a-z][a-z0-9_]*$",
			Check: func(rec *CVERecord) (bool, string) {
				vvd := findADP(rec)
				if vvd == nil {
					return true, ""
				}
				for i, cr := range vvd.XCrit {
					if !serviceKeyRe.MatchString(cr.Service) {
						return false, fmt.Sprintf("x_crit[%d].service=%q invalid pattern", i, cr.Service)
					}
				}
				return true, ""
			},
		},
		{
			Section: "9.1", Name: "x-crit-template-format-matches-provider",
			Requirement: "Each x_crit entry template_format MUST match provider",
			Check: func(rec *CVERecord) (bool, string) {
				vvd := findADP(rec)
				if vvd == nil {
					return true, ""
				}
				for i, cr := range vvd.XCrit {
					expected := providerFormatMap[cr.Provider]
					if expected != "" && cr.TemplateFormat != expected {
						return false, fmt.Sprintf("x_crit[%d] provider=%s expects %s, got %s", i, cr.Provider, expected, cr.TemplateFormat)
					}
				}
				return true, ""
			},
		},
		{
			Section: "4.1", Name: "x-crit-dates-iso8601",
			Requirement: "All date fields in x_crit temporal MUST be valid ISO 8601 full-date (YYYY-MM-DD)",
			Check: func(rec *CVERecord) (bool, string) {
				vvd := findADP(rec)
				if vvd == nil {
					return true, ""
				}
				for i, cr := range vvd.XCrit {
					for name, val := range collectDates(&cr.Temporal) {
						if val != "" && !isValidDate(val) {
							return false, fmt.Sprintf("x_crit[%d].temporal.%s=%q invalid date", i, name, val)
						}
					}
				}
				return true, ""
			},
		},
		{
			Section: "4.4.1", Name: "x-crit-false-only-when-auto-provider",
			Requirement: "existing_deployments_remain_vulnerable=false ONLY when fix_propagation=automatic AND shared_responsibility=provider_only",
			Check: func(rec *CVERecord) (bool, string) {
				vvd := findADP(rec)
				if vvd == nil {
					return true, ""
				}
				for i, cr := range vvd.XCrit {
					if !cr.ExistingDeploymentsRemainVulnerable {
						if cr.FixPropagation != "automatic" || cr.SharedResponsibility != "provider_only" {
							return false, fmt.Sprintf("x_crit[%d] vulnerable=false but propagation=%s responsibility=%s",
								i, cr.FixPropagation, cr.SharedResponsibility)
						}
					}
				}
				return true, ""
			},
		},
		{
			Section: "4.4.2", Name: "x-crit-no-fix-no-date",
			Requirement: "fix_propagation=no_fix_available -> provider_fix_date MUST be absent",
			Check: func(rec *CVERecord) (bool, string) {
				vvd := findADP(rec)
				if vvd == nil {
					return true, ""
				}
				for i, cr := range vvd.XCrit {
					if cr.FixPropagation == "no_fix_available" {
						if cr.Temporal.ProviderFixDate != nil && *cr.Temporal.ProviderFixDate != "" {
							return false, fmt.Sprintf("x_crit[%d] no_fix_available but provider_fix_date=%s", i, *cr.Temporal.ProviderFixDate)
						}
					}
				}
				return true, ""
			},
		},
		{
			Section: "4.4.3", Name: "x-crit-sequence-contiguous",
			Requirement: "remediation_actions sequence MUST be unique and contiguous starting at 1",
			Check: func(rec *CVERecord) (bool, string) {
				vvd := findADP(rec)
				if vvd == nil {
					return true, ""
				}
				for i, cr := range vvd.XCrit {
					if len(cr.RemediationActions) == 0 {
						continue
					}
					seen := make(map[int]bool)
					for _, a := range cr.RemediationActions {
						if seen[a.Sequence] {
							return false, fmt.Sprintf("x_crit[%d] duplicate sequence %d", i, a.Sequence)
						}
						seen[a.Sequence] = true
					}
					for j := 1; j <= len(cr.RemediationActions); j++ {
						if !seen[j] {
							return false, fmt.Sprintf("x_crit[%d] missing sequence %d", i, j)
						}
					}
				}
				return true, ""
			},
		},

		// --- Dictionary-based validation ---
		{
			Section: "12.3", Name: "x-crit-dictionary-lookup",
			Requirement: "Each x_crit (provider, service, resource_type) MUST resolve to a dictionary entry",
			Check: func(rec *CVERecord) (bool, string) {
				vvd := findADP(rec)
				if vvd == nil {
					return true, ""
				}
				for i, cr := range vvd.XCrit {
					key := dictKey(cr.Provider, cr.Service, cr.ResourceType)
					if _, ok := dict[key]; !ok {
						return false, fmt.Sprintf("x_crit[%d] (%s/%s/%s) not found in dictionary", i, cr.Provider, cr.Service, cr.ResourceType)
					}
				}
				return true, ""
			},
		},
		{
			Section: "12.3", Name: "x-crit-template-matches-dictionary",
			Requirement: "Each x_crit template MUST match the dictionary entry template",
			Check: func(rec *CVERecord) (bool, string) {
				vvd := findADP(rec)
				if vvd == nil {
					return true, ""
				}
				for i, cr := range vvd.XCrit {
					key := dictKey(cr.Provider, cr.Service, cr.ResourceType)
					de, ok := dict[key]
					if !ok {
						continue // dictionary-lookup rule handles this
					}
					if cr.Template != de.Template {
						return false, fmt.Sprintf("x_crit[%d] template=%q != dictionary=%q", i, cr.Template, de.Template)
					}
				}
				return true, ""
			},
		},
		{
			Section: "12.3", Name: "x-crit-region-behavior-consistent",
			Requirement: "global-only dictionary entries MUST NOT have a named-variable {region} slot",
			Check: func(rec *CVERecord) (bool, string) {
				vvd := findADP(rec)
				if vvd == nil {
					return true, ""
				}
				for i, cr := range vvd.XCrit {
					key := dictKey(cr.Provider, cr.Service, cr.ResourceType)
					de, ok := dict[key]
					if !ok {
						continue
					}
					if de.RegionBehavior == "global-only" {
						// Template must not contain a bare {region} (named variable)
						// but may contain {region=value} (hardcoded) or no region at all
						if strings.Contains(cr.Template, "{region}") {
							return false, fmt.Sprintf("x_crit[%d] global-only resource has named-variable {region} slot", i)
						}
					}
				}
				return true, ""
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Console output
// ---------------------------------------------------------------------------

func printConsole(records []CVERecord, rules []Rule, results map[string]*RuleResult, failures []Failure, totalPass, totalFail int, dictSize int) {
	fmt.Println("=== CVEListv5 + CRIT Conformance Test Results ===")
	fmt.Printf("CVE Files: %d | Rules: %d | Dictionary entries: %d\n", len(records), len(rules), dictSize)
	fmt.Println(strings.Repeat("-", 120))
	fmt.Printf("%-6s | %-6s | %-42s | %-18s | %s\n",
		"RESULT", "SEC", "RULE", "CVE-ID", "DETAIL")
	fmt.Println(strings.Repeat("-", 120))

	for _, f := range failures {
		detail := f.Detail
		if len(detail) > 50 {
			detail = detail[:47] + "..."
		}
		fmt.Printf("%-6s | %-6s | %-42s | %-18s | %s\n",
			"FAIL", f.Section, f.RuleName, f.CVEID, detail)
	}

	fmt.Println(strings.Repeat("=", 120))
	fmt.Println("\n=== Summary Report ===")
	fmt.Printf("\n%-6s | %-6s | %-42s | %6s | %6s | %s\n",
		"STATUS", "SEC", "RULE", "PASS", "FAIL", "REQUIREMENT")
	fmt.Println(strings.Repeat("-", 120))

	for _, rule := range rules {
		r := results[rule.Name]
		status := "PASS"
		if r.Fail > 0 {
			status = "FAIL"
		}
		req := rule.Requirement
		if len(req) > 40 {
			req = req[:37] + "..."
		}
		fmt.Printf("%-6s | %-6s | %-42s | %6d | %6d | %s\n",
			status, rule.Section, rule.Name, r.Pass, r.Fail, req)
	}

	fmt.Println(strings.Repeat("-", 120))
	fmt.Printf("\nTOTAL: %d passed, %d failed across %d files x %d rules = %d checks\n",
		totalPass, totalFail, len(records), len(rules), totalPass+totalFail)
}

// ---------------------------------------------------------------------------
// Markdown report
// ---------------------------------------------------------------------------

func writeMarkdownReport(path string, records []CVERecord, rules []Rule, results map[string]*RuleResult, failures []Failure, totalPass, totalFail int, now time.Time) error {
	var b strings.Builder
	totalChecks := totalPass + totalFail
	verdict := "PASS"
	if totalFail > 0 {
		verdict = "FAIL"
	}

	b.WriteString("# CVEListv5 + CRIT Conformance Report\n\n")
	fmt.Fprintf(&b, "**Date:** %s  \n", now.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(&b, "**Verdict:** %s  \n", verdict)
	fmt.Fprintf(&b, "**CVE Files:** %d | **Rules:** %d | **Checks:** %d  \n", len(records), len(rules), totalChecks)
	fmt.Fprintf(&b, "**Passed:** %d | **Failed:** %d  \n\n", totalPass, totalFail)

	// Pie chart
	b.WriteString("## Overall Results\n\n")
	b.WriteString("```mermaid\npie title Check Results\n")
	fmt.Fprintf(&b, "    \"Pass\" : %d\n", totalPass)
	fmt.Fprintf(&b, "    \"Fail\" : %d\n", totalFail)
	b.WriteString("```\n\n")

	// Per-year breakdown
	yearFiles := make(map[string]int)
	yearFail := make(map[string]int)
	for _, rec := range records {
		year := "unknown"
		if len(rec.CVEMetadata.CVEID) >= 8 {
			year = rec.CVEMetadata.CVEID[4:8]
		}
		yearFiles[year]++
	}
	for _, f := range failures {
		year := "unknown"
		if len(f.CVEID) >= 8 {
			year = f.CVEID[4:8]
		}
		yearFail[year]++
	}
	years := make([]string, 0, len(yearFiles))
	for y := range yearFiles {
		years = append(years, y)
	}
	sort.Strings(years)

	b.WriteString("## Results by CVE Year\n\n")
	b.WriteString("| Year | Files | Checks | Passed | Failed | Rate |\n")
	b.WriteString("|------|------:|-------:|-------:|-------:|-----:|\n")
	for _, y := range years {
		total := yearFiles[y] * len(rules)
		pass := total - yearFail[y]
		rate := 100.0
		if total > 0 {
			rate = float64(pass) / float64(total) * 100
		}
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %.1f%% |\n",
			y, yearFiles[y], total, pass, yearFail[y], rate)
	}
	b.WriteString("\n")

	// Rule results table
	b.WriteString("## Rule Results\n\n")
	b.WriteString("| Status | Section | Rule | Passed | Failed | Requirement |\n")
	b.WriteString("|:------:|:-------:|------|-------:|-------:|-------------|\n")
	for _, rule := range rules {
		r := results[rule.Name]
		status := "PASS"
		if r.Fail > 0 {
			status = "FAIL"
		}
		req := escapeMarkdown(rule.Requirement)
		fmt.Fprintf(&b, "| %s | %s | `%s` | %d | %d | %s |\n",
			status, rule.Section, rule.Name, r.Pass, r.Fail, req)
	}
	b.WriteString("\n")

	// Failures
	if len(failures) > 0 {
		b.WriteString("## Failures\n\n")
		failsByRule := make(map[string][]Failure)
		for _, f := range failures {
			failsByRule[f.RuleName] = append(failsByRule[f.RuleName], f)
		}
		ruleNames := make([]string, 0, len(failsByRule))
		for k := range failsByRule {
			ruleNames = append(ruleNames, k)
		}
		sort.Strings(ruleNames)

		for _, ruleName := range ruleNames {
			ff := failsByRule[ruleName]
			fmt.Fprintf(&b, "### `%s` (%s) &mdash; %d failures\n\n", ruleName, ff[0].Section, len(ff))
			b.WriteString("| CVE-ID | File | Detail |\n")
			b.WriteString("|--------|------|--------|\n")
			cap := 25
			for i, f := range ff {
				if i >= cap {
					fmt.Fprintf(&b, "| ... | ... | *%d more omitted* |\n", len(ff)-cap)
					break
				}
				detail := escapeMarkdown(f.Detail)
				if len(detail) > 80 {
					detail = detail[:77] + "..."
				}
				fmt.Fprintf(&b, "| %s | %s | %s |\n", f.CVEID, filepath.Base(f.FilePath), detail)
			}
			b.WriteString("\n")
		}
	} else {
		b.WriteString("## Failures\n\nNone.\n\n")
	}

	b.WriteString("---\n\n")
	b.WriteString("*Generated by [crit-validate](https://github.com/Vulnetix/ietf-crit-spec/cmd/crit-validate)*\n")

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("creating report directory: %w", err)
	}
	return os.WriteFile(path, []byte(b.String()), 0644)
}

func escapeMarkdown(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func runConvert(args []string) {
	fs := flag.NewFlagSet("convert", flag.ExitOnError)
	fromJSON := fs.String("from-json", "", "CRIT sample JSON file → vector string")
	fromVector := fs.String("from-vector", "", "CRIT vector string → expanded JSON")
	fs.Parse(args)

	switch {
	case *fromJSON != "":
		data, err := os.ReadFile(*fromJSON)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", *fromJSON, err)
			os.Exit(1)
		}
		var rec CRITRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing JSON: %v\n", err)
			os.Exit(1)
		}
		pubEpoch := dateToEpoch(rec.Temporal.VulnPublishedDate)
		var saEpoch int64
		if rec.Temporal.ServiceAvailableDate != nil {
			saEpoch = dateToEpoch(*rec.Temporal.ServiceAvailableDate)
		}
		v := critspec.CRITVector{
			CRITVersion:    "0.2.0",
			Provider:       rec.Provider,
			VEXStatus:      rec.VexStatus,
			FixPropagation: rec.FixPropagation,
			SharedResp:     rec.SharedResponsibility,
			Lifecycle:      rec.ResourceLifecycle,
			ExistingVuln:   rec.ExistingDeploymentsRemainVulnerable,
			VulnPublished:  pubEpoch,
			ServiceAvail:   saEpoch,
			VulnID:         rec.VulnID,
			Service:        rec.Service,
			ResourceType:   rec.ResourceType,
		}
		vec, err := critspec.ComputeVector(v)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error computing vector: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(vec)

	case *fromVector != "":
		parsed, warnings, err := critspec.ParseVector(*fromVector)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing vector: %v\n", err)
			os.Exit(1)
		}
		for _, w := range warnings {
			fmt.Fprintf(os.Stderr, "warning: %s\n", w.Message)
		}
		out, _ := json.MarshalIndent(parsed, "", "  ")
		fmt.Println(string(out))

	default:
		fmt.Fprintln(os.Stderr, "Error: specify --from-json or --from-vector")
		fs.Usage()
		os.Exit(1)
	}
}

func dateToEpoch(date string) int64 {
	t, err := time.Parse("2006-01-02", date)
	if err != nil {
		return 0
	}
	return t.Unix()
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "convert" {
		runConvert(os.Args[2:])
		return
	}

	dataDir := flag.String("data", "", "Directory containing CVE JSON files (required)")
	dictPath := flag.String("dictionary", "", "Custom dictionary file or directory of dictionary JSON files")
	reportDir := flag.String("report", "", "Write dated Markdown report to this directory")
	adpName := flag.String("adp-short-name", "VVD", "ADP container shortName to validate (default: VVD)")
	noFail := flag.Bool("no-fail", false, "Exit 0 even when tests fail")
	quiet := flag.Bool("quiet", false, "Suppress console output")
	flag.Parse()

	adpShortName = *adpName

	if *dataDir == "" {
		fmt.Fprintln(os.Stderr, "Error: --data flag is required")
		flag.Usage()
		os.Exit(1)
	}

	if info, err := os.Stat(*dataDir); err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "Error: --data %q is not a valid directory\n", *dataDir)
		os.Exit(1)
	}

	// Load built-in dictionaries from embedded filesystem
	dict, err := loadBuiltinDictionaries()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading built-in dictionaries: %v\n", err)
		os.Exit(1)
	}
	if !*quiet {
		fmt.Printf("Loaded %d built-in dictionary entries\n", len(dict))
	}

	// If custom dictionaries provided, validate and merge
	if *dictPath != "" {
		sch, err := compileDictionarySchema()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error compiling dictionary schema: %v\n", err)
			os.Exit(1)
		}
		external, err := loadExternalDictionaries(*dictPath, sch)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading custom dictionaries: %v\n", err)
			os.Exit(1)
		}
		before := len(dict)
		dict = mergeDictionaries(dict, external)
		added := len(dict) - before
		if !*quiet {
			fmt.Printf("Loaded %d custom dictionary entries (%d new)\n", len(external), added)
		}
	}

	records, err := loadCVERecords(*dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading CVE records: %v\n", err)
		os.Exit(1)
	}
	if len(records) == 0 {
		fmt.Fprintf(os.Stderr, "Error: no JSON files found in %s\n", *dataDir)
		os.Exit(1)
	}

	rules := defineRules(dict)
	results := make(map[string]*RuleResult)
	for _, r := range rules {
		results[r.Name] = &RuleResult{}
	}

	var failures []Failure
	totalPass, totalFail := 0, 0

	for i := range records {
		rec := &records[i]
		for _, rule := range rules {
			pass, detail := rule.Check(rec)
			result := results[rule.Name]
			if pass {
				result.Pass++
				totalPass++
			} else {
				result.Fail++
				totalFail++
				failures = append(failures, Failure{
					RuleName: rule.Name, Section: rule.Section,
					CVEID: rec.CVEMetadata.CVEID, Detail: detail,
					FilePath: rec.FilePath,
				})
			}
		}
	}

	if !*quiet {
		printConsole(records, rules, results, failures, totalPass, totalFail, len(dict))
	}

	now := time.Now().UTC()
	if *reportDir != "" {
		reportFile := filepath.Join(*reportDir, now.Format("20060102")+"-cve-crit-conformance.md")
		if err := writeMarkdownReport(reportFile, records, rules, results, failures, totalPass, totalFail, now); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing report: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\nReport written to %s\n", reportFile)
	}

	if totalFail > 0 && !*noFail {
		os.Exit(1)
	}
}
