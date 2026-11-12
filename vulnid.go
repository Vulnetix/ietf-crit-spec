package critspec

import (
	"fmt"
	"regexp"
	"strings"
)

// VulnIDPattern is the character set a vuln_id may use. It is limited to the
// characters the vector string qualifier section can carry unambiguously
// (':' and '#' are delimiters, '/' separates metrics).
const VulnIDPattern = `^[A-Za-z0-9._-]+$`

// SchemePattern is the token syntax for scheme and aliases[].scheme.
const SchemePattern = `^[a-z][a-z0-9_-]*$`

var (
	vulnIDRe = regexp.MustCompile(VulnIDPattern)
	schemeRe = regexp.MustCompile(SchemePattern)
	cveIDRe  = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
)

// VulnAlias is another identifier for the vulnerability a CRIT record
// describes. It is not part of the natural key.
type VulnAlias struct {
	Scheme string `json:"scheme"`
	ID     string `json:"id"`
}

// ValidVulnID reports whether id is a non-empty vuln_id that the vector
// string can carry.
func ValidVulnID(id string) bool { return vulnIDRe.MatchString(id) }

// ValidScheme reports whether s is a syntactically valid scheme token.
func ValidScheme(s string) bool { return schemeRe.MatchString(s) }

// CheckScheme validates an optional scheme against vuln_id. An empty scheme
// is valid. For the cve and gcve schemes, vuln_id must have the matching shape.
func CheckScheme(scheme, vulnID string) error {
	if scheme == "" {
		return nil
	}
	if !ValidScheme(scheme) {
		return fmt.Errorf("scheme %q invalid", scheme)
	}
	switch scheme {
	case "cve":
		if !cveIDRe.MatchString(vulnID) {
			return fmt.Errorf("scheme cve but vuln_id %q is not CVE-YYYY-N{4,}", vulnID)
		}
	case "gcve":
		if !strings.HasPrefix(vulnID, "GCVE-") {
			return fmt.Errorf("scheme gcve but vuln_id %q does not start with GCVE-", vulnID)
		}
	}
	return nil
}

// CheckAliases validates aliases: each entry needs a valid scheme and a
// non-empty id, entries must be unique, and none may repeat vuln_id.
func CheckAliases(aliases []VulnAlias, vulnID string) error {
	seen := make(map[VulnAlias]bool, len(aliases))
	for i, a := range aliases {
		if !ValidScheme(a.Scheme) || a.ID == "" {
			return fmt.Errorf("aliases[%d] malformed", i)
		}
		if a.ID == vulnID {
			return fmt.Errorf("aliases[%d] repeats vuln_id", i)
		}
		if seen[a] {
			return fmt.Errorf("aliases[%d] duplicates an earlier entry", i)
		}
		seen[a] = true
	}
	return nil
}
