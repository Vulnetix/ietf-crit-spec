package critspec

import (
	"fmt"
	"regexp"
	"strings"
)

// VulnIDPattern is the character set a vuln_id may use. It is limited to the
// characters the vector string qualifier section can carry unambiguously
// (':' and '#' are delimiters, '/' separates metrics). The vector grammar has
// no escape or percent-encoding mechanism.
const VulnIDPattern = `^[A-Za-z0-9._-]+$`

// SchemePattern is the token syntax for scheme and aliases[].scheme. The
// scheme is an open token; well-known values are listed in the draft's
// "Well-Known Identifier Schemes" table.
const SchemePattern = `^[a-z][a-z0-9_-]*$`

// CVEIDPattern is the syntax of an identifier in the cve scheme.
const CVEIDPattern = `^CVE-[0-9]{4}-[0-9]{4,}$`

// GCVEIDPattern is the syntax of an identifier in the gcve scheme, as defined
// by GCVE-BCP-04 (https://gcve.eu/bcp/gcve-bcp-04/). It admits printable ASCII
// from U+0022 to U+007E after the GNA ID, which is wider than VulnIDPattern.
const GCVEIDPattern = `^GCVE-[0-9]+-[\x22-\x7E]+$`

// GCVEIDMaxLen is the GCVE-BCP-04 maximum length of a GCVE identifier.
const GCVEIDMaxLen = 255

var (
	vulnIDRe    = regexp.MustCompile(VulnIDPattern)
	schemeRe    = regexp.MustCompile(SchemePattern)
	cveIDRe     = regexp.MustCompile(CVEIDPattern)
	gcveIDRe    = regexp.MustCompile(GCVEIDPattern)
	gnaIssuerRe = regexp.MustCompile(`^GNA-([0-9]+)$`)
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

// ValidGCVEID reports whether id is a GCVE identifier per GCVE-BCP-04: it
// matches GCVEIDPattern and is at most GCVEIDMaxLen characters long.
func ValidGCVEID(id string) bool {
	return len(id) <= GCVEIDMaxLen && gcveIDRe.MatchString(id)
}

// GNAID returns the GNA ID that a GCVE identifier carries after "GCVE-", and
// false if id is not a valid GCVE identifier.
func GNAID(id string) (string, bool) {
	if !ValidGCVEID(id) {
		return "", false
	}
	rest := strings.TrimPrefix(id, "GCVE-")
	return rest[:strings.IndexByte(rest, '-')], true
}

// checkSchemeSyntax applies the normative syntax of the cve and gcve schemes
// to an identifier. Other schemes, well-known or not, impose no syntax that a
// validator enforces.
func checkSchemeSyntax(scheme, id string) error {
	switch scheme {
	case "cve":
		if !cveIDRe.MatchString(id) {
			return fmt.Errorf("scheme cve but %q does not match %s", id, CVEIDPattern)
		}
	case "gcve":
		if !ValidGCVEID(id) {
			return fmt.Errorf("scheme gcve but %q does not match the GCVE-BCP-04 pattern %s (max %d characters)", id, GCVEIDPattern, GCVEIDMaxLen)
		}
	}
	return nil
}

// CheckScheme validates an optional scheme against vuln_id. An empty scheme
// is valid, and an unrecognised scheme is accepted as an opaque token. For the
// cve and gcve schemes, vuln_id must match the scheme's syntax. vuln_id must
// also satisfy ValidVulnID, which is checked separately.
func CheckScheme(scheme, vulnID string) error {
	if scheme == "" {
		return nil
	}
	if !ValidScheme(scheme) {
		return fmt.Errorf("scheme %q invalid", scheme)
	}
	return checkSchemeSyntax(scheme, vulnID)
}

// CheckIssuer validates issuer against scheme and vuln_id. issuer is free
// text in general; for the gcve scheme, an issuer of the form GNA-<n> must
// name the GNA ID that vuln_id carries.
func CheckIssuer(scheme, issuer, vulnID string) error {
	if scheme != "gcve" || issuer == "" {
		return nil
	}
	m := gnaIssuerRe.FindStringSubmatch(issuer)
	if m == nil {
		return nil
	}
	if gna, ok := GNAID(vulnID); ok && gna != m[1] {
		return fmt.Errorf("issuer %q does not match GNA ID %s of vuln_id %q", issuer, gna, vulnID)
	}
	return nil
}

// IssuerRecommended reports whether issuer follows the recommended form for
// scheme (GNA-<n> for gcve). An absent issuer, or any other scheme, is
// accepted. It backs a SHOULD-level check.
func IssuerRecommended(scheme, issuer string) bool {
	if scheme != "gcve" || issuer == "" {
		return true
	}
	return gnaIssuerRe.MatchString(issuer)
}

// CheckAliases validates aliases: each entry needs a valid scheme and a
// non-empty id, entries must be unique, and none may repeat vuln_id. Alias
// ids are not limited to the vector character set; only the cve and gcve
// schemes impose a syntax on them.
func CheckAliases(aliases []VulnAlias, vulnID string) error {
	seen := make(map[VulnAlias]bool, len(aliases))
	for i, a := range aliases {
		if !ValidScheme(a.Scheme) || a.ID == "" {
			return fmt.Errorf("aliases[%d] malformed", i)
		}
		if err := checkSchemeSyntax(a.Scheme, a.ID); err != nil {
			return fmt.Errorf("aliases[%d]: %v", i, err)
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
