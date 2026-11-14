package critspec

import (
	"strings"
	"testing"
)

func TestValidVulnID(t *testing.T) {
	for _, id := range []string{"CVE-2024-6387", "GCVE-110-CLOUD-2008-0001", "GHSA-xxxx-yyyy-zzzz", "a.b_c-1"} {
		if !ValidVulnID(id) {
			t.Errorf("ValidVulnID(%q) = false, want true", id)
		}
	}
	for _, id := range []string{"", "GHSA:1", "a/b", "x#y", "has space"} {
		if ValidVulnID(id) {
			t.Errorf("ValidVulnID(%q) = true, want false", id)
		}
	}
}

func TestCheckScheme(t *testing.T) {
	ok := []struct{ scheme, id string }{
		{"", "anything"},
		{"cve", "CVE-2024-6387"},
		{"gcve", "GCVE-110-CLOUD-2008-0001"},
		{"ghsa", "GHSA-xxxx-yyyy-zzzz"},
	}
	for _, c := range ok {
		if err := CheckScheme(c.scheme, c.id); err != nil {
			t.Errorf("CheckScheme(%q, %q) = %v, want nil", c.scheme, c.id, err)
		}
	}
	bad := []struct{ scheme, id string }{
		{"CVE", "CVE-2024-6387"},
		{"cve", "GCVE-1-2024-0001"},
		{"gcve", "CVE-2024-6387"},
	}
	for _, c := range bad {
		if err := CheckScheme(c.scheme, c.id); err == nil {
			t.Errorf("CheckScheme(%q, %q) = nil, want error", c.scheme, c.id)
		}
	}
}

func TestCheckAliases(t *testing.T) {
	if err := CheckAliases([]VulnAlias{{"gcve", "GCVE-1-2024-0001"}, {"osv", "OSV-1"}}, "CVE-2024-6387"); err != nil {
		t.Errorf("valid aliases: %v", err)
	}
	cases := map[string][]VulnAlias{
		"bad scheme": {{"Bad", "x"}},
		"empty id":   {{"cve", ""}},
		"repeats id": {{"cve", "CVE-2024-6387"}},
		"duplicate":  {{"osv", "OSV-1"}, {"osv", "OSV-1"}},
	}
	for name, a := range cases {
		if err := CheckAliases(a, "CVE-2024-6387"); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestVectorRejectsUnsafeVulnID(t *testing.T) {
	v := CRITVector{
		CRITVersion: "0.3.0", Provider: "aws", VEXStatus: "fixed",
		FixPropagation: "automatic", SharedResp: "provider_only", Lifecycle: "stateless",
		VulnID: "a/b", Service: "ec2", ResourceType: "instance",
	}
	if _, err := ComputeVector(v); err == nil {
		t.Error("ComputeVector accepted vuln_id with '/'")
	}
	if _, _, err := ParseVector("CRITv0.3.0/CP:AW/VS:FX/FP:AU/SR:PO/RL:SL/EV:F/PP:0/SA:0#a b:ec2:instance"); err == nil {
		t.Error("ParseVector accepted vuln_id with a space")
	}
}

func TestValidGCVEID(t *testing.T) {
	// GCVE-1-2025-0018 is the GNA 1 example in GCVE-BCP-05; GNA 110 uses a
	// family segment; GNA 65535 is the GCVE-BCP-04 test GNA.
	for _, id := range []string{
		"GCVE-1-2025-0018",
		"GCVE-110-CLOUD-2008-0001",
		"GCVE-110-MAGEIA-2024-250",
		"GCVE-65535-RHSA-2024:1234",
		"GCVE-65535-a/b#c%d",
	} {
		if !ValidGCVEID(id) {
			t.Errorf("ValidGCVEID(%q) = false, want true", id)
		}
	}
	long := "GCVE-1-" + strings.Repeat("A", GCVEIDMaxLen-len("GCVE-1-")+1)
	for _, id := range []string{
		"", "GCVE-", "GCVE-1-", "GCVE-ABC-2024-0001", "GCVE--2024-0001",
		"gcve-1-2025-0018", "GCVE-1-has space", "GCVE-1-x!y", "CVE-2024-6387", long,
	} {
		if ValidGCVEID(id) {
			t.Errorf("ValidGCVEID(%.40q) = true, want false", id)
		}
	}
	if gna, ok := GNAID("GCVE-110-CLOUD-2008-0001"); !ok || gna != "110" {
		t.Errorf("GNAID = %q, %v; want 110, true", gna, ok)
	}
}

func TestCheckSchemeGCVE(t *testing.T) {
	// The vector-unsafe GCVE id is a valid GCVE id, so CheckScheme accepts it;
	// it is ValidVulnID that keeps it out of vuln_id.
	if err := CheckScheme("gcve", "GCVE-65535-RHSA-2024:1234"); err != nil {
		t.Errorf("CheckScheme accepted shape: %v", err)
	}
	if ValidVulnID("GCVE-65535-RHSA-2024:1234") {
		t.Error("vuln_id with ':' must not be vector-safe")
	}
	for _, id := range []string{"GCVE-ABC-2024-0001", "GCVE-1", "GCVE-1-x!y"} {
		if err := CheckScheme("gcve", id); err == nil {
			t.Errorf("CheckScheme(gcve, %q) = nil, want error", id)
		}
	}
	// Unknown schemes are opaque tokens.
	if err := CheckScheme("rhsa", "RHSA-2024_1234"); err != nil {
		t.Errorf("unknown scheme rejected: %v", err)
	}
}

func TestCheckIssuer(t *testing.T) {
	ok := []struct{ scheme, issuer, id string }{
		{"gcve", "GNA-110", "GCVE-110-CLOUD-2008-0001"},
		{"gcve", "", "GCVE-110-CLOUD-2008-0001"},
		{"gcve", "CIRCL", "GCVE-1-2025-0018"},
		{"cve", "GNA-1", "CVE-2024-6387"},
	}
	for _, c := range ok {
		if err := CheckIssuer(c.scheme, c.issuer, c.id); err != nil {
			t.Errorf("CheckIssuer(%q, %q, %q) = %v, want nil", c.scheme, c.issuer, c.id, err)
		}
	}
	if err := CheckIssuer("gcve", "GNA-1", "GCVE-110-CLOUD-2008-0001"); err == nil {
		t.Error("CheckIssuer accepted a GNA that differs from vuln_id's")
	}
	if IssuerRecommended("gcve", "CIRCL") {
		t.Error("IssuerRecommended(gcve, CIRCL) = true, want false")
	}
	if !IssuerRecommended("gcve", "GNA-1") || !IssuerRecommended("cve", "cve.org") {
		t.Error("IssuerRecommended rejected a recommended form")
	}
}

func TestCheckAliasesSchemeSyntax(t *testing.T) {
	// Alias ids may use characters the vector string cannot carry.
	good := []VulnAlias{{"gcve", "GCVE-65535-RHSA-2024:1234"}, {"rhsa", "RHSA-2024:1234"}}
	if err := CheckAliases(good, "CVE-2024-6387"); err != nil {
		t.Errorf("valid aliases rejected: %v", err)
	}
	for name, a := range map[string][]VulnAlias{
		"gcve non-numeric GNA": {{"gcve", "GCVE-ABC-2024-0001"}},
		"cve bad shape":        {{"cve", "CVE-24-1"}},
	} {
		if err := CheckAliases(a, "CVE-2024-6387"); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}
