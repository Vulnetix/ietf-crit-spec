package critspec

import "testing"

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
