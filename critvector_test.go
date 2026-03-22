package critspec

import (
	"strings"
	"testing"
)

func TestComputeVector(t *testing.T) {
	v := CRITVector{
		CRITVersion:    "0.2.0",
		Provider:       "aws",
		VEXStatus:      "fixed",
		FixPropagation: "rebuild_and_redeploy",
		SharedResp:     "customer_action_required",
		Lifecycle:      "stateful_customer",
		ExistingVuln:   true,
		VulnPublished:  1719792000,
		ServiceAvail:   1514764800,
		VulnID:         "CVE-2024-6387",
		Service:        "ec2",
		ResourceType:   "instance",
	}
	got, err := ComputeVector(v)
	if err != nil {
		t.Fatalf("ComputeVector: %v", err)
	}
	want := "CRITv0.2.0/CP:AW/VS:FX/FP:RR/SR:CA/RL:SC/EV:T/PP:1719792000/SA:1514764800#CVE-2024-6387:ec2:instance"
	if got != want {
		t.Errorf("ComputeVector:\n  got:  %s\n  want: %s", got, want)
	}
}

func TestComputeVectorAllProviders(t *testing.T) {
	cases := []struct {
		provider string
		code     string
	}{
		{"aws", "AW"}, {"azure", "MA"}, {"gcp", "GC"},
		{"cloudflare", "CF"}, {"oracle", "OC"},
	}
	for _, tc := range cases {
		v := CRITVector{
			CRITVersion: "0.2.0", Provider: tc.provider, VEXStatus: "affected",
			FixPropagation: "automatic", SharedResp: "provider_only",
			Lifecycle: "ephemeral", VulnPublished: 1000000000, ServiceAvail: 900000000,
			VulnID: "CVE-2024-0001", Service: "svc", ResourceType: "rt",
		}
		got, err := ComputeVector(v)
		if err != nil {
			t.Errorf("provider %q: %v", tc.provider, err)
			continue
		}
		if !strings.Contains(got, "CP:"+tc.code) {
			t.Errorf("provider %q: expected CP:%s in %s", tc.provider, tc.code, got)
		}
	}
}

func TestComputeVectorErrors(t *testing.T) {
	base := CRITVector{
		CRITVersion: "0.2.0", Provider: "aws", VEXStatus: "fixed",
		FixPropagation: "automatic", SharedResp: "shared", Lifecycle: "ephemeral",
		VulnPublished: 1000, ServiceAvail: 900,
		VulnID: "CVE-2024-0001", Service: "svc", ResourceType: "rt",
	}
	tests := []struct {
		name   string
		mutate func(*CRITVector)
	}{
		{"unknown provider", func(v *CRITVector) { v.Provider = "unknown" }},
		{"unknown vex_status", func(v *CRITVector) { v.VEXStatus = "bad" }},
		{"unknown fix_propagation", func(v *CRITVector) { v.FixPropagation = "bad" }},
		{"unknown shared_responsibility", func(v *CRITVector) { v.SharedResp = "bad" }},
		{"unknown lifecycle", func(v *CRITVector) { v.Lifecycle = "bad" }},
		{"empty vuln_id", func(v *CRITVector) { v.VulnID = "" }},
		{"empty service", func(v *CRITVector) { v.Service = "" }},
		{"empty resource_type", func(v *CRITVector) { v.ResourceType = "" }},
		{"empty version", func(v *CRITVector) { v.CRITVersion = "" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := base
			tc.mutate(&v)
			_, err := ComputeVector(v)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestParseVectorRoundTrip(t *testing.T) {
	input := "CRITv0.2.0/CP:AW/VS:FX/FP:RR/SR:CA/RL:SC/EV:T/PP:1719792000/SA:1514764800#CVE-2024-6387:ec2:instance"
	parsed, warnings, err := ParseVector(input)
	if err != nil {
		t.Fatalf("ParseVector: %v", err)
	}
	if len(warnings) > 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	recomputed, err := ComputeVector(*parsed)
	if err != nil {
		t.Fatalf("ComputeVector after parse: %v", err)
	}
	if recomputed != input {
		t.Errorf("round-trip mismatch:\n  got:  %s\n  want: %s", recomputed, input)
	}
}

func TestParseVectorFields(t *testing.T) {
	input := "CRITv0.2.0/CP:MA/VS:AF/FP:CC/SR:SH/RL:CF/EV:F/PP:1719792000/SA:1514764800#CVE-2024-37085:azure_vmware_solution:privateClouds"
	v, _, err := ParseVector(input)
	if err != nil {
		t.Fatalf("ParseVector: %v", err)
	}
	if v.CRITVersion != "0.2.0" {
		t.Errorf("CRITVersion = %q, want 0.2.0", v.CRITVersion)
	}
	if v.Provider != "azure" {
		t.Errorf("Provider = %q, want azure", v.Provider)
	}
	if v.VEXStatus != "affected" {
		t.Errorf("VEXStatus = %q, want affected", v.VEXStatus)
	}
	if v.FixPropagation != "config_change" {
		t.Errorf("FixPropagation = %q, want config_change", v.FixPropagation)
	}
	if v.SharedResp != "shared" {
		t.Errorf("SharedResp = %q, want shared", v.SharedResp)
	}
	if v.Lifecycle != "config_only" {
		t.Errorf("Lifecycle = %q, want config_only", v.Lifecycle)
	}
	if v.ExistingVuln != false {
		t.Errorf("ExistingVuln = %v, want false", v.ExistingVuln)
	}
	if v.VulnPublished != 1719792000 {
		t.Errorf("VulnPublished = %d, want 1719792000", v.VulnPublished)
	}
	if v.ServiceAvail != 1514764800 {
		t.Errorf("ServiceAvail = %d, want 1514764800", v.ServiceAvail)
	}
	if v.VulnID != "CVE-2024-37085" {
		t.Errorf("VulnID = %q, want CVE-2024-37085", v.VulnID)
	}
	if v.Service != "azure_vmware_solution" {
		t.Errorf("Service = %q, want azure_vmware_solution", v.Service)
	}
	if v.ResourceType != "privateClouds" {
		t.Errorf("ResourceType = %q, want privateClouds", v.ResourceType)
	}
}

func TestParseVectorUnknownMetrics(t *testing.T) {
	// Append an unknown metric "XX:foo" after the registered set.
	input := "CRITv0.2.0/CP:AW/VS:FX/FP:AU/SR:PO/RL:EP/EV:F/PP:1000/SA:900/XX:foo#CVE-2024-0001:svc:rt"
	v, warnings, err := ParseVector(input)
	if err != nil {
		t.Fatalf("ParseVector should not error on unknown metrics: %v", err)
	}
	if len(warnings) == 0 {
		t.Error("expected warnings for unknown metric, got none")
	}
	if v.UnknownMetrics["XX"] != "foo" {
		t.Errorf("UnknownMetrics[XX] = %q, want foo", v.UnknownMetrics["XX"])
	}
}

func TestParseVectorErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"no hash", "CRITv0.2.0/CP:AW/VS:FX/FP:AU/SR:PO/RL:EP/EV:F/PP:1000/SA:900"},
		{"bad prefix", "FOOv0.2.0/CP:AW/VS:FX/FP:AU/SR:PO/RL:EP/EV:F/PP:1000/SA:900#CVE:svc:rt"},
		{"missing CP", "CRITv0.2.0/VS:FX/FP:AU/SR:PO/RL:EP/EV:F/PP:1000/SA:900#CVE:svc:rt"},
		{"wrong order", "CRITv0.2.0/VS:FX/CP:AW/FP:AU/SR:PO/RL:EP/EV:F/PP:1000/SA:900#CVE:svc:rt"},
		{"bad qualifier count", "CRITv0.2.0/CP:AW/VS:FX/FP:AU/SR:PO/RL:EP/EV:F/PP:1000/SA:900#CVE"},
		{"unknown CP code", "CRITv0.2.0/CP:ZZ/VS:FX/FP:AU/SR:PO/RL:EP/EV:F/PP:1000/SA:900#CVE:svc:rt"},
		{"non-integer PP", "CRITv0.2.0/CP:AW/VS:FX/FP:AU/SR:PO/RL:EP/EV:F/PP:abc/SA:900#CVE:svc:rt"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ParseVector(tc.input)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestSuggestMetric(t *testing.T) {
	tests := []struct {
		input    string
		wantSug  string
		wantOK   bool
	}{
		{"XP", "CP", true},  // distance 1 from CP
		{"CP", "CP", true},  // exact match, distance 0
		{"ZZ", "", false},   // distance > 1 from all registered keys
	}
	for _, tc := range tests {
		sug, ok := SuggestMetric(tc.input)
		if ok != tc.wantOK {
			t.Errorf("SuggestMetric(%q): ok=%v, want %v", tc.input, ok, tc.wantOK)
		}
		if sug != tc.wantSug {
			t.Errorf("SuggestMetric(%q): suggestion=%q, want %q", tc.input, sug, tc.wantSug)
		}
	}
}

func TestValidateVector(t *testing.T) {
	v := CRITVector{
		CRITVersion: "0.2.0", Provider: "aws", VEXStatus: "fixed",
		FixPropagation: "rebuild_and_redeploy", SharedResp: "customer_action_required",
		Lifecycle: "stateful_customer", ExistingVuln: true,
		VulnPublished: 1719792000, ServiceAvail: 1514764800,
		VulnID: "CVE-2024-6387", Service: "ec2", ResourceType: "instance",
	}
	canonical, _ := ComputeVector(v)

	if err := ValidateVector(canonical, v); err != nil {
		t.Errorf("ValidateVector with correct vector: %v", err)
	}

	// Wrong provider in vector.
	wrong := strings.Replace(canonical, "CP:AW", "CP:MA", 1)
	if err := ValidateVector(wrong, v); err == nil {
		t.Error("ValidateVector should fail when vector doesn't match fields")
	}
}
