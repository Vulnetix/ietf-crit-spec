package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	critspec "github.com/Vulnetix/ietf-crit-spec"
)

// binaryPath builds crit-validate and returns the path to the binary.
func binaryPath(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "crit-validate")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = filepath.Join(rootDir(t), "cmd", "crit-validate")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return bin
}

// rootDir returns the repository root (two levels up from cmd/crit-validate).
func rootDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(wd, "..", "..")
}

// allSampleFiles returns paths to every sample JSON file.
func allSampleFiles(t *testing.T) []string {
	t.Helper()
	root := rootDir(t)
	var files []string
	for _, provider := range []string{"aws", "azure", "cloudflare", "gcp", "oracle"} {
		matches, err := filepath.Glob(filepath.Join(root, "samples", provider, "*.json"))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, matches...)
	}
	if len(files) == 0 {
		t.Fatal("no sample files found")
	}
	return files
}

// TestConvertFromJSON_AllSamples runs --from-json on every sample and verifies
// the output is a parseable CRIT vector whose fields match the source JSON.
func TestConvertFromJSON_AllSamples(t *testing.T) {
	bin := binaryPath(t)

	for _, samplePath := range allSampleFiles(t) {
		name := filepath.Base(samplePath)
		t.Run(name, func(t *testing.T) {
			// Run convert --from-json
			out, err := exec.Command(bin, "convert", "--from-json", samplePath).CombinedOutput()
			if err != nil {
				t.Fatalf("convert --from-json failed: %v\n%s", err, out)
			}
			vector := strings.TrimSpace(string(out))

			// Parse the vector output
			parsed, warnings, err := critspec.ParseVector(vector)
			if err != nil {
				t.Fatalf("output vector does not parse: %v\nvector: %s", err, vector)
			}
			for _, w := range warnings {
				t.Logf("warning: %s", w.Message)
			}

			// Load the source JSON and compare fields
			data, err := os.ReadFile(samplePath)
			if err != nil {
				t.Fatal(err)
			}
			var rec map[string]interface{}
			if err := json.Unmarshal(data, &rec); err != nil {
				t.Fatal(err)
			}

			if parsed.Provider != rec["provider"] {
				t.Errorf("provider: got %q, want %q", parsed.Provider, rec["provider"])
			}
			if parsed.VEXStatus != rec["vex_status"] {
				t.Errorf("vex_status: got %q, want %q", parsed.VEXStatus, rec["vex_status"])
			}
			if parsed.FixPropagation != rec["fix_propagation"] {
				t.Errorf("fix_propagation: got %q, want %q", parsed.FixPropagation, rec["fix_propagation"])
			}
			if parsed.SharedResp != rec["shared_responsibility"] {
				t.Errorf("shared_responsibility: got %q, want %q", parsed.SharedResp, rec["shared_responsibility"])
			}
			if parsed.Lifecycle != rec["resource_lifecycle"] {
				t.Errorf("resource_lifecycle: got %q, want %q", parsed.Lifecycle, rec["resource_lifecycle"])
			}
			if parsed.VulnID != rec["vuln_id"] {
				t.Errorf("vuln_id: got %q, want %q", parsed.VulnID, rec["vuln_id"])
			}
			if parsed.Service != rec["service"] {
				t.Errorf("service: got %q, want %q", parsed.Service, rec["service"])
			}
			if parsed.ResourceType != rec["resource_type"] {
				t.Errorf("resource_type: got %q, want %q", parsed.ResourceType, rec["resource_type"])
			}
		})
	}
}

// TestConvertRoundTrip_AllSamples verifies that for every sample:
// JSON → vector → parsed JSON → recomputed vector produces the same vector.
func TestConvertRoundTrip_AllSamples(t *testing.T) {
	bin := binaryPath(t)

	for _, samplePath := range allSampleFiles(t) {
		name := filepath.Base(samplePath)
		t.Run(name, func(t *testing.T) {
			// Step 1: JSON → vector
			out1, err := exec.Command(bin, "convert", "--from-json", samplePath).CombinedOutput()
			if err != nil {
				t.Fatalf("from-json failed: %v\n%s", err, out1)
			}
			vector := strings.TrimSpace(string(out1))

			// Step 2: vector → JSON
			out2, err := exec.Command(bin, "convert", "--from-vector", vector).CombinedOutput()
			if err != nil {
				t.Fatalf("from-vector failed: %v\n%s", err, out2)
			}

			// Step 3: Parse the expanded JSON and recompute
			var parsed critspec.CRITVector
			if err := json.Unmarshal(out2, &parsed); err != nil {
				t.Fatalf("expanded JSON does not unmarshal: %v", err)
			}
			recomputed, err := critspec.ComputeVector(parsed)
			if err != nil {
				t.Fatalf("recompute failed: %v", err)
			}

			// Step 4: Verify round-trip
			if recomputed != vector {
				t.Errorf("round-trip mismatch:\n  original:   %s\n  recomputed: %s", vector, recomputed)
			}
		})
	}
}

// TestConvertFromVector_ValidatesOutput verifies that --from-vector output
// contains all required fields with correct types.
func TestConvertFromVector_ValidatesOutput(t *testing.T) {
	bin := binaryPath(t)

	vectors := []string{
		"CRITv0.3.0/CP:AW/VS:FX/FP:RR/SR:CA/RL:SC/EV:T/PP:1719792000/SA:1187740800#CVE-2024-6387:ec2:instance",
		"CRITv0.3.0/CP:MA/VS:AF/FP:CC/SR:SH/RL:CF/EV:T/PP:1719237600/SA:1596240000#CVE-2024-37085:azure_vmware_solution:privateClouds",
		"CRITv0.3.0/CP:CF/VS:FX/FP:AU/SR:PO/RL:GC/EV:F/PP:1696856400/SA:1222300800#CVE-2023-44487:dns:zone",
		"CRITv0.3.0/CP:OC/VS:FX/FP:CC/SR:CA/RL:SC/EV:T/PP:1705323600/SA:1475280000#CVE-2024-20953:compute:instance",
		"CRITv0.3.0/CP:GC/VS:FX/FP:CC/SR:SH/RL:EP/EV:T/PP:1721570400/SA:1500940800#TRA-2024-20:cloud_functions:function",
	}

	requiredFields := []string{
		"CRITVersion", "Provider", "VEXStatus", "FixPropagation",
		"SharedResp", "Lifecycle", "VulnID", "Service", "ResourceType",
	}

	for _, v := range vectors {
		t.Run(v[0:40], func(t *testing.T) {
			out, err := exec.Command(bin, "convert", "--from-vector", v).CombinedOutput()
			if err != nil {
				t.Fatalf("from-vector failed: %v\n%s", err, out)
			}

			var result map[string]interface{}
			if err := json.Unmarshal(out, &result); err != nil {
				t.Fatalf("output is not valid JSON: %v", err)
			}

			for _, field := range requiredFields {
				val, ok := result[field]
				if !ok {
					t.Errorf("missing required field %q", field)
					continue
				}
				s, ok := val.(string)
				if !ok {
					t.Errorf("field %q is not a string: %T", field, val)
					continue
				}
				if s == "" {
					t.Errorf("field %q is empty", field)
				}
			}

			// Check epoch fields are numbers
			for _, field := range []string{"VulnPublished", "ServiceAvail"} {
				val, ok := result[field]
				if !ok {
					t.Errorf("missing epoch field %q", field)
					continue
				}
				if _, ok := val.(float64); !ok {
					t.Errorf("field %q is not a number: %T", field, val)
				}
			}
		})
	}
}

// TestConvertFromJSON_VectorMatchesEmbedded verifies that the vector computed
// by convert --from-json matches the vectorString already in the sample file.
func TestConvertFromJSON_VectorMatchesEmbedded(t *testing.T) {
	bin := binaryPath(t)

	for _, samplePath := range allSampleFiles(t) {
		name := filepath.Base(samplePath)
		t.Run(name, func(t *testing.T) {
			// Read the embedded vectorString
			data, err := os.ReadFile(samplePath)
			if err != nil {
				t.Fatal(err)
			}
			var rec struct {
				VectorString string `json:"vectorString"`
			}
			if err := json.Unmarshal(data, &rec); err != nil {
				t.Fatal(err)
			}
			if rec.VectorString == "" {
				t.Skip("no vectorString in sample")
			}

			// Compute via convert
			out, err := exec.Command(bin, "convert", "--from-json", samplePath).CombinedOutput()
			if err != nil {
				t.Fatalf("convert failed: %v\n%s", err, out)
			}
			computed := strings.TrimSpace(string(out))

			if computed != rec.VectorString {
				t.Errorf("computed vector does not match embedded:\n  computed: %s\n  embedded: %s", computed, rec.VectorString)
			}
		})
	}
}

// TestConvertFromVector_UnknownMetrics verifies that unknown metrics produce
// warnings on stderr but valid JSON on stdout.
func TestConvertFromVector_UnknownMetrics(t *testing.T) {
	bin := binaryPath(t)

	// Valid vector with an extra unknown metric "XX:foo" appended
	v := "CRITv0.3.0/CP:AW/VS:FX/FP:AU/SR:PO/RL:EP/EV:F/PP:1000000000/SA:900000000/XX:foo#CVE-2024-0001:svc:rt"

	cmd := exec.Command(bin, "convert", "--from-vector", v)
	// Use Output() to capture only stdout (warnings go to stderr)
	stdout, err := cmd.Output()
	if err != nil {
		t.Fatalf("should not error on unknown metrics: %v", err)
	}

	// Verify the output JSON still has correct known fields
	var result critspec.CRITVector
	if err := json.Unmarshal(stdout, &result); err != nil {
		t.Fatalf("stdout JSON invalid: %v\nstdout: %s", err, stdout)
	}
	if result.Provider != "aws" {
		t.Errorf("Provider: got %q, want aws", result.Provider)
	}
	if result.UnknownMetrics["XX"] != "foo" {
		t.Errorf("unknown metric XX not preserved: %v", result.UnknownMetrics)
	}
}

// TestConvertFromVector_InvalidVector verifies that invalid vectors produce
// non-zero exit codes.
func TestConvertFromVector_InvalidVector(t *testing.T) {
	bin := binaryPath(t)

	invalid := []struct {
		name   string
		vector string
	}{
		{"missing_hash", "CRITv0.3.0/CP:AW/VS:FX/FP:AU/SR:PO/RL:EP/EV:F/PP:1000/SA:900"},
		{"bad_prefix", "FOOv0.2.0/CP:AW/VS:FX/FP:AU/SR:PO/RL:EP/EV:F/PP:1000/SA:900#CVE:svc:rt"},
		{"missing_metric", "CRITv0.3.0/VS:FX/FP:AU/SR:PO/RL:EP/EV:F/PP:1000/SA:900#CVE:svc:rt"},
		{"bad_code", "CRITv0.3.0/CP:ZZ/VS:FX/FP:AU/SR:PO/RL:EP/EV:F/PP:1000/SA:900#CVE:svc:rt"},
	}

	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(bin, "convert", "--from-vector", tc.vector)
			if err := cmd.Run(); err == nil {
				t.Error("expected non-zero exit for invalid vector")
			}
		})
	}
}
