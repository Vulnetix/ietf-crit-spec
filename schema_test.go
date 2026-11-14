package critspec

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// TestRecordSchemaIdentifiers checks the identifier rules of the record
// schema (scheme, issuer, aliases) against the GCVE-keyed sample and
// variants of it that must be rejected.
func TestRecordSchemaIdentifiers(t *testing.T) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(RecordSchema))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	const url = "https://vulnetix.com/schemas/crit-record-v0.3.0.schema.json"
	if err := c.AddResource(url, doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile(url)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile("samples/aws/gcve-110-cloud-2022-0025-eks-iam-authenticator.json")
	if err != nil {
		t.Fatal(err)
	}
	load := func() map[string]any {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	validate := func(m map[string]any) error {
		b, _ := json.Marshal(m)
		inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		return sch.Validate(inst)
	}

	if err := validate(load()); err != nil {
		t.Fatalf("GCVE-keyed sample rejected: %v", err)
	}

	ok := map[string]func(m map[string]any){
		"unknown scheme is an open token": func(m map[string]any) {
			m["aliases"] = []any{map[string]any{"scheme": "rhsa", "id": "RHSA-2024:1234"}}
		},
		"gcve alias with vector-unsafe characters": func(m map[string]any) {
			m["aliases"] = []any{map[string]any{"scheme": "gcve", "id": "GCVE-65535-RHSA-2024:1234"}}
		},
		"CVE-keyed record with GCVE alias": func(m map[string]any) {
			m["vuln_id"], m["scheme"], m["issuer"] = "CVE-2022-2385", "cve", "AWS"
			m["aliases"] = []any{map[string]any{"scheme": "gcve", "id": "GCVE-110-CLOUD-2022-0025"}}
		},
	}
	for name, mutate := range ok {
		m := load()
		mutate(m)
		if err := validate(m); err != nil {
			t.Errorf("%s: rejected: %v", name, err)
		}
	}

	bad := map[string]func(m map[string]any){
		"vuln_id containing ':'": func(m map[string]any) {
			m["vuln_id"] = "GCVE-65535-RHSA-2024:1234"
		},
		"percent-encoded vuln_id": func(m map[string]any) {
			m["vuln_id"] = "GCVE-65535-RHSA-2024%3A1234"
		},
		"scheme gcve with non-numeric GNA": func(m map[string]any) {
			m["vuln_id"] = "GCVE-ABC-2022-0025"
		},
		"scheme cve with GCVE vuln_id": func(m map[string]any) {
			m["scheme"] = "cve"
		},
		"uppercase scheme": func(m map[string]any) {
			m["scheme"] = "GCVE"
		},
		"alias as plain string": func(m map[string]any) {
			m["aliases"] = []any{"CVE-2022-2385"}
		},
		"alias cve with bad shape": func(m map[string]any) {
			m["aliases"] = []any{map[string]any{"scheme": "cve", "id": "CVE-22-2385"}}
		},
		"alias gcve with non-numeric GNA": func(m map[string]any) {
			m["aliases"] = []any{map[string]any{"scheme": "gcve", "id": "GCVE-X-2022-0025"}}
		},
		"duplicate alias": func(m map[string]any) {
			a := map[string]any{"scheme": "cve", "id": "CVE-2022-2385"}
			m["aliases"] = []any{a, a}
		},
	}
	for name, mutate := range bad {
		m := load()
		mutate(m)
		if err := validate(m); err == nil {
			t.Errorf("%s: accepted, want rejection", name)
		}
	}

	// An alias that repeats vuln_id cannot be expressed in JSON Schema; it is
	// enforced by CheckAliases (crit-test 4.1.5).
	if err := CheckAliases([]VulnAlias{{"gcve", "GCVE-110-CLOUD-2022-0025"}}, "GCVE-110-CLOUD-2022-0025"); err == nil {
		t.Error("CheckAliases accepted an alias that repeats vuln_id")
	}
}
