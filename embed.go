// Package critspec embeds the CRIT dictionaries and JSON schemas into the
// binary at build time so that tools like crit-validate carry the spec
// default dictionary and validation schemas without requiring external
// files. Downstream Go projects import this package to get the canonical
// dictionaries and schemas without re-shipping their own copies.
package critspec

import "embed"

// Dictionaries embeds all provider dictionary JSON files from
// dictionaries/. Iterate with fs.WalkDir; each file is a single-provider
// dictionary conforming to DictionarySchema.
//
//go:embed dictionaries/*.json
var Dictionaries embed.FS

// DictionarySchema is the JSON Schema that validates provider dictionary
// files. Compile with any draft 2020-12 capable validator (e.g.
// github.com/santhosh-tekuri/jsonschema/v6).
//
//go:embed schemas/crit-dictionary-v0.3.0.schema.json
var DictionarySchema []byte

// RecordSchema is the JSON Schema that validates a single hand-authored
// or processor-emitted CRIT record (the per-CVE x_crit payload).
//
//go:embed schemas/crit-record-v0.3.0.schema.json
var RecordSchema []byte

// SamplesSchema is the JSON Schema that validates the generated
// CRIT-samples.json output produced by the conformance test harness.
// Most downstream consumers will not need this; included for parity.
//
//go:embed schemas/crit-samples-v0.1.0.schema.json
var SamplesSchema []byte

// SchemaVersion is the active CRIT schema version reflected in the
// embedded RecordSchema, DictionarySchema, and Dictionaries content.
// Downstream code can use this for log lines or compatibility checks.
const SchemaVersion = "0.3.0"
