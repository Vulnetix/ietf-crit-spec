// Package critspec embeds the CRIT dictionaries and JSON schemas into the
// binary at build time so that tools like crit-validate carry the spec
// default dictionary and validation schemas without requiring external files.
package critspec

import "embed"

// Dictionaries embeds all provider dictionary JSON files from dictionaries/.
//
//go:embed dictionaries/*.json
var Dictionaries embed.FS

// DictionarySchema embeds the CRIT dictionary JSON Schema.
//
//go:embed schemas/crit-dictionary-v0.2.0.schema.json
var DictionarySchema []byte
