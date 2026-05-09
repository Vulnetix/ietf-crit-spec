// Package dictload reads the embedded CRIT Spec Default Dictionaries
// (github.com/Vulnetix/ietf-crit-spec/dictionaries/*.json) and returns
// them in a typed form. Downstream Go projects should consume this
// instead of re-implementing the walk over critspec.Dictionaries.
package dictload

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	critspec "github.com/Vulnetix/ietf-crit-spec"
)

// Entry is one (service, resource_type) row from a provider dictionary.
// Field names mirror crit-dictionary-v0.3.0.schema.json verbatim so JSON
// round-trips work without a separate marshal struct.
type Entry struct {
	Service        string `json:"service"`
	ResourceType   string `json:"resource_type"`
	Template       string `json:"template"`
	TemplateFormat string `json:"template_format"`
	RegionBehavior string `json:"region_behavior"`
	Notes          string `json:"notes,omitempty"`
}

// Dictionary is the on-disk shape of one provider dictionary file.
type Dictionary struct {
	DictionaryVersion string  `json:"dictionary_version"`
	Provider          string  `json:"provider"`
	Entries           []Entry `json:"entries"`
}

// Key is a (provider, service, resource_type) natural key used as the
// lookup index in NewIndex.
type Key struct {
	Provider     string
	Service      string
	ResourceType string
}

// Load walks the embedded Spec Default Dictionaries and returns one
// Dictionary per provider file. Files are returned in directory-walk
// order; callers that need deterministic ordering should sort by
// Provider.
func Load() ([]Dictionary, error) {
	var dicts []Dictionary
	err := fs.WalkDir(critspec.Dictionaries, "dictionaries", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		raw, err := fs.ReadFile(critspec.Dictionaries, path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		var dict Dictionary
		if err := json.Unmarshal(raw, &dict); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		if dict.Provider == "" {
			dict.Provider = strings.TrimSuffix(filepath.Base(path), ".json")
		}
		dicts = append(dicts, dict)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return dicts, nil
}

// Index is a lookup map from (provider, service, resource_type) → Entry
// across every embedded dictionary. The Provider field on each Entry is
// not populated; the map key carries it.
type Index map[Key]Entry

// NewIndex flattens every embedded dictionary into a single lookup
// index. Useful for downstream validators that resolve natural keys to
// templates.
func NewIndex() (Index, error) {
	dicts, err := Load()
	if err != nil {
		return nil, err
	}
	out := make(Index)
	for _, dict := range dicts {
		for _, e := range dict.Entries {
			out[Key{dict.Provider, e.Service, e.ResourceType}] = e
		}
	}
	return out, nil
}

// AllowedTemplateFormats returns the union of template_format values
// observed in the embedded dictionary for the supplied provider. Empty
// slice when the provider has no entries.
func AllowedTemplateFormats(provider string) ([]string, error) {
	dicts, err := Load()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	for _, dict := range dicts {
		if dict.Provider != provider {
			continue
		}
		for _, e := range dict.Entries {
			if e.TemplateFormat != "" {
				seen[e.TemplateFormat] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	return out, nil
}
