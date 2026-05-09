package critspec

import "sort"

// This file exposes read-only accessors over the registered code tables
// so downstream Go projects can interrogate the canonical CRIT enums
// without copy-pasting the maps from critvector.go.

// ProviderCode returns the 2-letter CP code for a canonical provider key
// (e.g. "aws" -> "AW"). Reports false if the provider is not registered.
func ProviderCode(provider string) (string, bool) {
	c, ok := providerToCode[provider]
	return c, ok
}

// ProviderFromCode is the inverse of ProviderCode.
func ProviderFromCode(code string) (string, bool) {
	p, ok := codeToProvider[code]
	return p, ok
}

// KnownProvider reports whether the supplied provider key is registered
// in the spec. Use this to gate enum-strict validation in downstream
// tools that may encounter provider names not yet adopted upstream.
func KnownProvider(provider string) bool {
	_, ok := providerToCode[provider]
	return ok
}

// Providers returns every registered canonical provider key in sorted
// order. The slice is freshly allocated; callers may mutate it.
func Providers() []string {
	out := make([]string, 0, len(providerToCode))
	for p := range providerToCode {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// VEXStatusCode returns the 2-letter VS code for a vex_status value.
func VEXStatusCode(value string) (string, bool) {
	c, ok := vexStatusToCode[value]
	return c, ok
}

// FixPropagationCode returns the 2-letter FP code for a fix_propagation value.
func FixPropagationCode(value string) (string, bool) {
	c, ok := fixPropToCode[value]
	return c, ok
}

// SharedResponsibilityCode returns the 2-letter SR code for a
// shared_responsibility value.
func SharedResponsibilityCode(value string) (string, bool) {
	c, ok := sharedRespToCode[value]
	return c, ok
}

// LifecycleCode returns the 2-letter RL code for a resource_lifecycle value.
func LifecycleCode(value string) (string, bool) {
	c, ok := lifecycleToCode[value]
	return c, ok
}

// RegisteredMetricKeys returns the canonical ordered list of registered
// CRIT vector metric keys (CP, VS, FP, SR, RL, EV, PP, SA). Returns a
// fresh copy; callers may not mutate the underlying registeredKeys.
func RegisteredMetricKeys() []string {
	out := make([]string, len(registeredKeys))
	copy(out, registeredKeys)
	return out
}
