package config

import (
	"sort"
	"strings"
)

// SemgrepConfigResolver maps GitHub languages → Semgrep config names
var semgrepConfigMap = map[string]string{
	"go":          "p/golang",
	"golang":      "p/golang",
	"python":      "p/python",
	"java":        "p/java",
	"javascript":  "p/javascript",
	"typescript":  "p/typescript",
	"ruby":        "p/ruby",
	"php":         "p/php",
	"rust":        "p/rust",
	"c":           "p/c",
	"cpp":         "p/cpp",
	"c++":         "p/cpp",
	"c#":          "p/csharp",
	"csharp":      "p/csharp",
	"dotnet":      "p/csharp",
	"objective-c": "p/objective-c",
	"kotlin":      "p/kotlin",
	"scala":       "p/scala",
	"swift":       "p/swift",
	"perl":        "p/perl",
	"haskell":     "p/haskell",
	"lua":         "p/lua",
	"elixir":      "p/elixir",
	"dart":        "p/dart",
	"dockerfile":  "p/dockerfile",
	"terraform":   "p/terraform",
	"yaml":        "p/yaml",
	"json":        "p/json",
	"html":        "p/html",
	"jsx":         "p/javascript",
	"tsx":         "p/typescript",
	"shell":       "p/bash",
	"bash":        "p/bash",
	"powershell":  "p/powershell",
	"sql":         "p/sql",
	// note: intentionally not mapping "css" -> "p/c" (avoids CSS->C mistake)
}

// Normalize single language token
func normalizeLang(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// ResolveSemgrepConfigSingle tries to resolve a single language token to a semgrep config.
// Rules:
//   - exact lookup first
//   - substring matching only for keys of length >= 2 (avoid matching "c" inside "css")
//   - prefer longer key matches (to avoid small-key collisions)
func ResolveSemgrepConfigSingle(language string) string {
	if language == "" {
		return ""
	}
	key := normalizeLang(language)
	if cfg, ok := semgrepConfigMap[key]; ok {
		return cfg
	}

	// prepare candidate keys sorted by length desc so we prefer longer matches
	type kv struct {
		k string
		v string
	}
	cands := make([]kv, 0, len(semgrepConfigMap))
	for k, v := range semgrepConfigMap {
		cands = append(cands, kv{k: k, v: v})
	}
	sort.SliceStable(cands, func(i, j int) bool {
		return len(cands[i].k) > len(cands[j].k)
	})

	for _, c := range cands {
		// only consider substring matches for keys of length >= 2
		if len(c.k) >= 2 && strings.Contains(key, c.k) {
			return c.v
		}
	}

	return "" // no match
}

// ResolveSemgrepConfigs accepts a list of GitHub languages (ordered by repo language share)
// and returns an ordered list of semgrep configs to pass to the CLI.
// - It avoids bogus matches like "css" -> "c"
// - It de-dupes results and preserves input priority
// - It limits the number of configs to avoid huge scans
func ResolveSemgrepConfigs(langs []string) []string {
	if len(langs) == 0 {
		return []string{"auto"}
	}

	seen := map[string]bool{}
	configs := make([]string, 0, 4)
	maxConfigs := 4

	for _, lang := range langs {
		cfg := ResolveSemgrepConfigSingle(lang)
		if cfg == "" {
			// skip languages without a semgrep config (eg. CSS/SCSS may not map well)
			continue
		}
		if !seen[cfg] {
			configs = append(configs, cfg)
			seen[cfg] = true
			if len(configs) >= maxConfigs {
				break
			}
		}
	}

	// Always fallback to "auto" if nothing resolved (so semgrep can still try autodetect)
	if len(configs) == 0 {
		return []string{"auto"}
	}
	return configs
}
