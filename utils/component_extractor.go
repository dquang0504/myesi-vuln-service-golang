package utils

func ExtractComponents(sbom map[string]interface{}) []map[string]string {
	comps := []map[string]string{}

	// --- 1. CycloneDX ---
	if components, ok := sbom["components"].([]interface{}); ok {
		for _, c := range components {
			if comp, ok := c.(map[string]interface{}); ok {
				name, _ := comp["name"].(string)
				version, _ := comp["version"].(string)
				typ, _ := comp["type"].(string)
				if name != "" && version != "" {
					comps = append(comps, map[string]string{
						"name":    name,
						"version": version,
						"type":    typ,
					})
				}
			}
		}
	}

	// --- 2. SPDX ---
	if spdxPkgs, ok := sbom["packages"].([]interface{}); ok {
		for _, p := range spdxPkgs {
			if pkg, ok := p.(map[string]interface{}); ok {
				name, _ := pkg["name"].(string)
				version, _ := pkg["versionInfo"].(string)
				typ := "library"
				if name != "" && version != "" {
					comps = append(comps, map[string]string{
						"name":    name,
						"version": version,
						"type":    typ,
					})
				}
			}
		}
	}

	// --- 3. Syft fallback ---
	if artifacts, ok := sbom["artifacts"].([]interface{}); ok {
		for _, a := range artifacts {
			if art, ok := a.(map[string]interface{}); ok {
				name, _ := art["name"].(string)
				version, _ := art["version"].(string)
				typ, _ := art["type"].(string)
				if name != "" && version != "" {
					comps = append(comps, map[string]string{
						"name":    name,
						"version": version,
						"type":    typ,
					})
				}
			}
		}
	}

	return comps
}
