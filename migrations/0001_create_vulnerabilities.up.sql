CREATE TABLE IF NOT EXISTS vulnerabilities (
    id BIGSERIAL PRIMARY KEY,
    sbom_id UUID NOT NULL,
    project_name TEXT,
    component_name TEXT NOT NULL,
    component_version TEXT NOT NULL,
    vuln_id TEXT, -- CVE/GHSA/OSV id if present
    severity TEXT,
    osv_metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    UNIQUE (sbom_id, component_name, component_version, vuln_id)
);

CREATE INDEX IF NOT EXISTS idx_vuln_sbom ON vulnerabilities(sbom_id);
CREATE INDEX IF NOT EXISTS idx_vuln_component ON vulnerabilities(component_name);