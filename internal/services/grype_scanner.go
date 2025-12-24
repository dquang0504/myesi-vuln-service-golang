package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// GrypeFinding represents a normalized vulnerability record produced by Grype.
type GrypeFinding struct {
	ComponentName    string
	ComponentVersion string
	VulnerabilityID  string
	Severity         string
	CVSSVector       *string
	CVSSScore        float64
	FixAvailable     bool
	FixedVersion     *string
	Metadata         []byte
}

type grypeReport struct {
	Matches []grypeMatch `json:"matches"`
}

type grypeMatch struct {
	Artifact struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Type    string `json:"type"`
		PURL    string `json:"purl"`
	} `json:"artifact"`
	Vulnerability struct {
		ID         string      `json:"id"`
		Severity   string      `json:"severity"`
		Fix        grypeFix    `json:"fix"`
		CVSS       []grypeCVSS `json:"cvss"`
		Metadata   interface{} `json:"metadata"`
		DataSource string      `json:"dataSource"`
	} `json:"vulnerability"`
}

type grypeFix struct {
	State    string   `json:"state"`
	Versions []string `json:"versions"`
}

type grypeCVSS struct {
	Vector  string `json:"vector"`
	Metrics struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"metrics"`
}

func cvssVersionRank(vector string) int {
	vec := strings.ToUpper(vector)
	switch {
	case strings.Contains(vec, "CVSS:3"):
		return 3
	case strings.Contains(vec, "CVSS:2"):
		return 2
	case vec != "":
		return 1
	default:
		return 0
	}
}

func selectBestCVSS(entries []grypeCVSS) (vector string, hasVector bool, score float64) {
	bestRank := -1
	bestScore := 0.0
	var bestVector string
	var vectorPresent bool

	for _, entry := range entries {
		vec := strings.TrimSpace(entry.Vector)
		val := entry.Metrics.BaseScore
		rank := cvssVersionRank(vec)

		if val <= 0 && vec == "" {
			continue
		}

		if rank > bestRank || (rank == bestRank && val > bestScore) {
			bestRank = rank
			bestScore = val
			if vec != "" {
				bestVector = vec
				vectorPresent = true
			} else {
				bestVector = ""
				vectorPresent = false
			}
		}
	}

	return bestVector, vectorPresent, bestScore
}

// BuildCycloneDXFromComponents serializes the provided component list into a minimal CycloneDX SBOM.
func BuildCycloneDXFromComponents(components []map[string]string) ([]byte, error) {
	type cdxComponent struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Version string `json:"version"`
		PURL    string `json:"purl,omitempty"`
	}
	type cdxBOM struct {
		BomFormat   string         `json:"bomFormat"`
		SpecVersion string         `json:"specVersion"`
		Version     int            `json:"version"`
		Components  []cdxComponent `json:"components"`
	}

	bom := cdxBOM{
		BomFormat:   "CycloneDX",
		SpecVersion: "1.4",
		Version:     1,
	}

	for _, c := range components {
		name := strings.TrimSpace(c["name"])
		version := strings.TrimSpace(c["version"])
		if name == "" || version == "" {
			continue
		}
		componentType := strings.ToLower(strings.TrimSpace(c["type"]))
		if componentType == "" {
			componentType = "library"
		}
		bom.Components = append(bom.Components, cdxComponent{
			Type:    componentType,
			Name:    name,
			Version: version,
		})
	}

	if len(bom.Components) == 0 {
		return nil, fmt.Errorf("no valid components to build SBOM")
	}

	return json.Marshal(bom)
}

// ScanSBOMWithGrype executes Grype against the provided SBOM document bytes and
// normalizes the resulting matches.
func ScanSBOMWithGrype(ctx context.Context, sbomBytes []byte) ([]GrypeFinding, error) {
	if len(sbomBytes) == 0 {
		return nil, fmt.Errorf("empty SBOM payload")
	}

	tmpFile, err := os.CreateTemp("", "sbom-*.json")
	if err != nil {
		return nil, fmt.Errorf("create temp SBOM file: %w", err)
	}
	defer func() {
		tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
	}()

	if _, err := tmpFile.Write(sbomBytes); err != nil {
		return nil, fmt.Errorf("write SBOM temp file: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		return nil, fmt.Errorf("sync SBOM temp file: %w", err)
	}

	grypeCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(grypeCtx, "grype", fmt.Sprintf("sbom:%s", tmpFile.Name()), "-o", "json")
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("grype scan failed: %w\n%s", err, output.String())
	}

	var report grypeReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		return nil, fmt.Errorf("parse grype output: %w", err)
	}

	findings := make([]GrypeFinding, 0, len(report.Matches))
	seen := make(map[string]struct{})

	for _, match := range report.Matches {
		name := strings.TrimSpace(match.Artifact.Name)
		version := strings.TrimSpace(match.Artifact.Version)
		vulnID := strings.TrimSpace(match.Vulnerability.ID)
		if name == "" || version == "" || vulnID == "" {
			continue
		}

		key := name + "|" + version + "|" + vulnID
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		metadata, _ := json.Marshal(match)
		severity := strings.ToLower(strings.TrimSpace(match.Vulnerability.Severity))

		var cvssVector *string
		cvssScore := 0.0
		if vec, ok, score := selectBestCVSS(match.Vulnerability.CVSS); ok || score > 0 {
			if ok {
				vectorCopy := vec
				cvssVector = &vectorCopy
			}
			if score > 0 {
				cvssScore = score
			}
		}

		fixAvailable := false
		var fixedVersion *string
		if len(match.Vulnerability.Fix.Versions) > 0 {
			fixAvailable = true
			version := match.Vulnerability.Fix.Versions[0]
			if strings.TrimSpace(version) != "" {
				v := strings.TrimSpace(version)
				fixedVersion = &v
			}
		} else if strings.EqualFold(match.Vulnerability.Fix.State, "fixed") {
			fixAvailable = true
		}

		findings = append(findings, GrypeFinding{
			ComponentName:    name,
			ComponentVersion: version,
			VulnerabilityID:  vulnID,
			Severity:         severity,
			CVSSVector:       cvssVector,
			CVSSScore:        cvssScore,
			FixAvailable:     fixAvailable,
			FixedVersion:     fixedVersion,
			Metadata:         metadata,
		})
	}

	return findings, nil
}
