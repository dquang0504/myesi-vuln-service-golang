package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"myesi-vuln-service-golang/internal/config"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	//rate limiter for OSV queries
	osvLimiter = time.Tick(time.Second / 10) // 5 requests per second
	OSVURL     = config.LoadConfig().OSVURL
)

// QueryOSVBatch sends record(s) of components (package name + version) to OSV API to fetch
// vulnerabilities if found any
func QueryOSVBatch(ctx context.Context, comps []config.OSVRecord) ([]map[string]interface{}, error) {
	<-osvLimiter
	if len(comps) == 0 {
		return nil, fmt.Errorf("no components provided")
	}

	// --- Chuẩn bị payload theo OSV batch format ---
	queries := make([]map[string]interface{}, 0, len(comps))
	for _, c := range comps {
		q := map[string]interface{}{
			"package": map[string]string{
				"name":      c.Package.Name,
				"ecosystem": c.Package.Ecosystem,
			},
			"version": c.Version,
		}
		queries = append(queries, q)
	}

	payloadMap := map[string]interface{}{"queries": queries}
	payloadBytes, err := json.Marshal(payloadMap)
	if err != nil {
		return nil, err
	}

	// --- Log payload trước khi gửi ---
	log.Printf("OSV batch payload: %s\n", string(payloadBytes))

	// --- Gửi request POST ---
	req, err := http.NewRequestWithContext(ctx, "POST", OSVURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned status %d: %s", resp.StatusCode, string(body))
	}

	// --- Parse kết quả ---
	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}

	fmt.Println("parsed: ", parsed)

	resultsRaw, ok := parsed["results"]
	if !ok {
		return nil, fmt.Errorf("no 'results' field in OSV response")
	}

	resultsArr, ok := resultsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("'results' field is not array")
	}

	// --- Convert []interface{} → []map[string]interface{} ---
	results := make([]map[string]interface{}, 0, len(resultsArr))
	for _, r := range resultsArr {
		if m, ok := r.(map[string]interface{}); ok {
			results = append(results, m)
		} else {
			results = append(results, map[string]interface{}{"note": "invalid result format"})
		}
	}

	// --- Log kết quả ngay sau khi nhận ---
	for i, r := range results {
		if len(r) > 0 {
			log.Printf("Component %s@%s has vuln info: %+v\n", comps[i].Package.Name, comps[i].Version, r)
		}
	}

	return results, nil
}

func CvssToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0.0:
		return "low"
	default:
		return "none"
	}
}

// FetchVulnDetails fetches vulnerability details from OSV API,
// returning severity label, optional CVSS vector, and patch info if available.
func FetchVulnDetails(ctx context.Context, vulnID string) (string, *string, bool, *string, error) {
	url := fmt.Sprintf("https://api.osv.dev/v1/vulns/%s", vulnID)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "unknown", nil, false, nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "unknown", nil, false, nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "unknown", nil, false, nil, fmt.Errorf("decode error: %w", err)
	}

	label := "unknown"
	var cvssVector *string
	fixAvailable := false
	var fixedVersion *string

	// --- Parse severity ---
	if sevRaw, ok := data["severity"]; ok {
		if arr, ok := sevRaw.([]interface{}); ok {
			for _, item := range arr {
				if m, ok := item.(map[string]interface{}); ok {
					if s, ok := m["score"].(string); ok {
						if f, err := strconv.ParseFloat(s, 64); err == nil {
							label = CvssToSeverity(f)
						} else if strings.HasPrefix(s, "CVSS:") {
							cvssVector = &s
						}
					}
					if t, ok := m["type"].(string); ok && strings.HasPrefix(t, "CVSS") {
						if s, ok := m["score"].(string); ok && strings.HasPrefix(s, "CVSS:") {
							cvssVector = &s
						}
					}
				}
			}
		} else if s, ok := sevRaw.(string); ok {
			label = strings.ToLower(s)
		}
	}

	// --- Fallback: database_specific.severity ---
	if label == "unknown" {
		if ds, ok := data["database_specific"].(map[string]interface{}); ok {
			if s, ok := ds["severity"].(string); ok {
				label = strings.ToLower(s)
			}
		}
	}

	// --- Extract fix info ---
	if affected, ok := data["affected"].([]interface{}); ok {
		for _, a := range affected {
			if aMap, ok := a.(map[string]interface{}); ok {
				if ranges, ok := aMap["ranges"].([]interface{}); ok {
					for _, r := range ranges {
						if rMap, ok := r.(map[string]interface{}); ok {
							if events, ok := rMap["events"].([]interface{}); ok {
								for _, e := range events {
									if ev, ok := e.(map[string]interface{}); ok {
										if fixed, ok := ev["fixed"].(string); ok && fixed != "" {
											fixAvailable = true
											fixedVersion = &fixed
											break
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return label, cvssVector, fixAvailable, fixedVersion, nil
}
