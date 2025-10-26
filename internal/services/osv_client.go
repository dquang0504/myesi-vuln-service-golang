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
	"time"
)

var OSVURL = config.LoadConfig().OSVURL

type queryPackage struct {
	Package map[string]string `json:"package"`
}

// QueryOSVBatch sends record(s) of components (package name + version) to OSV API to fetch
// vulnerabilities if found any
func QueryOSVBatch(ctx context.Context, comps []config.OSVRecord) ([]map[string]interface{}, error) {
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
