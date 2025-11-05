package utils

import (
	"fmt"
	"math"
	"strings"
)

// ParseCvssVectorToScore parses a CVSS v3.x vector string and calculates the Base Score
// e.g. "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N" -> 5.3
func ParseCvssVectorToScore(vector string) (float64, error) {
	if !strings.HasPrefix(vector, "CVSS:3") {
		return 0.0, fmt.Errorf("unsupported vector: %s", vector)
	}

	metrics := make(map[string]string)
	parts := strings.Split(vector, "/")
	for _, p := range parts[1:] { // skip CVSS:3.x prefix
		kv := strings.SplitN(p, ":", 2)
		if len(kv) == 2 {
			metrics[kv[0]] = kv[1]
		}
	}

	// Exploitability metrics
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[metrics["AC"]]
	prU := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[metrics["PR"]]
	prC := map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}[metrics["PR"]]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[metrics["UI"]]

	scope := metrics["S"] // U or C
	pr := prU
	if scope == "C" {
		pr = prC
	}

	exploitability := 8.22 * av * ac * pr * ui

	// Impact metrics
	impactC := map[string]float64{"N": 0.0, "L": 0.22, "H": 0.56}[metrics["C"]]
	impactI := map[string]float64{"N": 0.0, "L": 0.22, "H": 0.56}[metrics["I"]]
	impactA := map[string]float64{"N": 0.0, "L": 0.22, "H": 0.56}[metrics["A"]]

	impact := 0.0
	if scope == "U" {
		impact = 1 - ((1 - impactC) * (1 - impactI) * (1 - impactA))
	} else {
		impact = 1.08 * (1 - ((1 - impactC) * (1 - impactI) * (1 - impactA)))
	}

	baseScore := 0.0
	if impact <= 0 {
		baseScore = 0
	} else {
		if scope == "U" {
			score := math.Min(impact+exploitability, 10)
			baseScore = math.Round(score*10) / 10.0
		} else {
			score := math.Min(1.08*(impact+exploitability), 10)
			baseScore = math.Round(score*10) / 10.0
		}
	}
	return baseScore, nil
}
