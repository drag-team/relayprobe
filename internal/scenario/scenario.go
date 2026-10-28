package scenario

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"github.com/drag-team/relayprobe/internal/config"
)

const MaxBytes = 1 << 20

type Document struct {
	SchemaVersion    int      `json:"schema_version"`
	Name             string   `json:"name"`
	Repeat           *int     `json:"repeat,omitempty"`
	MinSuccessRate   *float64 `json:"min_success_rate,omitempty"`
	TargetMatrix     *bool    `json:"target_matrix,omitempty"`
	TargetQuorum     *int     `json:"target_quorum,omitempty"`
	RotationSamples  *int     `json:"rotation_samples,omitempty"`
	RotationInterval string   `json:"rotation_interval,omitempty"`
	Targets          []Target `json:"targets"`
}

type Target struct {
	URL  string `json:"url"`
	Name string `json:"name,omitempty"`
	config.ResponseRules
}

func Load(path string) (Document, error) {
	var document Document
	f, err := os.Open(path)
	if err != nil {
		return document, fmt.Errorf("open scenario: %w", err)
	}
	defer f.Close()
	limited := &io.LimitedReader{R: f, N: MaxBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return document, fmt.Errorf("decode scenario: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return document, errors.New("scenario contains multiple JSON values")
	}
	if limited.N <= 0 {
		return document, fmt.Errorf("scenario exceeds %d bytes", MaxBytes)
	}
	if document.SchemaVersion != 1 {
		return document, errors.New("scenario schema_version must be 1")
	}
	document.Name = strings.TrimSpace(document.Name)
	if document.Name == "" || len(document.Name) > 64 || strings.IndexFunc(document.Name, unicode.IsControl) >= 0 {
		return document, errors.New("scenario name must contain 1 to 64 safe characters")
	}
	if len(document.Targets) == 0 || len(document.Targets) > 32 {
		return document, errors.New("scenario must contain between 1 and 32 targets")
	}
	seen := make(map[string]struct{}, len(document.Targets))
	for index, target := range document.Targets {
		if _, exists := seen[target.URL]; exists {
			return document, fmt.Errorf("scenario target %d duplicates an earlier target", index+1)
		}
		seen[target.URL] = struct{}{}
		if len(target.Name) > 64 || strings.IndexFunc(target.Name, unicode.IsControl) >= 0 {
			return document, fmt.Errorf("scenario target %d has an invalid name", index+1)
		}
	}
	return document, nil
}

func Apply(document Document, destination *config.Config) error {
	destination.ScenarioName = document.Name
	destination.Targets = make([]string, 0, len(document.Targets))
	destination.TargetRules = make(map[string]config.ResponseRules, len(document.Targets))
	destination.TargetLabels = make(map[string]string, len(document.Targets))
	for _, target := range document.Targets {
		destination.Targets = append(destination.Targets, target.URL)
		destination.TargetRules[target.URL] = target.ResponseRules
		if target.Name != "" {
			destination.TargetLabels[target.URL] = target.Name
		}
	}
	if document.Repeat != nil {
		destination.Repeat = *document.Repeat
	}
	if document.MinSuccessRate != nil {
		destination.MinSuccessRate = *document.MinSuccessRate
	}
	if document.TargetMatrix != nil {
		destination.TargetMatrix = *document.TargetMatrix
	}
	if document.TargetQuorum != nil {
		destination.TargetQuorum = *document.TargetQuorum
	}
	if document.RotationSamples != nil {
		destination.RotationSamples = *document.RotationSamples
	}
	if document.RotationInterval != "" {
		destination.RotationRaw = document.RotationInterval
	}
	return nil
}
