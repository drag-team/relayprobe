package quality

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"
	"unicode"

	"github.com/drag-team/relayprobe/internal/model"
)

type Policy struct {
	SchemaVersion       int                `json:"schema_version"`
	MinProcessed        int                `json:"min_processed,omitempty"`
	MinSuccessful       int                `json:"min_successful,omitempty"`
	MinSuccessRate      float64            `json:"min_success_rate,omitempty"`
	MaxFailureRate      *float64           `json:"max_failure_rate,omitempty"`
	MaxInconclusiveRate *float64           `json:"max_inconclusive_rate,omitempty"`
	MaxTimeoutRate      *float64           `json:"max_timeout_rate,omitempty"`
	MaxP95MS            float64            `json:"max_p95_ms,omitempty"`
	MinRatePerSec       float64            `json:"min_rate_per_sec,omitempty"`
	RequirePreflight    bool               `json:"require_preflight,omitempty"`
	Targets             map[string]float64 `json:"target_min_success_rate,omitempty"`
}

func Load(path string) (Policy, error) {
	var p Policy
	f, err := os.Open(path)
	if err != nil {
		return p, fmt.Errorf("open quality policy: %w", err)
	}
	defer f.Close()
	limited := &io.LimitedReader{R: f, N: (1 << 20) + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&p); err != nil {
		return p, fmt.Errorf("decode quality policy: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return p, errors.New("quality policy must contain one JSON object")
		}
		return p, fmt.Errorf("decode quality policy trailer: %w", err)
	}
	if limited.N <= 0 {
		return p, errors.New("quality policy exceeds 1 MiB")
	}
	if err := p.Validate(); err != nil {
		return p, err
	}
	return p, nil
}

func (p Policy) Validate() error {
	if p.SchemaVersion != 1 {
		return errors.New("quality policy schema_version must be 1")
	}
	if p.MinProcessed < 0 || p.MinSuccessful < 0 {
		return errors.New("quality policy counts must not be negative")
	}
	values := []struct {
		name  string
		value *float64
	}{
		{"min_success_rate", p.optionalMinSuccess()}, {"max_failure_rate", p.MaxFailureRate},
		{"max_inconclusive_rate", p.MaxInconclusiveRate}, {"max_timeout_rate", p.MaxTimeoutRate},
	}
	for _, item := range values {
		if item.value != nil && (!finite(*item.value) || *item.value < 0 || *item.value > 1) {
			return fmt.Errorf("quality policy %s must be between 0 and 1", item.name)
		}
	}
	if !finite(p.MaxP95MS) || p.MaxP95MS < 0 || !finite(p.MinRatePerSec) || p.MinRatePerSec < 0 {
		return errors.New("quality policy performance thresholds must be finite and non-negative")
	}
	targets := make([]string, 0, len(p.Targets))
	for target := range p.Targets {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	for _, target := range targets {
		minimum := p.Targets[target]
		if strings.TrimSpace(target) == "" || len(target) > 2048 || strings.IndexFunc(target, unicode.IsControl) >= 0 || !finite(minimum) || minimum < 0 || minimum > 1 {
			return errors.New("quality policy target thresholds require a target and a value between 0 and 1")
		}
	}
	return nil
}

func (p Policy) optionalMinSuccess() *float64 {
	if p.MinSuccessRate == 0 {
		return nil
	}
	return &p.MinSuccessRate
}

func finite(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }

func Evaluate(p Policy, s model.RunSummary) model.QualityReport {
	report := model.QualityReport{Passed: true}
	add := func(name string, passed bool, actual float64, operator string, expected float64) {
		report.Checks = append(report.Checks, model.QualityCheck{Name: name, Passed: passed, Actual: actual, Operator: operator, Expected: expected})
		report.Passed = report.Passed && passed
	}
	if p.MinProcessed > 0 {
		add("min_processed", s.Processed >= p.MinProcessed, float64(s.Processed), ">=", float64(p.MinProcessed))
	}
	if p.MinSuccessful > 0 {
		add("min_successful", s.Successful >= p.MinSuccessful, float64(s.Successful), ">=", float64(p.MinSuccessful))
	}
	denominator := math.Max(1, float64(s.Processed))
	if p.MinSuccessRate > 0 {
		add("min_success_rate", float64(s.Successful)/denominator >= p.MinSuccessRate, float64(s.Successful)/denominator, ">=", p.MinSuccessRate)
	}
	maximums := []struct {
		name   string
		value  *float64
		actual float64
	}{
		{"max_failure_rate", p.MaxFailureRate, float64(s.Failed+s.Unreliable) / denominator},
		{"max_inconclusive_rate", p.MaxInconclusiveRate, float64(s.Inconclusive) / denominator},
		{"max_timeout_rate", p.MaxTimeoutRate, float64(s.Timeouts) / math.Max(1, float64(s.Attempts))},
	}
	for _, threshold := range maximums {
		if threshold.value != nil {
			add(threshold.name, threshold.actual <= *threshold.value, threshold.actual, "<=", *threshold.value)
		}
	}
	if p.MaxP95MS > 0 {
		add("max_p95_ms", s.Successful > 0 && s.LatencyP95MS <= p.MaxP95MS, s.LatencyP95MS, "<=", p.MaxP95MS)
	}
	if p.MinRatePerSec > 0 {
		add("min_rate_per_sec", s.RatePerSec >= p.MinRatePerSec, s.RatePerSec, ">=", p.MinRatePerSec)
	}
	if p.RequirePreflight {
		passed := len(s.TargetHealth) > 0
		for _, health := range s.TargetHealth {
			passed = passed && health.Status == "ok"
		}
		actual := 0.0
		if passed {
			actual = 1
		}
		add("require_preflight", passed, actual, "==", 1)
	}
	targets := make([]string, 0, len(p.Targets))
	for target := range p.Targets {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	for _, target := range targets {
		minimum := p.Targets[target]
		stats, exists := s.Targets[target]
		add("target:"+target, exists && stats.SuccessRate >= minimum, stats.SuccessRate, ">=", minimum)
	}
	return report
}

type testSuite struct {
	XMLName  xml.Name `xml:"testsuite"`
	Name     string   `xml:"name,attr"`
	Tests    int      `xml:"tests,attr"`
	Failures int      `xml:"failures,attr"`
	Time     string   `xml:"time,attr"`
	Case     testCase `xml:"testcase"`
}

type testCase struct {
	Classname string   `xml:"classname,attr"`
	Name      string   `xml:"name,attr"`
	Time      string   `xml:"time,attr"`
	Failure   *failure `xml:"failure,omitempty"`
}

type failure struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

func JUnit(s model.RunSummary) ([]byte, error) {
	duration := fmt.Sprintf("%.3f", s.DurationMS/1000)
	suite := testSuite{Name: "relayprobe", Tests: 1, Time: duration, Case: testCase{Classname: "relayprobe.validation", Name: "quality gate", Time: duration}}
	if s.Quality != nil && !s.Quality.Passed {
		parts := make([]string, 0)
		for _, check := range s.Quality.Checks {
			if !check.Passed {
				parts = append(parts, fmt.Sprintf("%s actual=%g expected %s %g", check.Name, check.Actual, check.Operator, check.Expected))
			}
		}
		suite.Failures = 1
		suite.Case.Failure = &failure{Message: "quality gate failed", Text: strings.Join(parts, "; ")}
	}
	payload, err := xml.MarshalIndent(suite, "", "  ")
	return append([]byte(xml.Header), append(payload, '\n')...), err
}
