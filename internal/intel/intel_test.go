package intel

import (
	"testing"

	"github.com/drag-team/netvex/internal/model"
)

func TestTargetResultsAndQuorumEvidence(t *testing.T) {
	observations := []model.Observation{
		{Target: "https://a.test/", Status: model.StatusOK, Timings: model.Timings{TotalMS: 10}},
		{Target: "https://b.test/", Status: model.StatusFailed, Code: "blocked"},
		{Target: "https://a.test/", Status: model.StatusOK, Timings: model.Timings{TotalMS: 20}},
		{Target: "https://b.test/", Status: model.StatusOK, Timings: model.Timings{TotalMS: 30}},
	}
	results := TargetResults(observations, 1, 2)
	if len(results) != 2 || !results[0].Qualified || results[0].MedianMS != 15 || results[1].Qualified || results[1].Status != model.StatusUnreliable {
		t.Fatalf("results=%+v", results)
	}
}

func TestRotationClassifications(t *testing.T) {
	makeObservations := func(exits ...string) []model.Observation {
		observations := make([]model.Observation, 0, len(exits))
		for _, exit := range exits {
			observations = append(observations, model.Observation{Status: model.StatusOK, ExitIP: exit, Metadata: &model.ExitMetadata{CountryCode: "US", ASN: "AS1"}})
		}
		return observations
	}
	if got := Rotation(makeObservations("1.1.1.1", "1.1.1.1", "1.1.1.1")); got.Classification != "stable" || got.UniqueExitIPs != 1 || !got.GeoConsistent {
		t.Fatalf("stable=%+v", got)
	}
	if got := Rotation(makeObservations("1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4")); got.Classification != "rotating" || got.ExitChanges != 3 {
		t.Fatalf("rotating=%+v", got)
	}
	if got := Rotation(makeObservations("1.1.1.1")); got.Classification != "insufficient" {
		t.Fatalf("insufficient=%+v", got)
	}
}
