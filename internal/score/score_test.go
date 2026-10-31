package score

import (
	"github.com/drag-team/netvex/internal/model"
	"testing"
)

func TestScoreEvidenceAndConfidence(t *testing.T) {
	obs := []model.Observation{}
	for i := 0; i < 5; i++ {
		s := model.StatusOK
		if i == 4 {
			s = model.StatusFailed
		}
		obs = append(obs, model.Observation{Status: s, Timings: model.Timings{TotalMS: float64(100 + i*10)}})
	}
	got := Calculate(obs)
	if got.Value == nil || *got.Value <= 0 || *got.Value >= 100 || got.Confidence != "medium" || got.SuccessRate != .8 {
		t.Fatalf("unexpected score: %+v", got)
	}
}
func TestScoreNoMeasurements(t *testing.T) {
	if got := Calculate(nil); got.Value != nil || got.Confidence != "none" {
		t.Fatalf("%+v", got)
	}
}

func TestScoreRequiresRepeatedEvidence(t *testing.T) {
	got := Calculate([]model.Observation{{Status: model.StatusOK, Timings: model.Timings{TotalMS: 10}}})
	if got.Value != nil || got.Confidence != "insufficient" {
		t.Fatalf("%+v", got)
	}
}
