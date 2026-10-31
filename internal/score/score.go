package score

import (
	"math"
	"sort"

	"github.com/drag-team/netvex/internal/model"
)

func Calculate(obs []model.Observation) model.Score {
	if len(obs) == 0 {
		return model.Score{Confidence: "none", Reason: "no measurements"}
	}
	latencies := make([]float64, 0, len(obs))
	successes := 0
	for _, o := range obs {
		if o.Status == model.StatusOK {
			successes++
			latencies = append(latencies, o.Timings.TotalMS)
		}
	}
	rate := float64(successes) / float64(len(obs))
	confidence := "low"
	if len(obs) >= 5 {
		confidence = "medium"
	}
	if len(obs) >= 10 {
		confidence = "high"
	}
	if len(obs) < 2 {
		return model.Score{Confidence: "insufficient", Reason: "at least two measurements are required for a numeric score", SuccessRate: rate}
	}
	if successes == 0 {
		z := 0.0
		return model.Score{Value: &z, Confidence: confidence, Reason: "no successful requests", SuccessRate: rate}
	}
	sort.Float64s(latencies)
	median := percentile(latencies, .5)
	p95 := percentile(latencies, .95)
	jitter := p95 - median
	latencyComponent := 100 * math.Exp(-median/1500)
	jitterComponent := 100 * math.Exp(-jitter/1000)
	value := 100 * (0.65*rate + 0.25*(latencyComponent/100) + 0.10*(jitterComponent/100))
	value = math.Round(math.Max(0, math.Min(100, value))*10) / 10
	reason := "weighted: 65% success rate, 25% median latency decay, 10% jitter decay"
	return model.Score{Value: &value, Confidence: confidence, Reason: reason, SuccessRate: rate, MedianMS: median, JitterMS: jitter}
}

func percentile(v []float64, q float64) float64 {
	if len(v) == 0 {
		return 0
	}
	if len(v) == 1 {
		return v[0]
	}
	pos := q * float64(len(v)-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	if lo == hi {
		return v[lo]
	}
	return v[lo] + (v[hi]-v[lo])*(pos-float64(lo))
}
