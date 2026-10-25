package metrics

import "testing"

func TestHistogram(t *testing.T) {
	h := NewHistogram(1, 1000)
	for i := 1; i <= 100; i++ {
		h.Observe(float64(i))
	}
	if h.Percentile(.5) != 50 || h.Percentile(.95) != 95 || h.Count() != 100 {
		t.Fatalf("p50=%v p95=%v n=%v", h.Percentile(.5), h.Percentile(.95), h.Count())
	}
}
