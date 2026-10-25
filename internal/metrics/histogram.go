package metrics

import "math"

type Histogram struct {
	width, max float64
	buckets    []uint64
	count      uint64
}

func NewHistogram(widthMS, maxMS float64) *Histogram {
	if widthMS <= 0 {
		widthMS = 1
	}
	if maxMS < widthMS {
		maxMS = widthMS
	}
	return &Histogram{width: widthMS, max: maxMS, buckets: make([]uint64, int(math.Ceil(maxMS/widthMS))+1)}
}
func (h *Histogram) Observe(v float64) {
	if v < 0 {
		v = 0
	}
	if v > h.max {
		v = h.max
	}
	i := int(v / h.width)
	h.buckets[i]++
	h.count++
}
func (h *Histogram) Percentile(q float64) float64 {
	if h.count == 0 {
		return 0
	}
	if q < 0 {
		q = 0
	}
	if q > 1 {
		q = 1
	}
	want := uint64(math.Ceil(q * float64(h.count)))
	if want < 1 {
		want = 1
	}
	var seen uint64
	for i, n := range h.buckets {
		seen += n
		if seen >= want {
			return float64(i) * h.width
		}
	}
	return h.max
}
func (h *Histogram) Count() uint64 { return h.count }
