package intel

import (
	"math"
	"net/netip"
	"sort"

	"github.com/drag-team/relayprobe/internal/model"
)

func TargetResults(observations []model.Observation, minSuccessRate float64, expectedPerTarget int, expectedTargets ...string) []model.TargetResult {
	type aggregate struct {
		result    model.TargetResult
		latencies []float64
		last      model.Status
	}
	byTarget := make(map[string]*aggregate)
	for _, target := range expectedTargets {
		byTarget[target] = &aggregate{result: model.TargetResult{Target: target}, last: model.StatusInterrupted}
	}
	for _, observation := range observations {
		target := observation.Target
		item := byTarget[target]
		if item == nil {
			item = &aggregate{result: model.TargetResult{Target: target}}
			byTarget[target] = item
		}
		item.result.Attempts++
		item.last = observation.Status
		item.result.LastCode = observation.Code
		if observation.Status == model.StatusOK {
			item.result.Successes++
			item.latencies = append(item.latencies, observation.Timings.TotalMS)
		}
	}
	results := make([]model.TargetResult, 0, len(byTarget))
	for _, item := range byTarget {
		basis := item.result.Attempts
		if expectedPerTarget > basis {
			basis = expectedPerTarget
		}
		item.result.Required = int(math.Ceil(float64(basis) * minSuccessRate))
		if item.result.Attempts > 0 {
			item.result.SuccessRate = float64(item.result.Successes) / float64(item.result.Attempts)
		}
		item.result.Qualified = item.result.Successes >= item.result.Required
		switch {
		case item.result.Qualified:
			item.result.Status = model.StatusOK
		case item.result.Successes > 0:
			item.result.Status = model.StatusUnreliable
		default:
			item.result.Status = item.last
		}
		if len(item.latencies) > 0 {
			sort.Float64s(item.latencies)
			item.result.MedianMS = percentile(item.latencies, 0.5)
		}
		results = append(results, item.result)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Target < results[j].Target })
	return results
}

func Rotation(observations []model.Observation) model.RotationProfile {
	exits := make([]string, 0, len(observations))
	counts := make(map[string]int)
	countries := make(map[string]struct{})
	asns := make(map[string]struct{})
	for _, observation := range observations {
		if observation.Status != model.StatusOK {
			continue
		}
		address, err := netip.ParseAddr(observation.ExitIP)
		if err != nil {
			continue
		}
		exit := address.Unmap().String()
		exits = append(exits, exit)
		counts[exit]++
		if observation.Metadata != nil {
			if observation.Metadata.CountryCode != "" {
				countries[observation.Metadata.CountryCode] = struct{}{}
			}
			if observation.Metadata.ASN != "" {
				asns[observation.Metadata.ASN] = struct{}{}
			}
		}
	}
	profile := model.RotationProfile{
		Classification:  "unavailable",
		ObservedSamples: len(exits),
		UniqueExitIPs:   len(counts),
		Countries:       sortedKeys(countries),
		ASNs:            sortedKeys(asns),
		GeoConsistent:   len(countries) <= 1 && len(asns) <= 1 && len(exits) > 0,
	}
	if len(exits) == 0 {
		return profile
	}
	for exit, count := range counts {
		if count > counts[profile.DominantExitIP] || count == counts[profile.DominantExitIP] && exit < profile.DominantExitIP {
			profile.DominantExitIP = exit
		}
	}
	profile.DominantShare = float64(counts[profile.DominantExitIP]) / float64(len(exits))
	for i := 1; i < len(exits); i++ {
		if exits[i] != exits[i-1] {
			profile.ExitChanges++
		}
	}
	if len(exits) > 1 {
		profile.ChangeRate = float64(profile.ExitChanges) / float64(len(exits)-1)
	}
	switch {
	case len(exits) < 2:
		profile.Classification = "insufficient"
	case len(counts) == 1:
		profile.Classification = "stable"
	case profile.ChangeRate >= 0.8 && float64(len(counts))/float64(len(exits)) >= 0.8:
		profile.Classification = "rotating"
	case profile.DominantShare >= 0.8:
		profile.Classification = "sticky"
	default:
		profile.Classification = "mixed"
	}
	return profile
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	return keys
}

func percentile(values []float64, quantile float64) float64 {
	if len(values) == 0 {
		return 0
	}
	if len(values) == 1 {
		return values[0]
	}
	position := quantile * float64(len(values)-1)
	lower := int(math.Floor(position))
	upper := int(math.Ceil(position))
	if lower == upper {
		return values[lower]
	}
	return values[lower] + (values[upper]-values[lower])*(position-float64(lower))
}
