package history

import (
	"math"
	"net/netip"
	"sort"
	"time"

	"github.com/drag-team/netvex/internal/model"
)

type Trend struct {
	ID                 string         `json:"id"`
	Endpoint           string         `json:"endpoint"`
	Protocol           model.Protocol `json:"protocol"`
	Label              string         `json:"label,omitempty"`
	Checks             int            `json:"checks"`
	SuccessfulChecks   int            `json:"successful_checks"`
	Availability       float64        `json:"availability"`
	ConsecutiveSuccess int            `json:"consecutive_success"`
	StatusChanges      int            `json:"status_changes"`
	FirstSeen          time.Time      `json:"first_seen"`
	LastSeen           time.Time      `json:"last_seen"`
	LastStatus         model.Status   `json:"last_status"`
	MedianLatencyMS    float64        `json:"median_latency_ms,omitempty"`
	UniqueExitIPs      int            `json:"unique_exit_ips"`
	Countries          []string       `json:"countries,omitempty"`
	ASNs               []string       `json:"asns,omitempty"`
	latencies          []float64
	exits              map[string]struct{}
	countries          map[string]struct{}
	asns               map[string]struct{}
}

type Analyzer struct {
	trends map[string]*Trend
}

func New() *Analyzer {
	return &Analyzer{trends: make(map[string]*Trend)}
}

func (a *Analyzer) Add(result model.Result) {
	trend := a.trends[result.ID]
	if trend == nil {
		trend = &Trend{ID: result.ID, Endpoint: result.Endpoint, Protocol: result.Protocol, Label: result.Label, exits: make(map[string]struct{}), countries: make(map[string]struct{}), asns: make(map[string]struct{})}
		a.trends[result.ID] = trend
	}
	if trend.Checks == 0 || result.CheckedAt.Before(trend.FirstSeen) {
		trend.FirstSeen = result.CheckedAt
	}
	if trend.Checks > 0 && result.Status != trend.LastStatus {
		trend.StatusChanges++
	}
	trend.Checks++
	trend.LastSeen = result.CheckedAt
	trend.LastStatus = result.Status
	if result.Status == model.StatusOK {
		trend.SuccessfulChecks++
		trend.ConsecutiveSuccess++
	} else {
		trend.ConsecutiveSuccess = 0
	}
	if result.Successes > 0 {
		trend.latencies = append(trend.latencies, result.Score.MedianMS)
	}
	for _, observation := range result.Observations {
		if observation.Status != model.StatusOK {
			continue
		}
		if address, err := netip.ParseAddr(observation.ExitIP); err == nil {
			trend.exits[address.Unmap().String()] = struct{}{}
		}
		if observation.Metadata != nil {
			if observation.Metadata.CountryCode != "" {
				trend.countries[observation.Metadata.CountryCode] = struct{}{}
			}
			if observation.Metadata.ASN != "" {
				trend.asns[observation.Metadata.ASN] = struct{}{}
			}
		}
	}
}

func (a *Analyzer) Results() []Trend {
	results := make([]Trend, 0, len(a.trends))
	for _, source := range a.trends {
		trend := *source
		trend.Availability = float64(trend.SuccessfulChecks) / float64(trend.Checks)
		trend.UniqueExitIPs = len(trend.exits)
		trend.Countries = keys(trend.countries)
		trend.ASNs = keys(trend.asns)
		if len(trend.latencies) > 0 {
			sort.Float64s(trend.latencies)
			trend.MedianLatencyMS = percentile(trend.latencies, 0.5)
		}
		trend.latencies, trend.exits, trend.countries, trend.asns = nil, nil, nil, nil
		results = append(results, trend)
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].Availability != results[j].Availability {
			return results[i].Availability > results[j].Availability
		}
		return results[i].Endpoint < results[j].Endpoint
	})
	return results
}

type Pool struct {
	Label            string   `json:"label"`
	Proxies          int      `json:"proxies"`
	Successful       int      `json:"successful"`
	SuccessRate      float64  `json:"success_rate"`
	UniqueExitIPs    int      `json:"unique_exit_ips"`
	UniqueSubnets    int      `json:"unique_subnets"`
	UniqueASNs       int      `json:"unique_asns"`
	Countries        []string `json:"countries,omitempty"`
	ASNConcentration float64  `json:"largest_asn_share,omitempty"`
	MedianLatencyMS  float64  `json:"median_latency_ms,omitempty"`
	MedianScore      float64  `json:"median_score,omitempty"`
	exits            map[string]struct{}
	subnets          map[string]struct{}
	asnCounts        map[string]int
	countries        map[string]struct{}
	latencies        []float64
	scores           []float64
}

func Pools(results []model.Result) []Pool {
	groups := make(map[string]*Pool)
	for _, result := range results {
		label := result.Label
		if label == "" {
			label = "default"
		}
		pool := groups[label]
		if pool == nil {
			pool = &Pool{Label: label, exits: make(map[string]struct{}), subnets: make(map[string]struct{}), asnCounts: make(map[string]int), countries: make(map[string]struct{})}
			groups[label] = pool
		}
		pool.Proxies++
		if result.Status == model.StatusOK {
			pool.Successful++
		}
		if result.Successes > 0 {
			pool.latencies = append(pool.latencies, result.Score.MedianMS)
		}
		if result.Score.Value != nil {
			pool.scores = append(pool.scores, *result.Score.Value)
		}
		seenASNs := make(map[string]struct{})
		for _, observation := range result.Observations {
			if observation.Status != model.StatusOK {
				continue
			}
			if address, err := netip.ParseAddr(observation.ExitIP); err == nil {
				address = address.Unmap()
				pool.exits[address.String()] = struct{}{}
				bits := 48
				if address.Is4() {
					bits = 24
				}
				pool.subnets[netip.PrefixFrom(address, bits).Masked().String()] = struct{}{}
			}
			if observation.Metadata != nil {
				if observation.Metadata.CountryCode != "" {
					pool.countries[observation.Metadata.CountryCode] = struct{}{}
				}
				if observation.Metadata.ASN != "" {
					seenASNs[observation.Metadata.ASN] = struct{}{}
				}
			}
		}
		for asn := range seenASNs {
			pool.asnCounts[asn]++
		}
	}
	pools := make([]Pool, 0, len(groups))
	for _, source := range groups {
		pool := *source
		pool.SuccessRate = float64(pool.Successful) / float64(pool.Proxies)
		pool.UniqueExitIPs = len(pool.exits)
		pool.UniqueSubnets = len(pool.subnets)
		pool.UniqueASNs = len(pool.asnCounts)
		pool.Countries = keys(pool.countries)
		largestASN := 0
		for _, count := range pool.asnCounts {
			if count > largestASN {
				largestASN = count
			}
		}
		if pool.Proxies > 0 {
			pool.ASNConcentration = float64(largestASN) / float64(pool.Proxies)
		}
		if len(pool.latencies) > 0 {
			sort.Float64s(pool.latencies)
			pool.MedianLatencyMS = percentile(pool.latencies, 0.5)
		}
		if len(pool.scores) > 0 {
			sort.Float64s(pool.scores)
			pool.MedianScore = percentile(pool.scores, 0.5)
		}
		pool.exits, pool.subnets, pool.asnCounts, pool.countries, pool.latencies, pool.scores = nil, nil, nil, nil, nil, nil
		pools = append(pools, pool)
	}
	sort.Slice(pools, func(i, j int) bool { return pools[i].Label < pools[j].Label })
	return pools
}

func keys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func percentile(values []float64, quantile float64) float64 {
	if len(values) == 1 {
		return values[0]
	}
	position := quantile * float64(len(values)-1)
	lower, upper := int(math.Floor(position)), int(math.Ceil(position))
	if lower == upper {
		return values[lower]
	}
	return values[lower] + (values[upper]-values[lower])*(position-float64(lower))
}
