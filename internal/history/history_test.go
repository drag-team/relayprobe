package history

import (
	"testing"
	"time"

	"github.com/drag-team/netvex/internal/model"
)

func TestTrendsAndPoolDiversity(t *testing.T) {
	value := 80.0
	first := model.Result{ID: "a", Endpoint: "proxy:80", Protocol: model.ProtocolHTTP, Label: "vendor", Status: model.StatusFailed, CheckedAt: time.Unix(1, 0)}
	second := model.Result{ID: "a", Endpoint: "proxy:80", Protocol: model.ProtocolHTTP, Label: "vendor", Status: model.StatusOK, Successes: 1, CheckedAt: time.Unix(2, 0), Score: model.Score{Value: &value, MedianMS: 20}, Observations: []model.Observation{{Status: model.StatusOK, ExitIP: "8.8.8.8", Metadata: &model.ExitMetadata{CountryCode: "US", ASN: "AS15169"}}}}
	analyzer := New()
	analyzer.Add(first)
	analyzer.Add(second)
	trends := analyzer.Results()
	if len(trends) != 1 || trends[0].Checks != 2 || trends[0].Availability != 0.5 || trends[0].ConsecutiveSuccess != 1 || trends[0].UniqueExitIPs != 1 {
		t.Fatalf("trends=%+v", trends)
	}
	pools := Pools([]model.Result{second})
	if len(pools) != 1 || pools[0].UniqueSubnets != 1 || pools[0].UniqueASNs != 1 || pools[0].SuccessRate != 1 {
		t.Fatalf("pools=%+v", pools)
	}
}
