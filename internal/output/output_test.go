package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"github.com/drag-team/relayprobe/internal/model"
	"strings"
	"testing"
)

func sample() model.Result {
	v := 91.2
	return model.Result{ID: "id", Proxy: "http://u:***@host:80", Endpoint: "host:80", Protocol: model.ProtocolHTTP, Status: model.StatusOK, Attempts: 2, Successes: 2, Score: model.Score{Value: &v, Confidence: "low", MedianMS: 12.3}}
}
func TestMachineFormats(t *testing.T) {
	for _, f := range []Format{FormatJSONL, FormatCSV, FormatTXT} {
		var b bytes.Buffer
		w := New(&b, f, true)
		if err := w.WriteResult(sample()); err != nil {
			t.Fatal(err)
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(b.String(), "\x1b[") {
			t.Fatalf("ANSI in %s", f)
		}
		if f == FormatJSONL {
			var v map[string]any
			if json.Unmarshal(bytes.TrimSpace(b.Bytes()), &v) != nil {
				t.Fatal("invalid JSON")
			}
		}
		if f == FormatCSV {
			if _, err := csv.NewReader(&b).ReadAll(); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestCSVUsesLatestSuccessfulMeasurement(t *testing.T) {
	r := sample()
	r.Observations = []model.Observation{
		{Status: model.StatusOK, Stage: model.StageComplete, ExitIP: "8.8.8.8", ThroughputKBPS: 1250, Metadata: &model.ExitMetadata{CountryCode: "US"}},
		{Status: model.StatusTimeout, Stage: model.StageResponse, Code: "body_read"},
	}
	var b bytes.Buffer
	w := New(&b, FormatCSV, false)
	if err := w.WriteResult(r); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&b).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	header, row := rows[0], rows[1]
	values := make(map[string]string, len(header))
	for i, name := range header {
		values[name] = row[i]
	}
	if values["last_code"] != "body_read" || values["exit_ip"] != "8.8.8.8" || values["country_code"] != "US" || values["throughput_kbps"] != "1250.0" {
		t.Fatalf("unexpected CSV values: %+v", values)
	}
}
