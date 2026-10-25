package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/drag-team/relayprobe/internal/model"
)

type Format string

const (
	FormatTable Format = "table"
	FormatJSONL Format = "jsonl"
	FormatCSV   Format = "csv"
	FormatTXT   Format = "txt"
)

func ParseFormat(s string) (Format, error) {
	f := Format(strings.ToLower(s))
	switch f {
	case FormatTable, FormatJSONL, FormatCSV, FormatTXT:
		return f, nil
	default:
		return "", fmt.Errorf("unsupported output format %q", s)
	}
}

type Writer struct {
	out    io.Writer
	format Format
	color  bool
	header bool
	csv    *csv.Writer
	json   *json.Encoder
}

func New(out io.Writer, format Format, color bool) *Writer {
	w := &Writer{out: out, format: format, color: color}
	if format == FormatCSV {
		w.csv = csv.NewWriter(out)
	} else if format == FormatJSONL {
		w.json = json.NewEncoder(out)
	}
	return w
}

func (w *Writer) WriteResult(r model.Result) error {
	switch w.format {
	case FormatJSONL:
		return w.json.Encode(r)
	case FormatCSV:
		if !w.header {
			if e := w.csv.Write([]string{"id", "proxy", "endpoint", "protocol", "status", "attempts", "successes", "required_successes", "success_rate", "score", "confidence", "median_ms", "last_stage", "last_code", "last_message", "exit_ip", "anonymity", "body_bytes", "throughput_kbps", "country_code", "country", "city", "asn", "organization", "network_type", "checked_at"}); e != nil {
				return e
			}
			w.header = true
		}
		stage, code, msg, exitIP, anonymity, bodyBytes, throughput := "", "", "", "", "", "", ""
		countryCode, country, city, asn, organization, networkType := "", "", "", "", "", ""
		if len(r.Observations) > 0 {
			last := r.Observations[len(r.Observations)-1]
			stage, code, msg = string(last.Stage), last.Code, last.Message
			measurement := last
			for i := len(r.Observations) - 1; i >= 0; i-- {
				if r.Observations[i].Status == model.StatusOK {
					measurement = r.Observations[i]
					break
				}
			}
			exitIP = measurement.ExitIP
			anonymity = measurement.Anonymity
			bodyBytes = strconv.FormatInt(measurement.BodyBytes, 10)
			throughput = strconv.FormatFloat(measurement.ThroughputKBPS, 'f', 1, 64)
			if measurement.Metadata != nil {
				countryCode, country, city = measurement.Metadata.CountryCode, measurement.Metadata.Country, measurement.Metadata.City
				asn, organization, networkType = measurement.Metadata.ASN, measurement.Metadata.Organization, measurement.Metadata.NetworkType
			}
		}
		scoreText := ""
		if r.Score.Value != nil {
			scoreText = strconv.FormatFloat(*r.Score.Value, 'f', 1, 64)
		}
		return w.csv.Write([]string{r.ID, r.Proxy, r.Endpoint, string(r.Protocol), string(r.Status), strconv.Itoa(r.Attempts), strconv.Itoa(r.Successes), strconv.Itoa(r.RequiredSuccesses), strconv.FormatFloat(r.Score.SuccessRate, 'f', 4, 64), scoreText, r.Score.Confidence, fmt.Sprintf("%.3f", r.Score.MedianMS), stage, code, msg, exitIP, anonymity, bodyBytes, throughput, countryCode, country, city, asn, organization, networkType, r.CheckedAt.Format("2006-01-02T15:04:05.999999999Z07:00")})
	case FormatTXT:
		_, e := fmt.Fprintln(w.out, r.Proxy)
		return e
	default:
		if !w.header {
			fmt.Fprintln(w.out, "STATUS        PROTOCOL  SCORE  SUCCESS  NEED  MEDIAN    PROXY")
			w.header = true
		}
		scoreText := "—"
		if r.Score.Value != nil {
			scoreText = fmt.Sprintf("%5.1f", *r.Score.Value)
		}
		med := "—"
		if r.Successes > 0 {
			med = fmt.Sprintf("%.0fms", r.Score.MedianMS)
		}
		status := fmt.Sprintf("%-13s", r.Status)
		if w.color {
			switch r.Status {
			case model.StatusOK:
				status = "\x1b[32m" + status + "\x1b[0m"
			case model.StatusTimeout:
				status = "\x1b[33m" + status + "\x1b[0m"
			case model.StatusInconclusive:
				status = "\x1b[36m" + status + "\x1b[0m"
			case model.StatusUnreliable:
				status = "\x1b[35m" + status + "\x1b[0m"
			default:
				status = "\x1b[31m" + status + "\x1b[0m"
			}
		}
		_, e := fmt.Fprintf(w.out, "%s %-9s %5s  %3d/%-3d  %4d  %-9s %s\n", status, r.Protocol, scoreText, r.Successes, r.Attempts, r.RequiredSuccesses, med, r.Proxy)
		return e
	}
}

func (w *Writer) Flush() error {
	if w.csv != nil {
		w.csv.Flush()
		return w.csv.Error()
	}
	return nil
}

func WriteDetailed(out io.Writer, r model.Result) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(b))
	return err
}
