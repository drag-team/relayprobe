package buildinfo

import "strings"

var (
	Version = "0.7.0-dev"
	Commit  = "unknown"
	Date    = "unknown"
)

func UserAgent() string {
	var b strings.Builder
	b.WriteString("RelayProbe/")
	for _, r := range Version {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._-+", r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}
