package buildinfo

import (
	"strings"
	"testing"
)

func TestUserAgentCannotInjectHeaders(t *testing.T) {
	old := Version
	defer func() { Version = old }()
	Version = "1.2\r\nInjected: yes"
	got := UserAgent()
	if strings.ContainsAny(got, "\r\n :") {
		t.Fatalf("unsafe user agent %q", got)
	}
}
