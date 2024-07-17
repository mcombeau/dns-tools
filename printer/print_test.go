package printer

import (
	"testing"

	"github.com/mcombeau/go-dns-tools/dns"
	"github.com/stretchr/testify/assert"
)

func TestGetFlagString(t *testing.T) {
	tests := []struct {
		name  string
		flags *dns.Flags
		want  string
	}{
		{
			name: "No flags set",
			flags: &dns.Flags{
				Response:           false,
				Authoritative:      false,
				Truncated:          false,
				RecursionDesired:   false,
				RecursionAvailable: false,
				DnssecOk:           false,
				AuthenticatedData:  false,
				CheckingDisabled:   false,
			},
			want: "",
		},
		{
			name: "QR flag set",
			flags: &dns.Flags{
				Response:           true,
				Authoritative:      false,
				Truncated:          false,
				RecursionDesired:   false,
				RecursionAvailable: false,
				DnssecOk:           false,
				AuthenticatedData:  false,
				CheckingDisabled:   false,
			},
			want: "qr",
		},
		{
			name: "AA flag set",
			flags: &dns.Flags{
				Response:           false,
				Authoritative:      true,
				Truncated:          false,
				RecursionDesired:   false,
				RecursionAvailable: false,
				DnssecOk:           false,
				AuthenticatedData:  false,
				CheckingDisabled:   false,
			},
			want: "aa",
		},
		{
			name: "All flags set",
			flags: &dns.Flags{
				Response:           true,
				Authoritative:      true,
				Truncated:          true,
				RecursionDesired:   true,
				RecursionAvailable: true,
				DnssecOk:           true,
				AuthenticatedData:  true,
				CheckingDisabled:   true,
			},
			want: "qr aa tc rd ra do ad cd",
		},
		{
			name: "Mixed flags set",
			flags: &dns.Flags{
				Response:           true,
				Authoritative:      false,
				Truncated:          true,
				RecursionDesired:   false,
				RecursionAvailable: true,
				DnssecOk:           false,
				AuthenticatedData:  true,
				CheckingDisabled:   false,
			},
			want: "qr tc ra ad",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getFlagString(tt.flags)
			assert.Equal(t, tt.want, result)
		})
	}
}
