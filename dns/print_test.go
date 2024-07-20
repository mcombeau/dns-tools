package dns

import (
	"testing"
)

func TestGetFlagString(t *testing.T) {
	tests := []struct {
		name string
		data *Flags
		want string
	}{
		{
			name: "No flags set",
			data: &Flags{
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
			data: &Flags{
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
			data: &Flags{
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
			data: &Flags{
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
			data: &Flags{
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
			got := getFlagString(tt.data)

			if got != tt.want {
				t.Errorf("getFlagString() got = %s, want = %s\n", got, tt.want)
			}
		})
	}
}
