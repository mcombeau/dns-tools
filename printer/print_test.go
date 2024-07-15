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

// func TestGetRecordDataString(t *testing.T) {
// 	tests := []struct {
// 		name    string
// 		record  dns.ResourceRecord
// 		want    string
// 		wantErr bool
// 	}{
// 		{
// 			name: "A record",
// 			record: dns.ResourceRecord{
// 				RType: dns.A,
// 				RData: net.IPv4(93, 184, 216, 34).To4(),
// 			},
// 			want:    "93.184.216.34",
// 			wantErr: false,
// 		},
// 		{
// 			name: "AAAA record",
// 			record: dns.ResourceRecord{
// 				RType: dns.AAAA,
// 				RData: net.ParseIP("2606:2800:220:1:248:1893:25c8:1946").To16(),
// 			},
// 			want:    "2606:2800:220:1:248:1893:25c8:1946",
// 			wantErr: false,
// 		},
// 		{
// 			name: "CNAME record",
// 			record: dns.ResourceRecord{
// 				RType: dns.CNAME,
// 				RData: []byte{5, 'a', 'l', 'i', 'a', 's', 3, 'c', 'o', 'm', 0},
// 			},
// 			want:    "alias.com.",
// 			wantErr: false,
// 		},
// 		{
// 			name: "PTR record",
// 			record: dns.ResourceRecord{
// 				RType: dns.PTR,
// 				RData: []byte{7, 'p', 't', 'r', 't', 'e', 's', 't', 3, 'c', 'o', 'm', 0},
// 			},
// 			want:    "ptrtest.com.",
// 			wantErr: false,
// 		},
// 		{
// 			name: "MX record",
// 			record: dns.ResourceRecord{
// 				RType: dns.MX,
// 				RData: append([]byte{0, 10}, []byte{4, 'm', 'a', 'i', 'l', 3, 'c', 'o', 'm', 0}...),
// 			},
// 			want:    "10 mail.com.",
// 			wantErr: false,
// 		},
// 		{
// 			name: "Unknown record type",
// 			record: dns.ResourceRecord{
// 				RType: 9999,
// 				RData: []byte{},
// 			},
// 			want:    "",
// 			wantErr: false,
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			result, err := getRecordDataString(tt.record)
// 			if tt.wantErr {
// 				assert.Error(t, err)
// 			} else {
// 				assert.NoError(t, err)
// 			}
// 			assert.Equal(t, tt.want, result)
// 		})
// 	}
// }
