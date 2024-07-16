package decoder

import (
	"fmt"
	"testing"

	"github.com/mcombeau/go-dns-tools/dns"
	"github.com/stretchr/testify/assert"
)

func TestDecodeFlags(t *testing.T) {
	tests := []struct {
		name  string
		bytes []byte
		want  *dns.Flags
	}{
		{
			name:  "All flags off",
			bytes: []byte{0b00000000, 0b00000000},
			want: &dns.Flags{
				Response:           false,
				Opcode:             0,
				Authoritative:      false,
				Truncated:          false,
				RecursionDesired:   false,
				RecursionAvailable: false,
				DnssecOk:           false,
				AuthenticatedData:  false,
				CheckingDisabled:   false,
				ResponseCode:       0,
			},
		},
		{
			name:  "Response flag on",
			bytes: []byte{0b10000000, 0b00000000},
			want: &dns.Flags{
				Response:           true,
				Opcode:             0,
				Authoritative:      false,
				Truncated:          false,
				RecursionDesired:   false,
				RecursionAvailable: false,
				DnssecOk:           false,
				AuthenticatedData:  false,
				CheckingDisabled:   false,
				ResponseCode:       0,
			},
		},
		{
			name:  "Opcode set to 2",
			bytes: []byte{0b00010000, 0b00000000},
			want: &dns.Flags{
				Response:           false,
				Opcode:             2,
				Authoritative:      false,
				Truncated:          false,
				RecursionDesired:   false,
				RecursionAvailable: false,
				DnssecOk:           false,
				AuthenticatedData:  false,
				CheckingDisabled:   false,
				ResponseCode:       0,
			},
		},
		{
			name:  "Authoritative flag on",
			bytes: []byte{0b00000100, 0b00000000},
			want: &dns.Flags{
				Response:           false,
				Opcode:             0,
				Authoritative:      true,
				Truncated:          false,
				RecursionDesired:   false,
				RecursionAvailable: false,
				DnssecOk:           false,
				AuthenticatedData:  false,
				CheckingDisabled:   false,
				ResponseCode:       0,
			},
		},
		{
			name:  "Multiple flags on",
			bytes: []byte{0b10010111, 0b11110011},
			want: &dns.Flags{
				Response:           true,
				Opcode:             2,
				Authoritative:      true,
				Truncated:          true,
				RecursionDesired:   true,
				RecursionAvailable: true,
				DnssecOk:           true,
				AuthenticatedData:  true,
				CheckingDisabled:   true,
				ResponseCode:       3,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fmt.Printf("tt.want.Response = %t\n", tt.want.Response)
			got := decodeDNSFlags(tt.bytes)
			fmt.Printf("got.Response = %t\n", got.Response)
			assert.Equal(t, tt.want.Response, got.Response)
			assert.Equal(t, tt.want.Opcode, got.Opcode)
			assert.Equal(t, tt.want.Authoritative, got.Authoritative)
			assert.Equal(t, tt.want.Truncated, got.Truncated)
			assert.Equal(t, tt.want.RecursionDesired, got.RecursionDesired)
			assert.Equal(t, tt.want.RecursionAvailable, got.RecursionAvailable)
			assert.Equal(t, tt.want.DnssecOk, got.DnssecOk)
			assert.Equal(t, tt.want.AuthenticatedData, got.AuthenticatedData)
			assert.Equal(t, tt.want.CheckingDisabled, got.CheckingDisabled)
			assert.Equal(t, tt.want.ResponseCode, got.ResponseCode)
		})
	}
}
func TestDecodeDNSHeader(t *testing.T) {
	tests := []struct {
		name      string
		bytes     []byte
		wantError bool
		want      *dns.Message
	}{
		{
			name: "Basic header decoding",
			bytes: []byte{
				0x04, 0xd2, // ID: 1234
				0x85, 0x00, // Flags: 10000101 00000000
				0x00, 0x01, // Question Count: 1
				0x00, 0x02, // Answer RR Count: 2
				0x00, 0x03, // Nameserver RR Count: 3
				0x00, 0x04, // Additional RR Count: 4
			},
			wantError: false,
			want: &dns.Message{
				Header: &dns.Header{
					Id: 1234,
					Flags: &dns.Flags{
						Response:           true,
						Opcode:             0,
						Authoritative:      true,
						Truncated:          false,
						RecursionDesired:   true,
						RecursionAvailable: false,
						DnssecOk:           false,
						AuthenticatedData:  false,
						CheckingDisabled:   false,
						ResponseCode:       0,
					},
					QuestionCount:     1,
					AnswerRRCount:     2,
					NameserverRRCount: 3,
					AdditionalRRCount: 4,
				},
				Questions:   nil,
				Answers:     nil,
				NameServers: nil,
				Additionals: nil,
			},
		},
		{
			name: "RecursionAvailable flag on",
			bytes: []byte{
				0x04, 0xd2, // ID: 1234
				0x85, 0x80, // Flags: 10000101 10000000
				0x00, 0x01, // Question Count: 1
				0x00, 0x02, // Answer RR Count: 2
				0x00, 0x03, // Nameserver RR Count: 3
				0x00, 0x04, // Additional RR Count: 4
			},
			wantError: false,
			want: &dns.Message{
				Header: &dns.Header{
					Id: 1234,
					Flags: &dns.Flags{
						Response:           true,
						Opcode:             0,
						Authoritative:      true,
						Truncated:          false,
						RecursionDesired:   true,
						RecursionAvailable: true,
						DnssecOk:           false,
						AuthenticatedData:  false,
						CheckingDisabled:   false,
						ResponseCode:       0,
					},
					QuestionCount:     1,
					AnswerRRCount:     2,
					NameserverRRCount: 3,
					AdditionalRRCount: 4,
				},
				Questions:   nil,
				Answers:     nil,
				NameServers: nil,
				Additionals: nil,
			},
		},
		{
			name: "Header too small",
			bytes: []byte{
				0x04, 0xd2, // ID: 1234
				0x85, 0x80, // Flags: 10000101 10000000
				0x00, 0x01, // Question Count: 1
				0x00, 0x02, // Answer RR Count: 2
				0x00, 0x03, // Nameserver RR Count: 3
			},
			wantError: true,
			want:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeDNSHeader(tt.bytes)
			if tt.wantError {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want.Header.Id, got.Id)
			assert.Equal(t, tt.want.Header.Flags.Response, got.Flags.Response)
			assert.Equal(t, tt.want.Header.Flags.Opcode, got.Flags.Opcode)
			assert.Equal(t, tt.want.Header.Flags.Authoritative, got.Flags.Authoritative)
			assert.Equal(t, tt.want.Header.Flags.Truncated, got.Flags.Truncated)
			assert.Equal(t, tt.want.Header.Flags.RecursionDesired, got.Flags.RecursionDesired)
			assert.Equal(t, tt.want.Header.Flags.RecursionAvailable, got.Flags.RecursionAvailable)
			assert.Equal(t, tt.want.Header.Flags.DnssecOk, got.Flags.DnssecOk)
			assert.Equal(t, tt.want.Header.Flags.AuthenticatedData, got.Flags.AuthenticatedData)
			assert.Equal(t, tt.want.Header.Flags.CheckingDisabled, got.Flags.CheckingDisabled)
			assert.Equal(t, tt.want.Header.Flags.ResponseCode, got.Flags.ResponseCode)
			assert.Equal(t, tt.want.Header.QuestionCount, got.QuestionCount)
			assert.Equal(t, tt.want.Header.AnswerRRCount, got.AnswerRRCount)
			assert.Equal(t, tt.want.Header.NameserverRRCount, got.NameserverRRCount)
			assert.Equal(t, tt.want.Header.AdditionalRRCount, got.AdditionalRRCount)
		})
	}
}
