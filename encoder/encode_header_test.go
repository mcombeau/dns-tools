package encoder

import (
	"bytes"
	"testing"

	"github.com/mcombeau/go-dns-tools/dns"
	"github.com/stretchr/testify/assert"
)

func TestEncodeFlags(t *testing.T) {
	tests := []struct {
		name  string
		flags *dns.Flags
		want  []byte
	}{
		{
			name: "All flags off",
			flags: &dns.Flags{
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
			want: []byte{0b00000000, 0b00000000},
		},
		{
			name: "Response flag on",
			flags: &dns.Flags{
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
			want: []byte{0b10000000, 0b00000000},
		},
		{
			name: "Opcode set to 2",
			flags: &dns.Flags{
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
			want: []byte{0b00010000, 0b00000000},
		},
		{
			name: "Authoritative flag on",
			flags: &dns.Flags{
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
			want: []byte{0b00000100, 0b00000000},
		},
		{
			name: "Multiple flags on",
			flags: &dns.Flags{
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
			want: []byte{0b10010111, 0b11110011},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := encodeDNSFlags(tt.flags)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestEncodeDNSHeader(t *testing.T) {
	tests := []struct {
		name string
		msg  *dns.Message
		want []byte
	}{
		{
			name: "Basic header encoding",
			msg: &dns.Message{
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
			want: []byte{
				0x04, 0xd2, // ID: 1234
				0x85, 0x00, // Flags: 10000101 00000000
				0x00, 0x01, // Question Count: 1
				0x00, 0x02, // Answer RR Count: 2
				0x00, 0x03, // Nameserver RR Count: 3
				0x00, 0x04, // Additional RR Count: 4
			},
		},
		{
			name: "RecursionAvailable flag on",
			msg: &dns.Message{
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
			want: []byte{
				0x04, 0xd2, // ID: 1234
				0x85, 0x80, // Flags: 10000101 10000000
				0x00, 0x01, // Question Count: 1
				0x00, 0x02, // Answer RR Count: 2
				0x00, 0x03, // Nameserver RR Count: 3
				0x00, 0x04, // Additional RR Count: 4
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			encodeDNSHeader(&buf, tt.msg)
			assert.Equal(t, tt.want, buf.Bytes())
		})
	}
}
