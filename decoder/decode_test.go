package decoder

import (
	"testing"

	"github.com/mcombeau/dns-tools/dns"
)

func TestDecodeDNSMessage(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want *dns.Message
	}{
		{
			name: "Basic DNS message decoding",
			data: []byte{
				0x04, 0xd2, // ID: 1234
				0x85, 0x00, // Flags: 10000101 00000000
				0x00, 0x01, // Question Count: 1
				0x00, 0x01, // Answer RR Count: 1
				0x00, 0x00, // Nameserver RR Count: 0
				0x00, 0x00, // Additional RR Count: 0
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 1, // QType: 1 (A)
				0, 1, // QClass: 1 (IN)
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 1, // RType: 1
				0, 1, // RClass: 1
				0, 0, 1, 44, // TTL: 300
				0, 4, // RDLength: 4
				93, 184, 216, 34, // RData: 93.184.216.34
			},
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
					AnswerRRCount:     1,
					NameserverRRCount: 0,
					AdditionalRRCount: 0,
				},
				Questions: []dns.Question{
					{
						Name:   "example.com.",
						QType:  dns.A,
						QClass: dns.IN,
					},
				},
				Answers: []dns.ResourceRecord{
					{
						Name:     "example.com.",
						RType:    dns.A,
						RClass:   dns.IN,
						TTL:      300,
						RDLength: 4,
						RData: dns.RData{
							Raw:     []byte{93, 184, 216, 34},
							Decoded: "93.184.216.34",
						},
					},
				},

				NameServers: nil,
				Additionals: nil,
			},
		},
		{
			name: "Compressed DNS message decoding",
			data: []byte{
				0x04, 0xd2, // ID: 1234
				0x85, 0x00, // Flags: 10000101 00000000
				0x00, 0x01, // Question Count: 1
				0x00, 0x01, // Answer RR Count: 1
				0x00, 0x00, // Nameserver RR Count: 0
				0x00, 0x00, // Additional RR Count: 0
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 1, // QType: 1 (A)
				0, 1, // QClass: 1 (IN)
				0xc0, 12, // Pointer to: example.com
				0, 1, // RType: 1
				0, 1, // RClass: 1
				0, 0, 1, 44, // TTL: 300
				0, 4, // RDLength: 4
				93, 184, 216, 34, // RData: 93.184.216.34
			},
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
					AnswerRRCount:     1,
					NameserverRRCount: 0,
					AdditionalRRCount: 0,
				},
				Questions: []dns.Question{
					{
						Name:   "example.com.",
						QType:  dns.A,
						QClass: dns.IN,
					},
				},
				Answers: []dns.ResourceRecord{
					{
						Name:     "example.com.",
						RType:    dns.A,
						RClass:   dns.IN,
						TTL:      300,
						RDLength: 4,
						RData: dns.RData{
							Raw:     []byte{93, 184, 216, 34},
							Decoded: "93.184.216.34",
						},
					},
				},

				NameServers: nil,
				Additionals: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeDNSMessage(tt.data)

			if err != nil {
				t.Fatalf("decodeDNSMessage() error = %v, data = %v\n", err, tt.data)
			}

			assertHeader(t, got.Header, tt.want.Header, tt.data)
			assertFlags(t, got.Header.Flags, tt.want.Header.Flags, tt.data)

			if len(got.Questions) != len(tt.want.Questions) {
				t.Fatalf("decodeDNSMessage() Questions count mismatch got = %d, want = %d, data = %v\n", len(got.Questions), len(tt.want.Questions), tt.data)
			}
			for i := range got.Questions {
				assertQuestion(t, &got.Questions[i], &tt.want.Questions[i], tt.data)
			}

			if len(got.Answers) != len(tt.want.Answers) {
				t.Fatalf("decodeDNSMessage() Answers count mismatch got = %d, want = %d, data = %v\n", len(got.Answers), len(tt.want.Answers), tt.data)
			}
			for i := range got.Answers {
				assertRessourceRecord(t, &got.Answers[i], &tt.want.Answers[i], tt.data)
			}
		})
	}
}
