package decoder

import (
	"testing"

	"github.com/mcombeau/dns-tools/dns"
	"github.com/stretchr/testify/assert"
)

func TestDecodeDNSMessage(t *testing.T) {
	tests := []struct {
		name  string
		bytes []byte
		want  *dns.Message
	}{
		{
			name: "Basic DNS message decoding",
			bytes: []byte{
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
			bytes: []byte{
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
			got, err := DecodeDNSMessage(tt.bytes)

			assert.NoError(t, err)

			assert.Equal(t, tt.want.Header.Id, got.Header.Id)

			assert.Equal(t, tt.want.Header.Flags.Response, got.Header.Flags.Response)
			assert.Equal(t, tt.want.Header.Flags.Opcode, got.Header.Flags.Opcode)
			assert.Equal(t, tt.want.Header.Flags.Authoritative, got.Header.Flags.Authoritative)
			assert.Equal(t, tt.want.Header.Flags.Truncated, got.Header.Flags.Truncated)
			assert.Equal(t, tt.want.Header.Flags.RecursionDesired, got.Header.Flags.RecursionDesired)
			assert.Equal(t, tt.want.Header.Flags.RecursionAvailable, got.Header.Flags.RecursionAvailable)
			assert.Equal(t, tt.want.Header.Flags.DnssecOk, got.Header.Flags.DnssecOk)
			assert.Equal(t, tt.want.Header.Flags.AuthenticatedData, got.Header.Flags.AuthenticatedData)
			assert.Equal(t, tt.want.Header.Flags.CheckingDisabled, got.Header.Flags.CheckingDisabled)
			assert.Equal(t, tt.want.Header.Flags.ResponseCode, got.Header.Flags.ResponseCode)

			assert.Equal(t, tt.want.Header.QuestionCount, got.Header.QuestionCount)
			assert.Equal(t, tt.want.Header.AnswerRRCount, got.Header.AnswerRRCount)
			assert.Equal(t, tt.want.Header.NameserverRRCount, got.Header.NameserverRRCount)
			assert.Equal(t, tt.want.Header.AdditionalRRCount, got.Header.AdditionalRRCount)

			assert.Equal(t, tt.want.Questions[0].Name, got.Questions[0].Name)
			assert.Equal(t, tt.want.Questions[0].QClass, got.Questions[0].QClass)
			assert.Equal(t, tt.want.Questions[0].QType, got.Questions[0].QType)

			assert.Equal(t, tt.want.Answers[0].Name, got.Answers[0].Name)
			assert.Equal(t, tt.want.Answers[0].RType, got.Answers[0].RType)
			assert.Equal(t, tt.want.Answers[0].RClass, got.Answers[0].RClass)
			assert.Equal(t, tt.want.Answers[0].TTL, got.Answers[0].TTL)
			assert.Equal(t, tt.want.Answers[0].RDLength, got.Answers[0].RDLength)
			assert.Equal(t, tt.want.Answers[0].RData.Raw, got.Answers[0].RData.Raw)
			assert.Equal(t, tt.want.Answers[0].RData.Decoded, got.Answers[0].RData.Decoded)
		})
	}
}

// func TestDecodeCompressedDNSMessage(t *testing.T) {
// 	mockResponse, err := testutils.MockDNSCompressedResponse()
// 	if err != nil {
// 		t.Fatalf("Failed to create mock response: %v\n", err)
// 	}

// 	var unpackedMockResponse dns.Msg
// 	err = unpackedMockResponse.Unpack(mockResponse)

// 	if err != nil {
// 		t.Fatalf("Failed to unpack mock response: %v\n", err)
// 	}

// 	want := unpackedMockResponse
// 	got, err := DecodeDNSMessage(mockResponse)

// 	assert.NoError(t, err)

// 	checkHeader(t, want, *got)
// 	checkQuestions(t, want.Question, got.Questions)
// 	checkResourceRecord(t, want.Answer, got.Answers)
// 	checkResourceRecord(t, want.Ns, got.NameServers)
// 	checkResourceRecord(t, want.Extra, got.Additionals)
// }

// func checkHeader(t *testing.T, want dns.Msg, got dnstypes.Message) {
// 	assert.Equal(t, want.Id, got.Header.Id)
// 	assert.Equal(t, want.Response, got.Header.Flags.Response)
// 	assert.Equal(t, int(want.Opcode), int(got.Header.Flags.Opcode))
// 	assert.Equal(t, want.Authoritative, got.Header.Flags.Authoritative)
// 	assert.Equal(t, want.Truncated, got.Header.Flags.Truncated)
// 	assert.Equal(t, want.RecursionDesired, got.Header.Flags.RecursionDesired)
// 	assert.Equal(t, want.RecursionAvailable, got.Header.Flags.RecursionAvailable)
// 	assert.True(t, got.Header.Flags.DnssecOk)
// 	assert.Equal(t, want.AuthenticatedData, got.Header.Flags.AuthenticatedData)
// 	assert.Equal(t, want.CheckingDisabled, got.Header.Flags.CheckingDisabled)
// 	assert.Equal(t, int(want.Rcode), int(got.Header.Flags.ResponseCode))
// 	assert.Equal(t, uint16(len(want.Question)), got.Header.QuestionCount)
// 	assert.Equal(t, uint16(len(want.Answer)), got.Header.AnswerRRCount)
// 	assert.Equal(t, uint16(len(want.Ns)), got.Header.NameserverRRCount)
// 	assert.Equal(t, uint16(len(want.Extra)), got.Header.NameserverRRCount)
// }

// func checkQuestions(t *testing.T, want []dns.Question, got []dnstypes.Question) {
// 	for i := 0; i < int(len(want)); i++ {
// 		assert.Equal(t, want[i].Name, got[i].Name)
// 		assert.Equal(t, want[i].Qtype, got[i].QType)
// 		assert.Equal(t, want[i].Qclass, got[i].QClass)
// 	}
// }

// func checkResourceRecord(t *testing.T, want []dns.RR, got []dnstypes.ResourceRecord) {
// 	for i := 0; i < int(len(want)); i++ {
// 		assert.Equal(t, want[i].Header().Name, got[i].Name)
// 		assert.Equal(t, want[i].Header().Rrtype, got[i].RType)
// 		assert.Equal(t, want[i].Header().Class, got[i].RClass)
// 		assert.Equal(t, want[i].Header().Ttl, got[i].TTL)
// 		assert.Equal(t, want[i].Header().Rdlength, got[i].RDLength)

// 		switch wantRecord := want[i].(type) {
// 		case *dns.A:
// 			assert.Equal(t, wantRecord.A.String(), net.IP(got[i].RData.Raw).String())
// 		case *dns.AAAA:
// 			assert.Equal(t, wantRecord.AAAA.String(), net.IP(got[i].RData.Raw).String())
// 		case *dns.CNAME:
// 			assert.Equal(t, wantRecord.Target, string(got[i].RData.Raw))
// 		case *dns.MX:
// 			assert.Equal(t, wantRecord.Mx, string(got[i].RData.Raw))
// 		default:
// 			t.Errorf("unsupported DNS record type: %T", wantRecord)
// 		}
// 	}
// }
