package decoder

import (
	"net"
	"testing"

	"github.com/mcombeau/go-dns-tools/testutils"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestDecodeDNSMessage(t *testing.T) {
	mockResponse := testutils.MockDNSResponse()

	var unpackedMockResponse dns.Msg
	err := unpackedMockResponse.Unpack(mockResponse)

	if err != nil {
		t.Fatalf("Failed to unpack mock response: %v\n", err)
	}

	want := unpackedMockResponse
	got, err := DecodeDNSMessage(mockResponse)

	assert.NoError(t, err)

	checkHeader(t, want, *got)
	checkQuestions(t, want.Question, got.Questions)
	checkResourceRecord(t, want.Answer, got.Answers)
	checkResourceRecord(t, want.Ns, got.NameServers)
	checkResourceRecord(t, want.Extra, got.Additionals)
}

func checkHeader(t *testing.T, want dns.Msg, got DNSMessage) {
	assert.Equal(t, want.Id, got.Header.Id)
	assert.Equal(t, want.Response, got.Header.Flags.Response)
	assert.Equal(t, int(want.Opcode), int(got.Header.Flags.Opcode))
	assert.Equal(t, want.Authoritative, got.Header.Flags.Authoritative)
	assert.Equal(t, want.Truncated, got.Header.Flags.Truncated)
	assert.Equal(t, want.RecursionDesired, got.Header.Flags.RecursionDesired)
	assert.Equal(t, want.RecursionAvailable, got.Header.Flags.RecursionAvailable)
	assert.True(t, got.Header.Flags.DnssecOk)
	assert.Equal(t, want.AuthenticatedData, got.Header.Flags.AuthenticatedData)
	assert.Equal(t, want.CheckingDisabled, got.Header.Flags.CheckingDisabled)
	assert.Equal(t, int(want.Rcode), int(got.Header.Flags.ResponseCode))
	assert.Equal(t, uint16(len(want.Question)), got.Header.QuestionCount)
	assert.Equal(t, uint16(len(want.Answer)), got.Header.AnswerRRCount)
	assert.Equal(t, uint16(len(want.Ns)), got.Header.NameserverRRCount)
	assert.Equal(t, uint16(len(want.Extra)), got.Header.NameserverRRCount)
}

func checkQuestions(t *testing.T, want []dns.Question, got []DNSQuestion) {
	for i := 0; i < int(len(want)); i++ {
		assert.Equal(t, want[i].Name, got[i].Name)
		assert.Equal(t, want[i].Qtype, got[i].QType)
		assert.Equal(t, want[i].Qclass, got[i].QClass)
	}
}

func checkResourceRecord(t *testing.T, want []dns.RR, got []DNSResourceRecord) {
	for i := 0; i < int(len(want)); i++ {
		assert.Equal(t, want[i].Header().Name, got[i].Name)
		assert.Equal(t, want[i].Header().Rrtype, got[i].RType)
		assert.Equal(t, want[i].Header().Class, got[i].RClass)
		assert.Equal(t, want[i].Header().Ttl, got[i].TTL)
		assert.Equal(t, want[i].Header().Rdlength, got[i].RDLength)

		switch wantRecord := want[i].(type) {
		case *dns.A:
			assert.Equal(t, wantRecord.A.String(), net.IP(got[i].RData).String())
		case *dns.AAAA:
			assert.Equal(t, wantRecord.AAAA.String(), net.IP(got[i].RData).String())
		case *dns.CNAME:
			assert.Equal(t, wantRecord.Target, string(got[i].RData))
		case *dns.MX:
			assert.Equal(t, wantRecord.Mx, string(got[i].RData))
		default:
			t.Errorf("unsupported DNS record type: %T", wantRecord)
		}
	}
}
