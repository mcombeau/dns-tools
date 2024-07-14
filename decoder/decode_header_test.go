package decoder

import (
	"testing"

	"github.com/mcombeau/go-dns-tools/testutils"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestDecodeFlags(t *testing.T) {
	mockResponse := testutils.MockDNSResponse()

	var unpackedMockResponse dns.Msg
	err := unpackedMockResponse.Unpack(mockResponse)

	if err != nil {
		t.Fatalf("Failed to unpack mock response: %v\n", err)
	}

	want := unpackedMockResponse
	got := decodeDNSFlags(mockResponse)

	assert.Equal(t, want.Response, got.Response)
	assert.Equal(t, int(want.Opcode), int(got.Opcode))
	assert.Equal(t, want.Authoritative, got.Authoritative)
	assert.Equal(t, want.Truncated, got.Truncated)
	assert.Equal(t, want.RecursionDesired, got.RecursionDesired)
	assert.Equal(t, want.RecursionAvailable, got.RecursionAvailable)
	assert.True(t, got.DnssecOk)
	assert.Equal(t, want.AuthenticatedData, got.AuthenticatedData)
	assert.Equal(t, want.CheckingDisabled, got.CheckingDisabled)
	assert.Equal(t, int(want.Rcode), int(got.ResponseCode))
}

func TestDecodeHeader(t *testing.T) {
	mockResponse := testutils.MockDNSResponse()

	var unpackedMockResponse dns.Msg
	err := unpackedMockResponse.Unpack(mockResponse)

	if err != nil {
		t.Fatalf("Failed to unpack mock response: %v\n", err)
	}

	want := unpackedMockResponse
	got, err := DecodeDNSHeader(mockResponse)

	assert.NoError(t, err)

	assert.Equal(t, want.Id, got.Id)
	assert.Equal(t, want.Response, got.Flags.Response)
	assert.Equal(t, int(want.Opcode), int(got.Flags.Opcode))
	assert.Equal(t, want.Authoritative, got.Flags.Authoritative)
	assert.Equal(t, want.Truncated, got.Flags.Truncated)
	assert.Equal(t, want.RecursionDesired, got.Flags.RecursionDesired)
	assert.Equal(t, want.RecursionAvailable, got.Flags.RecursionAvailable)
	assert.True(t, got.Flags.DnssecOk)
	assert.Equal(t, want.AuthenticatedData, got.Flags.AuthenticatedData)
	assert.Equal(t, want.CheckingDisabled, got.Flags.CheckingDisabled)
	assert.Equal(t, int(want.Rcode), int(got.Flags.ResponseCode))
	assert.Equal(t, uint16(len(want.Question)), got.QuestionCount)
	assert.Equal(t, uint16(len(want.Answer)), got.AnswerRRCount)
	assert.Equal(t, uint16(len(want.Ns)), got.NameserverRRCount)
	assert.Equal(t, uint16(len(want.Extra)), got.NameserverRRCount)
}
