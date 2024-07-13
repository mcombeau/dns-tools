package dnsparser

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestParseFlags(t *testing.T) {
	mockResponse := mockDNSResponse()

	var unpackedMockResponse dns.Msg
	err := unpackedMockResponse.Unpack(mockResponse)

	if err != nil {
		t.Fatalf("Failed to unpack mock response: %v\n", err)
	}

	want := unpackedMockResponse
	got, err := ParseDNSHeader(mockResponse)

	assert.NoError(t, err)

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
}

func TestParseHeader(t *testing.T) {
	mockResponse := mockDNSResponse()

	var unpackedMockResponse dns.Msg
	err := unpackedMockResponse.Unpack(mockResponse)

	if err != nil {
		t.Fatalf("Failed to unpack mock response: %v\n", err)
	}

	want := unpackedMockResponse
	got, err := ParseDNSHeader(mockResponse)

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
