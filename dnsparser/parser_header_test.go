package dnsparser

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestParseTransactionID(t *testing.T) {
	mockResponse := mockDNSResponse()

	var unpackedMockResponse dns.Msg
	err := unpackedMockResponse.Unpack(mockResponse)

	if err != nil {
		t.Fatalf("Failed to unpack mock response: %v\n", err)
	}

	want := unpackedMockResponse.Id
	got := parseTransactionID(mockResponse)

	assert.Equal(t, want, got)
}

func TestParseQuestionCount(t *testing.T) {
	mockResponse := mockDNSResponse()

	var unpackedMockResponse dns.Msg
	err := unpackedMockResponse.Unpack(mockResponse)

	if err != nil {
		t.Fatalf("Failed to unpack mock response: %v\n", err)
	}

	want := uint16(len(unpackedMockResponse.Question))
	got := parseQuestionCount(mockResponse)

	assert.Equal(t, want, got)
}

func TestParseAnswerRRCount(t *testing.T) {
	mockResponse := mockDNSResponse()

	var unpackedMockResponse dns.Msg
	err := unpackedMockResponse.Unpack(mockResponse)

	if err != nil {
		t.Fatalf("Failed to unpack mock response: %v\n", err)
	}

	want := uint16(len(unpackedMockResponse.Answer))
	got := parseAnswerRRCount(mockResponse)

	assert.Equal(t, want, got)
}

func TestParseNameserverRRCount(t *testing.T) {
	mockResponse := mockDNSResponse()

	var unpackedMockResponse dns.Msg
	err := unpackedMockResponse.Unpack(mockResponse)

	if err != nil {
		t.Fatalf("Failed to unpack mock response: %v\n", err)
	}

	want := uint16(len(unpackedMockResponse.Ns))
	got := parseNameserverRRCount(mockResponse)

	assert.Equal(t, want, got)
}

func TestParseAdditionalRRCount(t *testing.T) {
	mockResponse := mockDNSResponse()

	var unpackedMockResponse dns.Msg
	err := unpackedMockResponse.Unpack(mockResponse)

	if err != nil {
		t.Fatalf("Failed to unpack mock response: %v\n", err)
	}

	want := uint16(len(unpackedMockResponse.Extra))
	got := parseAdditionalRRCount(mockResponse)

	assert.Equal(t, want, got)
}

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
	assert.Equal(t, uint16(len(want.Question)), got.QuestionCount)
	assert.Equal(t, uint16(len(want.Answer)), got.AnswerRRCount)
	assert.Equal(t, uint16(len(want.Ns)), got.NameserverRRCount)
	assert.Equal(t, uint16(len(want.Extra)), got.NameserverRRCount)
}
