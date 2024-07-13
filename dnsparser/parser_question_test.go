package dnsparser

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestParseDomainName(t *testing.T) {
	mockResponse := mockDNSResponse()

	var unpackedMockResponse dns.Msg
	err := unpackedMockResponse.Unpack(mockResponse)

	if err != nil {
		t.Fatalf("Failed to unpack mock response: %v\n", err)
	}

	want := unpackedMockResponse.Question[0].Name
	wantBytes := len(unpackedMockResponse.Question[0].Name) + 1
	got, gotBytes := parseDomainName(mockResponse, 12)

	assert.Equal(t, want, got)
	assert.Equal(t, wantBytes, gotBytes)
}

func TestParseQuestion(t *testing.T) {
	mockResponse := mockDNSResponse()

	var unpackedMockResponse dns.Msg
	err := unpackedMockResponse.Unpack(mockResponse)

	if err != nil {
		t.Fatalf("Failed to unpack mock response: %v\n", err)
	}

	want := unpackedMockResponse.Question[0]
	got, _, err := parseDNSQuestion(mockResponse)

	assert.NoError(t, err)

	assert.Equal(t, want.Name, got.Name)
	assert.Equal(t, want.Qtype, got.Qtype)
}
