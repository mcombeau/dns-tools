package dnsparser

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestParseResourceRecord(t *testing.T) {
	mockResponse := mockDNSResponse()

	var unpackedMockResponse dns.Msg
	err := unpackedMockResponse.Unpack(mockResponse)

	if err != nil {
		t.Fatalf("Failed to unpack mock response: %v\n", err)
	}

	want := unpackedMockResponse.Answer[0]

	_, offset, err := parseDNSQuestion(mockResponse)

	if err != nil {
		t.Fatalf("Failed to parse DNS question: %v\n", err)
	}

	got, _, err := parseDNSResourceRecord(mockResponse, offset)

	assert.NoError(t, err)

	assert.Equal(t, want.Header().Name, got.Name)
	assert.Equal(t, want.Header().Rrtype, got.RType)
	assert.Equal(t, want.Header().Class, got.RClass)
	assert.Equal(t, want.Header().Ttl, got.TTL)
	assert.Equal(t, want.Header().Rdlength, got.RDLength)

}
