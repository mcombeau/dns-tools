package decoder

import (
	"net"
	"testing"

	"github.com/mcombeau/go-dns-tools/testutils"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestDecodeResourceRecord(t *testing.T) {
	mockResponse := testutils.MockDNSResponse()

	var unpackedMockResponse dns.Msg
	err := unpackedMockResponse.Unpack(mockResponse)

	if err != nil {
		t.Fatalf("Failed to unpack mock response: %v\n", err)
	}

	want := unpackedMockResponse.Answer[0]

	_, offset, err := decodeDNSQuestion(mockResponse, 12)

	if err != nil {
		t.Fatalf("Failed to parse DNS question: %v\n", err)
	}

	got, _, err := decodeDNSResourceRecord(mockResponse, offset)

	assert.NoError(t, err)

	assert.Equal(t, want.Header().Name, got.Name)
	assert.Equal(t, want.Header().Rrtype, got.RType)
	assert.Equal(t, want.Header().Class, got.RClass)
	assert.Equal(t, want.Header().Ttl, got.TTL)
	assert.Equal(t, want.Header().Rdlength, got.RDLength)

	switch record := want.(type) {
	case *dns.A:
		assert.Equal(t, record.A.String(), net.IP(got.RData).String())
	case *dns.AAAA:
		assert.Equal(t, record.AAAA.String(), net.IP(got.RData).String())
	case *dns.CNAME:
		assert.Equal(t, record.Target, string(got.RData))
	case *dns.MX:
		assert.Equal(t, record.Mx, string(got.RData))
	default:
		t.Fatalf("unsupported DNS record type: %T", record)
	}
}
