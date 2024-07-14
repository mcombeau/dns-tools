package decoder

import (
	"testing"

	"github.com/mcombeau/go-dns-tools/testutils"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestDecodeQuestion(t *testing.T) {
	mockResponse := testutils.MockDNSResponse()

	var unpackedMockResponse dns.Msg
	err := unpackedMockResponse.Unpack(mockResponse)

	if err != nil {
		t.Fatalf("Failed to unpack mock response: %v\n", err)
	}

	want := unpackedMockResponse.Question[0]
	got, gotOffset, err := decodeDNSQuestion(mockResponse, 12)

	assert.NoError(t, err)

	assert.Equal(t, want.Name, got.Name)
	assert.Equal(t, want.Qtype, got.QType)
	assert.Equal(t, want.Qclass, got.QClass)
	assert.Equal(t, 12+len(want.Name)+1+4, gotOffset)
}
