package utils

import (
	"testing"

	"github.com/mcombeau/go-dns-tools/testutils"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestDecodeDomainName(t *testing.T) {
	tests := []struct {
		data     []byte
		offset   int
		expected string
		length   int
	}{
		{
			data:     []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			offset:   0,
			expected: "example.com.",
			length:   13,
		},
		{
			data:     []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			offset:   0,
			expected: "www.example.com.",
			length:   17,
		},
		{
			data:     []byte{0},
			offset:   0,
			expected: ".",
			length:   1,
		},
	}

	for _, test := range tests {
		name, length := DecodeDomainName(test.data, test.offset)
		assert.Equal(t, test.expected, name)
		assert.Equal(t, test.length, length)
	}
}

func TestDecodeDomainNameInDNSMessage(t *testing.T) {
	mockResponse := testutils.MockDNSResponse()

	var unpackedMockResponse dns.Msg
	err := unpackedMockResponse.Unpack(mockResponse)

	if err != nil {
		t.Fatalf("Failed to unpack mock response: %v\n", err)
	}

	want := unpackedMockResponse.Question[0].Name
	wantBytes := len(unpackedMockResponse.Question[0].Name) + 1
	got, gotBytes := DecodeDomainName(mockResponse, 12)

	assert.Equal(t, want, got)
	assert.Equal(t, wantBytes, gotBytes)
}
