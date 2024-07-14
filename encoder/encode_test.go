package encoder

import (
	"testing"

	"github.com/mcombeau/go-dns-tools/dns"
	"github.com/stretchr/testify/assert"
)

func MockDNSQuery() *dns.Message {
	return &dns.Message{
		Header: &dns.Header{
			Id:            1234,
			Flags:         &dns.Flags{RecursionDesired: true},
			QuestionCount: 1,
		},
		Questions: []dns.Question{
			{
				Name:   "example.com.",
				QType:  1, // Type A
				QClass: 1, // Class IN
			},
		},
	}
}

func TestEncodeDNSMessage(t *testing.T) {
	message := MockDNSQuery()
	want := []byte{
		0x04, 0xd2, // ID bytes
		0x01, 0x00, // Flags: recursion desired
		0x00, 0x01, // Question count: 1
		0x00, 0x00, // Answer count: 0
		0x00, 0x00, // Authority count: 0
		0x00, 0x00, // Additional count: 0
		// Start domain label -> 7 bytes ("example")
		0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
		// Start domain label -> 3 bytes ("com")
		0x03, 0x63, 0x6f, 0x6d, 0x00, // End domain
		0x00, 0x01, // QTYPE: 1 (A)
		0x00, 0x01, // QCLASS: 1 (IN)
	}

	got, err := EncodeDNSMessage(message)

	assert.NoError(t, err)

	assert.Equal(t, len(want), len(got))
	assert.Equal(t, want, got)
}
