package encoder

import (
	"bytes"
	"testing"

	"github.com/mcombeau/go-dns-tools/dns"
	"github.com/stretchr/testify/assert"
)

func TestEncodeDNSQuestion(t *testing.T) {
	tests := []struct {
		name     string
		question dns.Question
		want     []byte
	}{
		{
			name: "A record question",
			question: dns.Question{
				Name:   "example.com",
				QType:  1, // A record
				QClass: 1, // IN class
			},
			want: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 1, // QType: 1 (A)
				0, 1, // QClass: 1 (IN)
			},
		},
		{
			name: "AAAA record question",
			question: dns.Question{
				Name:   "example.com",
				QType:  28, // AAAA record
				QClass: 1,  // IN class
			},
			want: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 28, // QType: 28 (AAAA)
				0, 1, // QClass: 1 (IN)
			},
		},
		{
			name: "CNAME record question",
			question: dns.Question{
				Name:   "www.example.com",
				QType:  5, // CNAME record
				QClass: 1, // IN class
			},
			want: []byte{
				3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: www.example.com
				0, 5, // QType: 5 (CNAME)
				0, 1, // QClass: 1 (IN)
			},
		},
		{
			name: "MX record question",
			question: dns.Question{
				Name:   "example.com",
				QType:  15, // MX record
				QClass: 1,  // IN class
			},
			want: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 15, // QType: 15 (MX)
				0, 1, // QClass: 1 (IN)
			},
		},
		{
			name: "NS record question",
			question: dns.Question{
				Name:   "example.com",
				QType:  2, // NS record
				QClass: 1, // IN class
			},
			want: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 2, // QType: 2 (NS)
				0, 1, // QClass: 1 (IN)
			},
		},
		{
			name: "PTR record question",
			question: dns.Question{
				Name:   "34.216.184.93.in-addr.arpa",
				QType:  12, // PTR record
				QClass: 1,  // IN class
			},
			want: []byte{
				2, '3', '4', 3, '2', '1', '6', 3, '1', '8', '4', 2, '9', '3', 7, 'i', 'n', '-', 'a', 'd', 'd', 'r', 4, 'a', 'r', 'p', 'a', 0, // Name: 34.216.184.93.in-addr.arpa
				0, 12, // QType: 12 (PTR)
				0, 1, // QClass: 1 (IN)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			encodeDNSQuestion(&buf, tt.question)
			assert.Equal(t, tt.want, buf.Bytes())
		})
	}
}
