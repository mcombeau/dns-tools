package decoder

import (
	"testing"

	"github.com/mcombeau/dns-tools/dns"
)

func TestDecodeDNSQuestion(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want dns.Question
	}{
		{
			name: "A record question",
			data: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 1, // QType: 1 (A)
				0, 1, // QClass: 1 (IN)
			},
			want: dns.Question{
				Name:   "example.com.",
				QType:  dns.A,
				QClass: dns.IN,
			},
		},
		{
			name: "AAAA record question",
			data: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 28, // QType: 28 (AAAA)
				0, 1, // QClass: 1 (IN)
			},
			want: dns.Question{
				Name:   "example.com.",
				QType:  dns.AAAA,
				QClass: dns.IN,
			},
		},
		{
			name: "CNAME record question",
			data: []byte{
				3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: www.example.com
				0, 5, // QType: 5 (CNAME)
				0, 1, // QClass: 1 (IN)
			},
			want: dns.Question{
				Name:   "www.example.com.",
				QType:  dns.CNAME,
				QClass: dns.IN,
			},
		},
		{
			name: "MX record question",
			data: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 15, // QType: 15 (MX)
				0, 1, // QClass: 1 (IN)
			},
			want: dns.Question{
				Name:   "example.com.",
				QType:  dns.MX,
				QClass: dns.IN,
			},
		},
		{
			name: "NS record question",
			data: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 2, // QType: 2 (NS)
				0, 1, // QClass: 1 (IN)
			},
			want: dns.Question{
				Name:   "example.com.",
				QType:  dns.NS,
				QClass: dns.IN,
			},
		},
		{
			name: "PTR record question",
			data: []byte{
				2, '3', '4', 3, '2', '1', '6', 3, '1', '8', '4', 2, '9', '3', 7, 'i', 'n', '-', 'a', 'd', 'd', 'r', 4, 'a', 'r', 'p', 'a', 0, // Name: 34.216.184.93.in-addr.arpa
				0, 12, // QType: 12 (PTR)
				0, 1, // QClass: 1 (IN)
			},
			want: dns.Question{
				Name:   "34.216.184.93.in-addr.arpa.",
				QType:  dns.PTR,
				QClass: dns.IN,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := decodeDNSQuestion(tt.data, 0)

			if err != nil {
				t.Fatalf("decodeDNSQuestion() error = %v, data = %v\n", err, tt.data)
			}

			assertQuestion(t, got, &tt.want, tt.data)
		})
	}
}

func assertQuestion(t *testing.T, got *dns.Question, want *dns.Question, data []byte) {
	if got.Name != want.Name {
		t.Errorf("decodeDNSQuestion() Name got = %s, want = %s, data = %v\n", got.Name, want.Name, data)
	}
	if got.QClass != want.QClass {
		t.Errorf("decodeDNSQuestion() QClass got = %d, want = %d, data = %v\n", got.QClass, want.QClass, data)
	}
	if got.QType != want.QType {
		t.Errorf("decodeDNSQuestion() QType got = %d, want = %d, data = %v\n", got.QType, want.QType, data)
	}
}
