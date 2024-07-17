package decoder

import (
	"testing"

	"github.com/mcombeau/dns-tools/dns"
	"github.com/stretchr/testify/assert"
)

func TestDecodeResourceRecord(t *testing.T) {
	tests := []struct {
		name  string
		bytes []byte
		want  dns.ResourceRecord
	}{
		{
			name: "A record",
			bytes: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 1, // RType: 1
				0, 1, // RClass: 1
				0, 0, 1, 44, // TTL: 300
				0, 4, // RDLength: 4
				93, 184, 216, 34, // RData: 93.184.216.34
			},
			want: dns.ResourceRecord{
				Name:     "example.com.",
				RType:    dns.A,
				RClass:   dns.IN,
				TTL:      300,
				RDLength: 4,
				RData: dns.RData{
					Raw:     []byte{93, 184, 216, 34},
					Decoded: "93.184.216.34",
				},
			},
		},
		{
			name: "AAAA record",
			bytes: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 28, // RType: 28 (AAAA)
				0, 1, // RClass: 1
				0, 0, 1, 44, // TTL: 300
				0, 16, // RDLength: 16
				32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // RData: 2001:db8::1
			},
			want: dns.ResourceRecord{
				Name:     "example.com.",
				RType:    dns.AAAA,
				RClass:   dns.IN,
				TTL:      300,
				RDLength: 16,
				RData: dns.RData{
					Raw:     []byte{32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, // 2001:db8::1
					Decoded: "2001:db8::1",
				},
			},
		},
		{
			name: "CNAME record",
			bytes: []byte{
				3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: www.example.com
				0, 5, // RType: 5 (CNAME)
				0, 1, // RClass: 1
				0, 0, 1, 44, // TTL: 300
				0, 13, // RDLength: 13
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // RData: example.com
			},
			want: dns.ResourceRecord{
				Name:     "www.example.com.",
				RType:    dns.CNAME,
				RClass:   dns.IN,
				TTL:      300,
				RDLength: 13,
				RData: dns.RData{
					Raw:     []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, // example.com
					Decoded: "example.com.",
				},
			},
		},
		{
			name: "MX record",
			bytes: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 15, // RType: 15 (MX)
				0, 1, // RClass: 1
				0, 0, 1, 44, // TTL: 300
				0, 20, // RDLength: 16
				0, 10, // Preference: 10
				4, 'm', 'a', 'i', 'l', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // RData: mail.example.com
			},
			want: dns.ResourceRecord{
				Name:     "example.com.",
				RType:    dns.MX,
				RClass:   dns.IN,
				TTL:      300,
				RDLength: 20,
				RData: dns.RData{
					Raw: []byte{
						0, 10,
						4, 'm', 'a', 'i', 'l', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
					},
					Decoded: "10 mail.example.com.",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := decodeDNSResourceRecord(tt.bytes, 0)
			assert.NoError(t, err)
			assert.Equal(t, tt.want.Name, got.Name)
			assert.Equal(t, tt.want.RType, got.RType)
			assert.Equal(t, tt.want.RClass, got.RClass)
			assert.Equal(t, tt.want.TTL, got.TTL)
			assert.Equal(t, tt.want.RDLength, got.RDLength)
			assert.Equal(t, tt.want.RData.Raw, got.RData.Raw)
			assert.Equal(t, tt.want.RData.Decoded, got.RData.Decoded)
		})
	}
}
