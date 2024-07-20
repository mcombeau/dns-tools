package encoder

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/mcombeau/dns-tools/dns"
)

func TestEncodeResourceRecord(t *testing.T) {
	tests := []struct {
		name string
		rr   dns.ResourceRecord
		want []byte
	}{
		{
			name: "A record",
			rr: dns.ResourceRecord{
				Name:     "example.com",
				RType:    dns.A,
				RClass:   dns.IN,
				TTL:      300,
				RDLength: 4,
				RData: dns.RData{
					Raw:     []byte{93, 184, 216, 34},
					Decoded: "",
				},
			},
			want: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 1, // RType: 1
				0, 1, // RClass: 1
				0, 0, 1, 44, // TTL: 300
				0, 4, // RDLength: 4
				93, 184, 216, 34, // RData: 93.184.216.34
			},
		},
		{
			name: "AAAA record",
			rr: dns.ResourceRecord{
				Name:     "example.com",
				RType:    dns.AAAA,
				RClass:   dns.IN,
				TTL:      300,
				RDLength: 16,
				RData: dns.RData{
					Raw:     []byte{32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, // 2001:db8::1
					Decoded: "",
				},
			},
			want: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 28, // RType: 28 (AAAA)
				0, 1, // RClass: 1
				0, 0, 1, 44, // TTL: 300
				0, 16, // RDLength: 16
				32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // RData: 2001:db8::1
			},
		},
		{
			name: "CNAME record",
			rr: dns.ResourceRecord{
				Name:     "www.example.com",
				RType:    dns.CNAME,
				RClass:   dns.IN,
				TTL:      300,
				RDLength: 13,
				RData: dns.RData{
					Raw:     []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, // example.com
					Decoded: "",
				},
			},
			want: []byte{
				3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: www.example.com
				0, 5, // RType: 5 (CNAME)
				0, 1, // RClass: 1
				0, 0, 1, 44, // TTL: 300
				0, 13, // RDLength: 13
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // RData: example.com
			},
		},
		{
			name: "MX record",
			rr: dns.ResourceRecord{
				Name:     "example.com",
				RType:    dns.MX,
				RClass:   dns.IN,
				TTL:      300,
				RDLength: 16,
				RData: dns.RData{
					Raw:     append([]byte{0, 10}, []byte{4, 'm', 'a', 'i', 'l', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}...), // preference 10, mail.example.com
					Decoded: "",
				},
			},
			want: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 15, // RType: 15 (MX)
				0, 1, // RClass: 1
				0, 0, 1, 44, // TTL: 300
				0, 16, // RDLength: 16
				0, 10, // Preference: 10
				4, 'm', 'a', 'i', 'l', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // RData: mail.example.com
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			encodeDNSResourceRecord(&buf, tt.rr)
			got := buf.Bytes()

			if len(got) != len(tt.want) {
				t.Errorf("encodeDNSResourceRecord() bytes length got = %d, want = %d\n", len(got), len(tt.want))
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("encodeDNSResourceRecord() bytes\n\tgot = %v,\n\twant = %v\n", got, tt.want)
			}
		})
	}
}
