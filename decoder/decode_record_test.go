package decoder

import (
	"reflect"
	"testing"

	"github.com/mcombeau/dns-tools/dns"
)

func TestDecodeResourceRecord(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want dns.ResourceRecord
	}{
		{
			name: "A record",
			data: []byte{
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
			data: []byte{
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
			data: []byte{
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
			data: []byte{
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
			got, _, err := decodeDNSResourceRecord(tt.data, 0)

			if err != nil {
				t.Fatalf("decodeDNSResourceRecord() error = %v, data = %v\n", err, tt.data)
			}

			assertRessourceRecord(t, got, &tt.want, tt.data)
		})
	}
}

func assertRessourceRecord(t *testing.T, got *dns.ResourceRecord, want *dns.ResourceRecord, data []byte) {
	if got.Name != want.Name {
		t.Errorf("decodeDNSResourceRecord() Name got = %s, want = %s, data = %v\n", got.Name, want.Name, data)
	}
	if got.RType != want.RType {
		t.Errorf("decodeDNSResourceRecord() RType got = %d, want = %d, data = %v\n", got.RType, want.RType, data)
	}
	if got.RClass != want.RClass {
		t.Errorf("decodeDNSResourceRecord() RClass got = %d, want = %d, data = %v\n", got.RClass, want.RClass, data)
	}
	if got.TTL != want.TTL {
		t.Errorf("decodeDNSResourceRecord() TTL got = %d, want = %d, data = %v\n", got.TTL, want.TTL, data)
	}
	if got.RDLength != want.RDLength {
		t.Errorf("decodeDNSResourceRecord() RDLength got = %d, want = %d, data = %v\n", got.RDLength, want.RDLength, data)
	}
	if !reflect.DeepEqual(got.RData.Raw, want.RData.Raw) {
		t.Errorf("decodeDNSResourceRecord() RData Raw got = %v, want = %v, data = %v\n", got.RData.Raw, want.RData.Raw, data)
	}
	if got.RData.Decoded != want.RData.Decoded {
		t.Errorf("decodeDNSResourceRecord() RData decoded got = %s, want = %s, data = %v\n", got.RData.Decoded, want.RData.Decoded, data)
	}
}
