package dns

import (
	"errors"
	"reflect"
	"testing"
)

func TestReadDomainName(t *testing.T) {
	tests := []struct {
		name            string
		data            []byte
		offset          int
		wantString      string
		wantFinalOffset int
	}{
		{
			name:            "Simple domain",
			data:            []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			offset:          0,
			wantString:      "example.com.",
			wantFinalOffset: 0 + 13,
		},
		{
			name:            "Subdomain",
			data:            []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			offset:          0,
			wantString:      "www.example.com.",
			wantFinalOffset: 0 + 17,
		},
		{
			name:            "Root domain",
			data:            []byte{0},
			offset:          0,
			wantString:      ".",
			wantFinalOffset: 0 + 1,
		},
		{
			name: "Compressed domain with pointer",
			data: []byte{
				3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // "www.example.com."
				0xc0, 4, // Pointer to offset 4 ("example.com.")
			},
			offset:          17, // Start of the compressed domain name
			wantString:      "example.com.",
			wantFinalOffset: 17 + 2,
		},
		{
			name: "Compressed subdomain with domain pointer",
			data: []byte{
				3, 'f', 'o', 'o', 0, // "foo." -> 5 bytes
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // "example.com." -> 13 bytes
				3, 'b', 'a', 'r', 0xc0, 5, // "bar.example.com." using pointer to offset 5 ("example.com.")
			},
			offset:          18, // Start of the compressed domain name "bar.example.com"
			wantString:      "bar.example.com.",
			wantFinalOffset: 18 + 6,
		},
		{
			name: "Multiple compressed domains",
			data: []byte{
				3, 'f', 'o', 'o', 0, // "foo." -> 5 bytes
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // "example.com." -> 13 bytes
				3, 'b', 'a', 'r', 0xc0, 5, // "bar.example.com." using pointer to offset 5 ("example.com.")
				3, 'b', 'a', 'z', 0xc0, 5, // "baz.example.com." using pointer to offset 5 ("example.com.")
			},
			offset:          24, // Start of the compressed domain name "baz.example.com"
			wantString:      "baz.example.com.",
			wantFinalOffset: 24 + 6,
		},
		{
			name: "Pointer to another pointer to domain",
			data: []byte{
				3, 'f', 'o', 'o', 0, // "foo." -> 5 bytes
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // "example.com." -> 13 bytes
				3, 'b', 'a', 'r', 0xc0, 5, // "bar.example.com." using pointer to offset 5 ("example.com.")
				3, 'b', 'a', 'z', 0xc0, 5, // "baz.example.com." using pointer to offset 5 ("example.com.")
				0xc0, 18, // Pointer to "bar.example.com."
			},
			offset:          30, // Start of the compressed domain name "bar.example.com"
			wantString:      "bar.example.com.",
			wantFinalOffset: 30 + 2,
		},
		{
			name: "Invalid: circular pointer",
			data: []byte{
				3, 'f', 'o', 'o', 0, // "foo." -> 5 bytes
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // "example.com." -> 13 bytes
				3, 'b', 'a', 'r', 0xc0, 18, // "bar.example.com." using pointer to offset 5 ("example.com.")
			},
			offset:          18, // Start of the compressed domain name "baz.example.com"
			wantString:      "bar.example.com.",
			wantFinalOffset: 18 + 6,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := &dnsReader{data: test.data, offset: test.offset}
			gotString, err := reader.readDomainName()

			if err != nil {
				t.Fatalf("readDomainName() got error = %v, data = %v, offset = %d\n", err, test.data, test.offset)
			}
			if gotString != test.wantString {
				t.Errorf("readDomainName() string got = %s, want = %s, data = %v, offset = %d\n", gotString, test.wantString, test.data, test.offset)
			}
			if reader.offset != test.wantFinalOffset {
				t.Errorf("readDomainName() offset got = %d, want = %d, data = %v, offset = %d\n", reader.offset, test.wantFinalOffset, test.data, test.offset)
			}
		})
	}
}

func TestEncodeName(t *testing.T) {

	tests := []struct {
		name string
		data string
		want []byte
	}{
		{
			name: "Simple domain",
			data: "example.com",
			want: []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
		{
			name: "Subdomain",
			data: "www.example.com",
			want: []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
		{
			name: "TLD",
			data: ".com",
			want: []byte{3, 'c', 'o', 'm', 0},
		},
		{
			name: "Root domain",
			data: "",
			want: []byte{0},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			writer := &dnsWriter{
				data:   make([]byte, 1),
				offset: 0,
			}
			writer.writeDomainName(test.data)
			got := writer.data

			if len(got) != len(test.want) {
				t.Errorf("encodeDomainName() bytes length got = %d, want = %d, data = %s\n", len(got), len(test.want), test.data)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("encodeDomainName() bytes got = %v, want = %v, data = %s\n", got, test.want, test.data)
			}
		})
	}
}

func TestGetReverseDNSDomain(t *testing.T) {
	tests := []struct {
		name      string
		ip        string
		want      string
		wantError error
	}{
		{
			name:      "IPv4 simple inversion",
			ip:        "8.8.8.8",
			want:      "8.8.8.8.in-addr.arpa.",
			wantError: nil,
		},
		{
			name:      "IPv4 inversion",
			ip:        "192.0.1.2",
			want:      "2.1.0.192.in-addr.arpa.",
			wantError: nil,
		},
		{
			name:      "IPv4 invalid address",
			ip:        "192.0.1.2.3",
			want:      "",
			wantError: ErrInvalidIP,
		},
		{
			name:      "IPv6 full hex",
			ip:        "2001:0db8:85a3:1234:1234:8a2e:0370:7334",
			want:      "4.3.3.7.0.7.3.0.e.2.a.8.4.3.2.1.4.3.2.1.3.a.5.8.8.b.d.0.1.0.0.2.ip6.arpa.",
			wantError: nil,
		},
		{
			name:      "IPv6 full hex with zero sequences",
			ip:        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			want:      "4.3.3.7.0.7.3.0.e.2.a.8.0.0.0.0.0.0.0.0.3.a.5.8.8.b.d.0.1.0.0.2.ip6.arpa.",
			wantError: nil,
		},
		{
			name:      "IPv6 compressed to :0:",
			ip:        "2001:0db8:0:0:0:0:0:0001",
			want:      "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
			wantError: nil,
		},
		{
			name:      "IPv6 compressed to ::",
			ip:        "2001:db8::1",
			want:      "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
			wantError: nil,
		},
		{
			name:      "IPv6 invalid address",
			ip:        "2001:0db8:85a3:1234:1234:8a2e:0370:7334:1234:1234",
			want:      "",
			wantError: ErrInvalidIP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetReverseDNSDomain(tt.ip)

			if tt.wantError != nil {
				if err == nil || !errors.Is(err, tt.wantError) {
					t.Fatalf("GetReverseDNSDomain() error got = %v, want error = %v, ip = %s\n", err.Error(), tt.wantError.Error(), tt.ip)
				}
				return
			}

			if got != tt.want {
				t.Errorf("GetReverseDNSDomain()\n\tgot = %s,\n\twant = %s, IP = %s\n", got, tt.want, tt.ip)
			}
		})
	}

}
