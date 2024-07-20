package dns

import (
	"bytes"
	"reflect"
	"testing"
)

func TestDecodeDomainName(t *testing.T) {
	tests := []struct {
		name                string
		data                []byte
		offset              int
		wantString          string
		wantOffsetIncrement int
	}{
		{
			name:                "Simple domain",
			data:                []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			offset:              0,
			wantString:          "example.com.",
			wantOffsetIncrement: 13,
		},
		{
			name:                "Subdomain",
			data:                []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			offset:              0,
			wantString:          "www.example.com.",
			wantOffsetIncrement: 17,
		},
		{
			name:                "Root domain",
			data:                []byte{0},
			offset:              0,
			wantString:          ".",
			wantOffsetIncrement: 1,
		},
		{
			name: "Compressed domain with pointer",
			data: []byte{
				3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // "www.example.com."
				0xc0, 4, // Pointer to offset 4 ("example.com.")
			},
			offset:              17, // Start of the compressed domain name
			wantString:          "example.com.",
			wantOffsetIncrement: 2,
		},
		{
			name: "Compressed subdomain with domain pointer",
			data: []byte{
				3, 'f', 'o', 'o', 0, // "foo." -> 5 bytes
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // "example.com." -> 13 bytes
				3, 'b', 'a', 'r', 0xc0, 5, // "bar.example.com." using pointer to offset 5 ("example.com.")
			},
			offset:              18, // Start of the compressed domain name "bar.example.com"
			wantString:          "bar.example.com.",
			wantOffsetIncrement: 6,
		},
		{
			name: "Multiple compressed domains",
			data: []byte{
				3, 'f', 'o', 'o', 0, // "foo." -> 5 bytes
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // "example.com." -> 13 bytes
				3, 'b', 'a', 'r', 0xc0, 5, // "bar.example.com." using pointer to offset 5 ("example.com.")
				3, 'b', 'a', 'z', 0xc0, 5, // "baz.example.com." using pointer to offset 5 ("example.com.")
			},
			offset:              24, // Start of the compressed domain name "baz.example.com"
			wantString:          "baz.example.com.",
			wantOffsetIncrement: 6,
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
			offset:              30, // Start of the compressed domain name "bar.example.com"
			wantString:          "bar.example.com.",
			wantOffsetIncrement: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotString, gotOffsetIncrement, err := decodeDomainName(test.data, test.offset)

			if err != nil {
				t.Fatalf("decodeDomainName() error = %v, data = %v, offset = %d\n", err, test.data, test.offset)
			}
			if gotString != test.wantString {
				t.Errorf("decodeDomainName() string got = %s, want = %s, data = %v, offset = %d\n", gotString, test.wantString, test.data, test.offset)
			}
			if gotOffsetIncrement != test.wantOffsetIncrement {
				t.Errorf("decodeDomainName() offset got = %d, want = %d, data = %v, offset = %d\n", gotOffsetIncrement, test.wantOffsetIncrement, test.data, test.offset)
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
			var buf bytes.Buffer

			encodeDomainName(&buf, test.data)
			got := buf.Bytes()

			if len(got) != len(test.want) {
				t.Errorf("encodeDomainName() bytes length got = %d, want = %d, data = %s\n", len(got), len(test.want), test.data)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("encodeDomainName() bytes got = %v, want = %v, data = %s\n", got, test.want, test.data)
			}
		})
	}
}
