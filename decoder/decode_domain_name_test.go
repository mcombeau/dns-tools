package decoder

import (
	"testing"

	"github.com/stretchr/testify/assert"
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

			assert.NoError(t, err)

			assert.Equal(t, test.wantString, gotString)
			assert.Equal(t, test.wantOffsetIncrement, gotOffsetIncrement)
		})
	}
}
