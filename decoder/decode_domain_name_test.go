package decoder

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeDomainName(t *testing.T) {
	tests := []struct {
		data       []byte
		offset     int
		wantString string
		wantLength int
	}{
		{
			data:       []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			offset:     0,
			wantString: "example.com.",
			wantLength: 13,
		},
		{
			data:       []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			offset:     0,
			wantString: "www.example.com.",
			wantLength: 17,
		},
		{
			data:       []byte{0},
			offset:     0,
			wantString: ".",
			wantLength: 1,
		},
	}

	for _, test := range tests {
		gotString, gotLength, err := decodeDomainName(test.data, test.offset)

		assert.NoError(t, err)

		assert.Equal(t, test.wantString, gotString)
		assert.Equal(t, test.wantLength, gotLength)
	}
}

// TODO: Create manual tests to test dns compression handling
