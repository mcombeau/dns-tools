package encoder

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeName(t *testing.T) {

	tests := []struct {
		data      string
		wantBytes []byte
	}{
		{
			data:      "example.com",
			wantBytes: []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
		{
			data:      "www.example.com",
			wantBytes: []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
		{
			data:      ".com",
			wantBytes: []byte{3, 'c', 'o', 'm', 0},
		},
	}

	for _, test := range tests {
		var buf bytes.Buffer

		encodeDomainName(&buf, test.data)
		gotBytes := buf.Bytes()

		assert.Equal(t, len(test.wantBytes), len(gotBytes))
		assert.Equal(t, test.wantBytes, gotBytes)
	}
}
