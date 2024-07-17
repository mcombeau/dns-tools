package encoder

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeName(t *testing.T) {

	tests := []struct {
		name      string
		data      string
		wantBytes []byte
	}{
		{
			name:      "Simple domain",
			data:      "example.com",
			wantBytes: []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
		{
			name:      "Subdomain",
			data:      "www.example.com",
			wantBytes: []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
		{
			name:      "TLD",
			data:      ".com",
			wantBytes: []byte{3, 'c', 'o', 'm', 0},
		},
		{
			name:      "Root domain",
			data:      "",
			wantBytes: []byte{0},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var buf bytes.Buffer

			encodeDomainName(&buf, test.data)
			gotBytes := buf.Bytes()

			assert.Equal(t, len(test.wantBytes), len(gotBytes))
			assert.Equal(t, test.wantBytes, gotBytes)

		})
	}
}
