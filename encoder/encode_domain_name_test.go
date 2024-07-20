package encoder

import (
	"bytes"
	"reflect"
	"testing"
)

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
