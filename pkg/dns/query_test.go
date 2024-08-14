package dns

import (
	"errors"
	"reflect"
	"testing"
)

func TestCreateDNSQuery(t *testing.T) {
	tests := []struct {
		name         string
		domain       string
		questionType uint16
		reverseQuery bool
		want         []byte
		wantError    error
	}{
		{
			name:         "Regular query",
			domain:       "example.com.",
			questionType: A,
			reverseQuery: false,
			want: []byte{
				0x00, 0x00, // ID bytes
				0x01, 0x00, // Flags: recursion desired
				0x00, 0x01, // Question count: 1
				0x00, 0x00, // Answer count: 0
				0x00, 0x00, // Authority count: 0
				0x00, 0x00, // Additional count: 0
				// Start domain
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm', 0x00, // End domain
				0x00, 0x01, // QTYPE: 1 (A)
				0x00, 0x01, // QCLASS: 1 (IN)
			},
			wantError: nil,
		},
		{
			name:         "Reverse query",
			domain:       "1.1.1.1",
			questionType: A,
			reverseQuery: true,
			want: []byte{
				0x00, 0x00, // ID bytes
				0x01, 0x00, // Flags: recursion desired
				0x00, 0x01, // Question count: 1
				0x00, 0x00, // Answer count: 0
				0x00, 0x00, // Authority count: 0
				0x00, 0x00, // Additional count: 0
				// Start domain
				0x01, '1', 0x01, '1', 0x01, '1', 0x01, '1',
				0x07, 'i', 'n', '-', 'a', 'd', 'd', 'r',
				0x04, 'a', 'r', 'p', 'a', 0x00, // End domain
				0x00, 0x0c, // QTYPE: 12 (PTR)
				0x00, 0x01, // QCLASS: 1 (IN)
			},
			wantError: nil,
		},
		{
			name:         "Invalid IP for reverse query",
			domain:       "1.1.1.1.1",
			questionType: A,
			reverseQuery: true,
			want:         []byte{},
			wantError:    ErrInvalidIP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			got, err := CreateDNSQuery(tt.domain, tt.questionType, tt.reverseQuery)

			if tt.wantError != nil {
				if err == nil || !errors.Is(err, tt.wantError) {
					t.Fatalf("readDNSQuestion() error got = %v, want error = %v, test name = %v\n", err.Error(), tt.wantError.Error(), tt.name)
				}
				return
			}

			if len(got) != len(tt.want) {
				t.Errorf("createDNSQuery() bytes length got = %d, want = %d\n", len(got), len(tt.want))
			}
			if !reflect.DeepEqual(got[2:], tt.want[2:]) {
				// Skip the first two bytes for comparison, since ID is randomized
				t.Errorf("createDNSQuery() bytes\n\tgot = %v,\n\twant = %v\n", got, tt.want)
			}
		})
	}
}
