package dns

import (
	"errors"
	"reflect"
	"testing"
)

func TestReadDNSQuestion(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		want      Question
		wantError error
	}{
		{
			name: "A record question",
			data: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 1, // QType: 1 (A)
				0, 1, // QClass: 1 (IN)
			},
			want: Question{
				Name:   "example.com.",
				QType:  A,
				QClass: IN,
			},
			wantError: nil,
		},
		{
			name: "AAAA record question",
			data: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 28, // QType: 28 (AAAA)
				0, 1, // QClass: 1 (IN)
			},
			want: Question{
				Name:   "example.com.",
				QType:  AAAA,
				QClass: IN,
			},
			wantError: nil,
		},
		{
			name: "CNAME record question",
			data: []byte{
				3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: www.example.com
				0, 5, // QType: 5 (CNAME)
				0, 1, // QClass: 1 (IN)
			},
			want: Question{
				Name:   "www.example.com.",
				QType:  CNAME,
				QClass: IN,
			},
			wantError: nil,
		},
		{
			name: "MX record question",
			data: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 15, // QType: 15 (MX)
				0, 1, // QClass: 1 (IN)
			},
			want: Question{
				Name:   "example.com.",
				QType:  MX,
				QClass: IN,
			},
			wantError: nil,
		},
		{
			name: "NS record question",
			data: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 2, // QType: 2 (NS)
				0, 1, // QClass: 1 (IN)
			},
			want: Question{
				Name:   "example.com.",
				QType:  NS,
				QClass: IN,
			},
			wantError: nil,
		},
		{
			name: "PTR record question",
			data: []byte{
				2, '3', '4', 3, '2', '1', '6', 3, '1', '8', '4', 2, '9', '3', 7, 'i', 'n', '-', 'a', 'd', 'd', 'r', 4, 'a', 'r', 'p', 'a', 0, // Name: 34.216.184.93.in-addr.arpa
				0, 12, // QType: 12 (PTR)
				0, 1, // QClass: 1 (IN)
			},
			want: Question{
				Name:   "34.216.184.93.in-addr.arpa.",
				QType:  PTR,
				QClass: IN,
			},
			wantError: nil,
		},
		{
			name: "Invalid question: bad domain name",
			data: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 5, 'c', 'o', 'm', 0, // Name: example.com
				0, 1, // QType: 1 (A)
				0, 1, // QClass: 1 (IN)
			},
			want:      Question{},
			wantError: ErrOffsetOutOfBounds,
		},
		{
			name: "Invalid question: too short",
			data: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 1, // QType: 1 (A)
			},
			want:      Question{},
			wantError: ErrInvalidLengthTooShort,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &dnsReader{data: tt.data}

			got, err := reader.readQuestion()

			if tt.wantError != nil {
				if err == nil || !errors.Is(err, tt.wantError) {
					t.Fatalf("readDNSQuestion() error got = %v, want error = %v, data = %v\n", err.Error(), tt.wantError.Error(), tt.data)
				}
				return
			}

			assertQuestion(t, got, tt.want, tt.data)
		})
	}
}

func assertQuestion(t *testing.T, got Question, want Question, data []byte) {
	if got.Name != want.Name {
		t.Errorf("readDNSQuestion() Name got = %s, want = %s, data = %v\n", got.Name, want.Name, data)
	}
	if got.QClass != want.QClass {
		t.Errorf("readDNSQuestion() QClass got = %d, want = %d, data = %v\n", got.QClass, want.QClass, data)
	}
	if got.QType != want.QType {
		t.Errorf("readDNSQuestion() QType got = %d, want = %d, data = %v\n", got.QType, want.QType, data)
	}
}

func TestEncodeDNSQuestion(t *testing.T) {
	tests := []struct {
		name     string
		question Question
		want     []byte
	}{
		{
			name: "A record question",
			question: Question{
				Name:   "example.com",
				QType:  A,
				QClass: IN,
			},
			want: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 1, // QType: 1 (A)
				0, 1, // QClass: 1 (IN)
			},
		},
		{
			name: "AAAA record question",
			question: Question{
				Name:   "example.com",
				QType:  AAAA,
				QClass: IN,
			},
			want: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 28, // QType: 28 (AAAA)
				0, 1, // QClass: 1 (IN)
			},
		},
		{
			name: "CNAME record question",
			question: Question{
				Name:   "www.example.com",
				QType:  CNAME,
				QClass: IN,
			},
			want: []byte{
				3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: www.example.com
				0, 5, // QType: 5 (CNAME)
				0, 1, // QClass: 1 (IN)
			},
		},
		{
			name: "MX record question",
			question: Question{
				Name:   "example.com",
				QType:  MX,
				QClass: IN,
			},
			want: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 15, // QType: 15 (MX)
				0, 1, // QClass: 1 (IN)
			},
		},
		{
			name: "NS record question",
			question: Question{
				Name:   "example.com",
				QType:  NS,
				QClass: IN,
			},
			want: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 2, // QType: 2 (NS)
				0, 1, // QClass: 1 (IN)
			},
		},
		{
			name: "PTR record question",
			question: Question{
				Name:   "34.216.184.93.in-addr.arpa",
				QType:  PTR,
				QClass: IN,
			},
			want: []byte{
				2, '3', '4', 3, '2', '1', '6', 3, '1', '8', '4', 2, '9', '3', 7, 'i', 'n', '-', 'a', 'd', 'd', 'r', 4, 'a', 'r', 'p', 'a', 0, // Name: 34.216.184.93.in-addr.arpa
				0, 12, // QType: 12 (PTR)
				0, 1, // QClass: 1 (IN)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writer := &dnsWriter{
				data:   make([]byte, 1),
				offset: 0,
			}
			writer.writeQuestion(tt.question)
			got := writer.data

			if len(got) != len(tt.want) {
				t.Errorf("encodeDNSQuestion() bytes length got = %d, want = %d\n", len(got), len(tt.want))
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("encodeDNSQuestion() bytes\n\tgot = %v,\n\twant = %v\n", got, tt.want)
			}
		})
	}
}
