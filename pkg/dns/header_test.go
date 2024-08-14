package dns

import (
	"errors"
	"reflect"
	"testing"
)

func TestDecodeFlags(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want Flags
	}{
		{
			name: "All flags off",
			data: []byte{0b00000000, 0b00000000},
			want: Flags{
				Response:           false,
				Opcode:             0,
				Authoritative:      false,
				Truncated:          false,
				RecursionDesired:   false,
				RecursionAvailable: false,
				DnssecOk:           false,
				AuthenticatedData:  false,
				CheckingDisabled:   false,
				ResponseCode:       0,
			},
		},
		{
			name: "Response flag on",
			data: []byte{0b10000000, 0b00000000},
			want: Flags{
				Response:           true,
				Opcode:             0,
				Authoritative:      false,
				Truncated:          false,
				RecursionDesired:   false,
				RecursionAvailable: false,
				DnssecOk:           false,
				AuthenticatedData:  false,
				CheckingDisabled:   false,
				ResponseCode:       0,
			},
		},
		{
			name: "Opcode set to 2",
			data: []byte{0b00010000, 0b00000000},
			want: Flags{
				Response:           false,
				Opcode:             2,
				Authoritative:      false,
				Truncated:          false,
				RecursionDesired:   false,
				RecursionAvailable: false,
				DnssecOk:           false,
				AuthenticatedData:  false,
				CheckingDisabled:   false,
				ResponseCode:       0,
			},
		},
		{
			name: "Authoritative flag on",
			data: []byte{0b00000100, 0b00000000},
			want: Flags{
				Response:           false,
				Opcode:             0,
				Authoritative:      true,
				Truncated:          false,
				RecursionDesired:   false,
				RecursionAvailable: false,
				DnssecOk:           false,
				AuthenticatedData:  false,
				CheckingDisabled:   false,
				ResponseCode:       0,
			},
		},
		{
			name: "Multiple flags on",
			data: []byte{0b10010111, 0b11110011},
			want: Flags{
				Response:           true,
				Opcode:             2,
				Authoritative:      true,
				Truncated:          true,
				RecursionDesired:   true,
				RecursionAvailable: true,
				DnssecOk:           true,
				AuthenticatedData:  true,
				CheckingDisabled:   true,
				ResponseCode:       3,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &dnsReader{data: tt.data}
			got := reader.readFlags()

			assertFlags(t, got, tt.want, tt.data)
		})
	}
}

func TestDecodeDNSHeader(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		wantError error
		want      *Message
	}{
		{
			name: "Basic header decoding",
			data: []byte{
				0x04, 0xd2, // ID: 1234
				0x85, 0x00, // Flags: 10000101 00000000
				0x00, 0x01, // Question Count: 1
				0x00, 0x02, // Answer RR Count: 2
				0x00, 0x03, // Nameserver RR Count: 3
				0x00, 0x04, // Additional RR Count: 4
			},
			wantError: nil,
			want: &Message{
				Header: Header{
					Id: 1234,
					Flags: Flags{
						Response:           true,
						Opcode:             0,
						Authoritative:      true,
						Truncated:          false,
						RecursionDesired:   true,
						RecursionAvailable: false,
						DnssecOk:           false,
						AuthenticatedData:  false,
						CheckingDisabled:   false,
						ResponseCode:       0,
					},
					QuestionCount:     1,
					AnswerRRCount:     2,
					NameserverRRCount: 3,
					AdditionalRRCount: 4,
				},
				Questions:   nil,
				Answers:     nil,
				NameServers: nil,
				Additionals: nil,
			},
		},
		{
			name: "RecursionAvailable flag on",
			data: []byte{
				0x04, 0xd2, // ID: 1234
				0x85, 0x80, // Flags: 10000101 10000000
				0x00, 0x01, // Question Count: 1
				0x00, 0x02, // Answer RR Count: 2
				0x00, 0x03, // Nameserver RR Count: 3
				0x00, 0x04, // Additional RR Count: 4
			},
			wantError: nil,
			want: &Message{
				Header: Header{
					Id: 1234,
					Flags: Flags{
						Response:           true,
						Opcode:             0,
						Authoritative:      true,
						Truncated:          false,
						RecursionDesired:   true,
						RecursionAvailable: true,
						DnssecOk:           false,
						AuthenticatedData:  false,
						CheckingDisabled:   false,
						ResponseCode:       0,
					},
					QuestionCount:     1,
					AnswerRRCount:     2,
					NameserverRRCount: 3,
					AdditionalRRCount: 4,
				},
				Questions:   nil,
				Answers:     nil,
				NameServers: nil,
				Additionals: nil,
			},
		},
		{
			name: "Header too small",
			data: []byte{
				0x04, 0xd2, // ID: 1234
				0x85, 0x80, // Flags: 10000101 10000000
				0x00, 0x01, // Question Count: 1
				0x00, 0x02, // Answer RR Count: 2
				0x00, 0x03, // Nameserver RR Count: 3
			},
			wantError: ErrInvalidHeader,
			want:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &dnsReader{data: tt.data}
			got, err := reader.readHeader()

			if tt.wantError != nil {
				if err == nil || !errors.Is(err, tt.wantError) {
					t.Fatalf("decodeDNSHeader() error got = %v, want error = %v, data = %v\n", err.Error(), tt.wantError.Error(), tt.data)
				}
				return
			}

			assertHeader(t, got, tt.want.Header, tt.data)
			assertFlags(t, got.Flags, tt.want.Header.Flags, tt.data)
		})
	}
}

func assertHeader(t *testing.T, got Header, want Header, data []byte) {
	if got.Id != want.Id {
		t.Errorf("decodeDNSHeader() Id got = %d, want = %d, data = %v\n", got.Id, want.Id, data)
	}
	if got.QuestionCount != want.QuestionCount {
		t.Errorf("decodeDNSHeader() QuestionCount got = %d, want = %d, data = %v\n", got.QuestionCount, want.QuestionCount, data)
	}
	if got.AnswerRRCount != want.AnswerRRCount {
		t.Errorf("decodeDNSHeader() AnswerCount got = %d, want = %d, data = %v\n", got.AnswerRRCount, want.AnswerRRCount, data)
	}
	if got.NameserverRRCount != want.NameserverRRCount {
		t.Errorf("decodeDNSHeader() NameserverCount got = %d, want = %d, data = %v\n", got.NameserverRRCount, want.NameserverRRCount, data)
	}
	if got.AdditionalRRCount != want.AdditionalRRCount {
		t.Errorf("decodeDNSHeader() AdditionalCount got = %d, want = %d, data = %v\n", got.AdditionalRRCount, want.AdditionalRRCount, data)
	}

}

func assertFlags(t *testing.T, got Flags, want Flags, data []byte) {
	if got.Response != want.Response {
		t.Errorf("decodeDNSFlags() QR got = %t, want = %t, data = %v\n", got.Response, want.Response, data)
	}
	if got.Opcode != want.Opcode {
		t.Errorf("decodeDNSFlags() Opcode got = %d, want = %d, data = %v\n", got.Opcode, want.Opcode, data)
	}
	if got.Authoritative != want.Authoritative {
		t.Errorf("decodeDNSFlags() AA got = %t, want = %t, data = %v\n", got.Authoritative, want.Authoritative, data)
	}
	if got.Truncated != want.Truncated {
		t.Errorf("decodeDNSFlags() TC got = %t, want = %t, data = %v\n", got.Authoritative, want.Authoritative, data)
	}
	if got.RecursionDesired != want.RecursionDesired {
		t.Errorf("decodeDNSFlags() RD got = %t, want = %t, data = %v\n", got.RecursionDesired, want.RecursionDesired, data)
	}
	if got.RecursionAvailable != want.RecursionAvailable {
		t.Errorf("decodeDNSFlags() RA got = %t, want = %t, data = %v\n", got.RecursionAvailable, want.RecursionAvailable, data)
	}
	if got.DnssecOk != want.DnssecOk {
		t.Errorf("decodeDNSFlags() DO got = %t, want = %t, data = %v\n", got.DnssecOk, want.DnssecOk, data)
	}
	if got.AuthenticatedData != want.AuthenticatedData {
		t.Errorf("decodeDNSFlags() AD got = %t, want = %t, data = %v\n", got.AuthenticatedData, want.AuthenticatedData, data)
	}
	if got.CheckingDisabled != want.CheckingDisabled {
		t.Errorf("decodeDNSFlags() CD got = %t, want = %t, data = %v\n", got.CheckingDisabled, want.CheckingDisabled, data)
	}
	if got.ResponseCode != want.ResponseCode {
		t.Errorf("decodeDNSFlags() RCode got = %d, want = %d, data = %v\n", got.ResponseCode, want.ResponseCode, data)
	}
}

func TestEncodeFlags(t *testing.T) {
	tests := []struct {
		name string
		data Flags
		want []byte
	}{
		{
			name: "All flags off",
			data: Flags{
				Response:           false,
				Opcode:             0,
				Authoritative:      false,
				Truncated:          false,
				RecursionDesired:   false,
				RecursionAvailable: false,
				DnssecOk:           false,
				AuthenticatedData:  false,
				CheckingDisabled:   false,
				ResponseCode:       0,
			},
			want: []byte{0b00000000, 0b00000000},
		},
		{
			name: "Response flag on",
			data: Flags{
				Response:           true,
				Opcode:             0,
				Authoritative:      false,
				Truncated:          false,
				RecursionDesired:   false,
				RecursionAvailable: false,
				DnssecOk:           false,
				AuthenticatedData:  false,
				CheckingDisabled:   false,
				ResponseCode:       0,
			},
			want: []byte{0b10000000, 0b00000000},
		},
		{
			name: "Opcode set to 2",
			data: Flags{
				Response:           false,
				Opcode:             2,
				Authoritative:      false,
				Truncated:          false,
				RecursionDesired:   false,
				RecursionAvailable: false,
				DnssecOk:           false,
				AuthenticatedData:  false,
				CheckingDisabled:   false,
				ResponseCode:       0,
			},
			want: []byte{0b00010000, 0b00000000},
		},
		{
			name: "Authoritative flag on",
			data: Flags{
				Response:           false,
				Opcode:             0,
				Authoritative:      true,
				Truncated:          false,
				RecursionDesired:   false,
				RecursionAvailable: false,
				DnssecOk:           false,
				AuthenticatedData:  false,
				CheckingDisabled:   false,
				ResponseCode:       0,
			},
			want: []byte{0b00000100, 0b00000000},
		},
		{
			name: "Multiple flags on",
			data: Flags{
				Response:           true,
				Opcode:             2,
				Authoritative:      true,
				Truncated:          true,
				RecursionDesired:   true,
				RecursionAvailable: true,
				DnssecOk:           true,
				AuthenticatedData:  true,
				CheckingDisabled:   true,
				ResponseCode:       3,
			},
			want: []byte{0b10010111, 0b11110011},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writer := &dnsWriter{
				data:   make([]byte, 2),
				offset: 0,
			}
			writer.writeFlags(tt.data)
			got := writer.data

			if len(got) != len(tt.want) {
				t.Errorf("encodeDNSFlags() bytes length got = %d, want = %d\n", len(got), len(tt.want))
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("encodeDNSFlags() bytes got = %v, want = %v\n", got, tt.want)
			}
		})
	}
}

func TestEncodeDNSHeader(t *testing.T) {
	tests := []struct {
		name string
		data Message
		want []byte
	}{
		{
			name: "Basic header encoding",
			data: Message{
				Header: Header{
					Id: 1234,
					Flags: Flags{
						Response:           true,
						Opcode:             0,
						Authoritative:      true,
						Truncated:          false,
						RecursionDesired:   true,
						RecursionAvailable: false,
						DnssecOk:           false,
						AuthenticatedData:  false,
						CheckingDisabled:   false,
						ResponseCode:       0,
					},
					QuestionCount:     1,
					AnswerRRCount:     2,
					NameserverRRCount: 3,
					AdditionalRRCount: 4,
				},
				Questions:   nil,
				Answers:     nil,
				NameServers: nil,
				Additionals: nil,
			},
			want: []byte{
				0x04, 0xd2, // ID: 1234
				0x85, 0x00, // Flags: 10000101 00000000
				0x00, 0x01, // Question Count: 1
				0x00, 0x02, // Answer RR Count: 2
				0x00, 0x03, // Nameserver RR Count: 3
				0x00, 0x04, // Additional RR Count: 4
			},
		},
		{
			name: "RecursionAvailable flag on",
			data: Message{
				Header: Header{
					Id: 1234,
					Flags: Flags{
						Response:           true,
						Opcode:             0,
						Authoritative:      true,
						Truncated:          false,
						RecursionDesired:   true,
						RecursionAvailable: true,
						DnssecOk:           false,
						AuthenticatedData:  false,
						CheckingDisabled:   false,
						ResponseCode:       0,
					},
					QuestionCount:     1,
					AnswerRRCount:     2,
					NameserverRRCount: 3,
					AdditionalRRCount: 4,
				},
				Questions:   nil,
				Answers:     nil,
				NameServers: nil,
				Additionals: nil,
			},
			want: []byte{
				0x04, 0xd2, // ID: 1234
				0x85, 0x80, // Flags: 10000101 10000000
				0x00, 0x01, // Question Count: 1
				0x00, 0x02, // Answer RR Count: 2
				0x00, 0x03, // Nameserver RR Count: 3
				0x00, 0x04, // Additional RR Count: 4
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writer := &dnsWriter{
				data:   make([]byte, 1),
				offset: 0,
			}
			writer.writeHeader(tt.data)
			got := writer.data

			if len(got) != len(tt.want) {
				t.Errorf("encodeDNSHeader() bytes length got = %d, want = %d\n", len(got), len(tt.want))
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("encodeDNSHeader() bytes\n\tgot = %v,\n\twant = %v\n", got, tt.want)
			}
		})
	}
}
