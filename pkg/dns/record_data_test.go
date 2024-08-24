package dns

import (
	"bytes"
	"errors"
	"net/netip"
	"strconv"
	"testing"
)

func TestRDataA(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		want      RData
		wantError error
	}{
		{
			name: "A record",
			data: []byte{192, 1, 0, 1},
			want: &RDataA{
				IP: netip.AddrFrom4([4]byte{192, 1, 0, 1}), // 192.1.0.1
			},
			wantError: nil,
		},
		{
			name:      "Invalid A record",
			data:      []byte{192, 1, 0, 1, 1},
			want:      &RDataA{},
			wantError: ErrInvalidIP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got RDataA
			reader := &dnsReader{data: tt.data}

			err := got.ReadRecordData(reader, uint16(len(tt.data)))

			if tt.wantError != nil {
				if err == nil || !errors.Is(err, tt.wantError) {
					t.Fatalf("Decode() error = %v, want error = %v, data = %v\n", err.Error(), tt.wantError.Error(), tt.data)
				}
				return
			}

			want, ok := tt.want.(*RDataA)
			if !ok {
				t.Fatalf("want is not of type *RDataA, got %T", tt.want)
			}

			// Test Decode
			if got.IP != want.IP {
				t.Errorf("Decode() IP got = %v, want = %v, data = %v\n", got.IP, want.IP, tt.data)
			}

			// Test String
			gotString := got.String()
			if gotString != want.IP.String() {
				t.Errorf("String() got = \"%s\", want = \"%s\", data = %v\n", gotString, want.IP.String(), tt.data)
			}

			// Test Encode
			writer := &dnsWriter{
				data:   make([]byte, 1),
				offset: 0,
			}
			if err := got.WriteRecordData(writer); err != nil {
				t.Fatalf("Encode() error = %v, data = %v\n", err, tt.data)
			}

			if !bytes.Equal(writer.data, tt.data) {
				t.Errorf("Encode() got = %v, want = %v\n", writer.data, tt.data)
			}
		})
	}
}

func TestRDataAAAA(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		want      RData
		wantError error
	}{
		{
			name: "AAAA record",
			data: []byte{32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			want: &RDataAAAA{
				IP: netip.AddrFrom16([16]byte{32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}), //2001:db8::1
			},
			wantError: nil,
		},
		{
			name:      "Invalid AAAA record: bad IP",
			data:      []byte{32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0},
			want:      &RDataAAAA{},
			wantError: ErrInvalidIP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got RDataAAAA
			reader := &dnsReader{data: tt.data}

			err := got.ReadRecordData(reader, uint16(len(tt.data)))

			if tt.wantError != nil {
				if err == nil || !errors.Is(err, tt.wantError) {
					t.Fatalf("Decode() error = %v, want error = %v, data = %v\n", err.Error(), tt.wantError.Error(), tt.data)
				}
				return
			}

			want, ok := tt.want.(*RDataAAAA)
			if !ok {
				t.Fatalf("want is not of type *RDataAAAA, got %T", tt.want)
			}

			// Test Decode
			if got.IP != want.IP {
				t.Errorf("Decode() IP got = %v, want = %v, data = %v\n", got.IP, want.IP, tt.data)
			}

			// Test String
			gotString := got.String()
			if gotString != want.IP.String() {
				t.Errorf("String() got = \"%s\", want = \"%s\", data = %v\n", gotString, want.IP.String(), tt.data)
			}

			// Test Encode
			writer := &dnsWriter{
				data:   make([]byte, 1),
				offset: 0,
			}
			if err := got.WriteRecordData(writer); err != nil {
				t.Fatalf("Encode() error = %v, data = %v\n", err, tt.data)
			}

			if !bytes.Equal(writer.data, tt.data) {
				t.Errorf("Encode() got = %v, want = %v\n", writer.data, tt.data)
			}
		})
	}
}

func TestRDataCNAME(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		want      RData
		wantError error
	}{
		{
			name: "CNAME record",
			data: []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			want: &RDataCNAME{
				DomainName: "example.com.",
			},
			wantError: nil,
		},
		{
			name: "Invalid CNAME record",
			data: []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm'},
			want: &RDataCNAME{
				DomainName: "example.com.",
			},
			wantError: ErrOffsetOutOfBounds,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got RDataCNAME
			reader := &dnsReader{data: tt.data}

			err := got.ReadRecordData(reader, uint16(len(tt.data)))

			if tt.wantError != nil {
				if err == nil || !errors.Is(err, tt.wantError) {
					t.Fatalf("Decode() error = %v, want error = %v, data = %v\n", err.Error(), tt.wantError.Error(), tt.data)
				}
				return
			}

			want, ok := tt.want.(*RDataCNAME)
			if !ok {
				t.Fatalf("want is not of type *RDataCNAME, got %T", tt.want)
			}

			// Test Decode
			if got.DomainName != want.DomainName {
				t.Errorf("Decode() domain name got = %s, want = %s, data = %v\n", got.DomainName, want.DomainName, tt.data)
			}

			// Test String
			gotString := got.String()
			if gotString != want.DomainName {
				t.Errorf("String() got = \"%s\", want = \"%s\", data = %v\n", gotString, want.DomainName, tt.data)
			}

			// Test Encode
			writer := &dnsWriter{
				data:   make([]byte, 1),
				offset: 0,
			}
			if err := got.WriteRecordData(writer); err != nil {
				t.Fatalf("Encode() error = %v, data = %v\n", err, tt.data)
			}

			if !bytes.Equal(writer.data, tt.data) {
				t.Errorf("Encode() got = %v, want = %v\n", writer.data, tt.data)
			}
		})
	}
}

func TestRDataTXT(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		want      RData
		wantError error
	}{
		{
			name: "TXT record",
			data: []byte{
				't', 'e', 's', 't', // TXT data: "test"
			},
			want: &RDataTXT{
				Text: "test",
			},
			wantError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got RDataTXT
			reader := &dnsReader{data: tt.data}

			err := got.ReadRecordData(reader, uint16(len(tt.data)))

			if tt.wantError != nil {
				if err == nil || !errors.Is(err, tt.wantError) {
					t.Fatalf("Decode() error = %v, want error = %v, data = %v\n", err.Error(), tt.wantError.Error(), tt.data)
				}
				return
			}

			want, ok := tt.want.(*RDataTXT)
			if !ok {
				t.Fatalf("want is not of type *RDataTXT, got %T", tt.want)
			}

			// Test Decode
			if got.Text != want.Text {
				t.Errorf("Decode() text got = %s, want = %s, data = %v\n", got.Text, want.Text, tt.data)
			}

			// Test String
			gotString := got.String()
			if gotString != want.Text {
				t.Errorf("String() got = \"%s\", want = \"%s\", data = %v\n", gotString, want.Text, tt.data)
			}

			// Test Encode
			writer := &dnsWriter{
				data:   make([]byte, 1),
				offset: 0,
			}
			if err := got.WriteRecordData(writer); err != nil {
				t.Fatalf("Encode() error = %v, data = %v\n", err, tt.data)
			}

			if !bytes.Equal(writer.data, tt.data) {
				t.Errorf("Encode() got = %v, want = %v\n", writer.data, tt.data)
			}
		})
	}
}

func TestRDataMX(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		want      RData
		wantError error
	}{
		{
			name: "MX record",
			data: []byte{
				0, 10,
				3, 'm', 'x', '1', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
			},
			want: &RDataMX{
				Preference: 10,
				DomainName: "mx1.example.com.",
			},
			wantError: nil,
		},
		{
			name: "Invalid MX record: bad domain name",
			data: []byte{
				0, 10,
				3, 'm', 'x', '1', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm',
			},
			want: &RDataMX{
				Preference: 10,
				DomainName: "mx1.example.com.",
			},
			wantError: ErrOffsetOutOfBounds,
		},
		{
			name: "Invalid MX record: missing field",
			data: []byte{
				3, 'm', 'x', '1', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
			},
			want: &RDataMX{
				Preference: 10,
				DomainName: "mx1.example.com.",
			},
			wantError: ErrOffsetOutOfBounds,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got RDataMX
			reader := &dnsReader{data: tt.data}

			err := got.ReadRecordData(reader, uint16(len(tt.data)))

			if tt.wantError != nil {
				if err == nil || !errors.Is(err, tt.wantError) {
					t.Fatalf("Decode() error = %v, want error = %v, data = %v\n", err.Error(), tt.wantError.Error(), tt.data)
				}
				return
			}

			want, ok := tt.want.(*RDataMX)
			if !ok {
				t.Fatalf("want is not of type *RDataMX, got %T", tt.want)
			}

			// Test Decode
			if got.Preference != want.Preference {
				t.Errorf("Decode() preference got = %d, want = %d, data = %v\n", got.Preference, want.Preference, tt.data)
			}
			if got.DomainName != want.DomainName {
				t.Errorf("Decode() domainName got = %s, want = %s, data = %v\n", got.DomainName, want.DomainName, tt.data)
			}

			// Test String
			gotString := got.String()
			wantString := strconv.Itoa(int(want.Preference)) + " " + want.DomainName
			if gotString != wantString {
				t.Errorf("String() got = \"%s\", want = \"%s\", data = %v\n", gotString, wantString, tt.data)
			}

			// Test Encode
			writer := &dnsWriter{
				data:   make([]byte, 1),
				offset: 0,
			}
			if err := got.WriteRecordData(writer); err != nil {
				t.Fatalf("Encode() error = %v, data = %v\n", err, tt.data)
			}

			if !bytes.Equal(writer.data, tt.data) {
				t.Errorf("Encode() got = %v, want = %v\n", writer.data, tt.data)
			}
		})
	}
}

func TestRDataSOA(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		want      RData
		wantError error
	}{
		{
			name: "SOA record",
			data: []byte{
				3, 'n', 's', '1', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // MName: ns1.example.com
				5, 'a', 'd', 'm', 'i', 'n', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // RName: admin.example.com
				0, 0, 0, 202, // Serial: 202
				0, 0, 1, 44, // Refresh: 300
				0, 0, 0, 100, // Retry: 100
				0, 0, 10, 0, // Expire: 2560
				0, 0, 1, 0, // Minimum: 256
			},
			want: &RDataSOA{
				MName:   "ns1.example.com.",
				RName:   "admin.example.com.",
				Serial:  202,
				Refresh: 300,
				Retry:   100,
				Expire:  2560,
				Minimum: 256,
			},
			wantError: nil,
		},
		{
			name: "Invalid SOA record: bad domain name",
			data: []byte{
				3, 'n', 's', '1', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // MName: ns1.example.com
				5, 'a', 'd', 'm', 'i', 'n', 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // RName: admin.example.com
				0, 0, 0, 202, // Serial: 202
				0, 0, 1, 44, // Refresh: 300
				0, 0, 0, 100, // Retry: 100
				0, 0, 10, 0, // Expire: 2560
				0, 0, 1, 0, // Minimum: 256
			},
			want:      &RDataSOA{},
			wantError: ErrOffsetOutOfBounds,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got RDataSOA
			reader := &dnsReader{data: tt.data}

			err := got.ReadRecordData(reader, uint16(len(tt.data)))

			if tt.wantError != nil {
				if err == nil || !errors.Is(err, tt.wantError) {
					t.Fatalf("Decode() error = %v, want error = %v, data = %v\n", err.Error(), tt.wantError.Error(), tt.data)
				}
				return
			}

			want, ok := tt.want.(*RDataSOA)
			if !ok {
				t.Fatalf("want is not of type *RDataSOA, got %T", tt.want)
			}

			// Test Decode
			if got.MName != want.MName {
				t.Errorf("Decode() mName got = %s, want = %s, data = %v\n", got.MName, want.MName, tt.data)
			}
			if got.RName != want.RName {
				t.Errorf("Decode() rName got = %s, want = %s, data = %v\n", got.RName, want.RName, tt.data)
			}
			if got.Serial != want.Serial {
				t.Errorf("Decode() serial got = %d, want = %d, data = %v\n", got.Serial, want.Serial, tt.data)
			}
			if got.Refresh != want.Refresh {
				t.Errorf("Decode() refresh got = %d, want = %d, data = %v\n", got.Refresh, want.Refresh, tt.data)
			}
			if got.Retry != want.Retry {
				t.Errorf("Decode() retry got = %d, want = %d, data = %v\n", got.Retry, want.Retry, tt.data)
			}
			if got.Expire != want.Expire {
				t.Errorf("Decode() expire got = %d, want = %d, data = %v\n", got.Expire, want.Expire, tt.data)
			}
			if got.Minimum != want.Minimum {
				t.Errorf("Decode() minimum got = %d, want = %d, data = %v\n", got.Minimum, want.Minimum, tt.data)
			}

			// Test String
			gotString := got.String()
			wantString := want.MName + " " + want.RName + " " + strconv.Itoa(int(want.Serial)) + " " + strconv.Itoa(int(want.Refresh)) + " " + strconv.Itoa(int(want.Retry)) + " " + strconv.Itoa(int(want.Expire)) + " " + strconv.Itoa(int(want.Minimum))
			if gotString != wantString {
				t.Errorf("String() got = \"%s\", want = \"%s\", data = %v\n", gotString, wantString, tt.data)
			}

			// Test Encode
			writer := &dnsWriter{
				data:   make([]byte, 1),
				offset: 0,
			}
			if err := got.WriteRecordData(writer); err != nil {
				t.Fatalf("Encode() error = %v, data = %v\n", err, tt.data)
			}

			if !bytes.Equal(writer.data, tt.data) {
				t.Errorf("Encode() got = %v, want = %v\n", writer.data, tt.data)
			}
		})
	}
}
