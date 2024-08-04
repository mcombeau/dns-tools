package dns

import (
	"bytes"
	"errors"
	"net"
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
				IP: net.ParseIP("192.1.0.1"),
			},
			wantError: nil,
		},
		{
			name:      "Invalid A record",
			data:      []byte{192, 1, 0, 1, 1},
			want:      &RDataA{},
			wantError: ErrInvalidRecordData,
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
			if !got.IP.Equal(want.IP) {
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
				IP: net.ParseIP("2001:db8::1"),
			},
			wantError: nil,
		},
		{
			name: "Invalid AAAA record",
			data: []byte{32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0},
			want: &RDataAAAA{
				IP: net.ParseIP("2001:db8::1"),
			},
			wantError: ErrInvalidRecordData,
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
			if !got.IP.Equal(want.IP) {
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
				domainName: "example.com.",
			},
			wantError: nil,
		},
		{
			name: "Invalid CNAME record",
			data: []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm'},
			want: &RDataCNAME{
				domainName: "example.com.",
			},
			wantError: ErrInvalidRecordData,
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
			if got.domainName != want.domainName {
				t.Errorf("Decode() domain name got = %s, want = %s, data = %v\n", got.domainName, want.domainName, tt.data)
			}

			// Test String
			gotString := got.String()
			if gotString != want.domainName {
				t.Errorf("String() got = \"%s\", want = \"%s\", data = %v\n", gotString, want.domainName, tt.data)
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
				text: "test",
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
			if got.text != want.text {
				t.Errorf("Decode() text got = %s, want = %s, data = %v\n", got.text, want.text, tt.data)
			}

			// Test String
			gotString := got.String()
			if gotString != want.text {
				t.Errorf("String() got = \"%s\", want = \"%s\", data = %v\n", gotString, want.text, tt.data)
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
				preference: 10,
				domainName: "mx1.example.com.",
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
				preference: 10,
				domainName: "mx1.example.com.",
			},
			wantError: ErrInvalidRecordData,
		},
		{
			name: "Invalid MX record: missing field",
			data: []byte{
				3, 'm', 'x', '1', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
			},
			want: &RDataMX{
				preference: 10,
				domainName: "mx1.example.com.",
			},
			wantError: ErrInvalidRecordData,
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
			if got.preference != want.preference {
				t.Errorf("Decode() preference got = %d, want = %d, data = %v\n", got.preference, want.preference, tt.data)
			}
			if got.domainName != want.domainName {
				t.Errorf("Decode() domainName got = %s, want = %s, data = %v\n", got.domainName, want.domainName, tt.data)
			}

			// Test String
			gotString := got.String()
			wantString := strconv.Itoa(int(want.preference)) + " " + want.domainName
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
				mName:   "ns1.example.com.",
				rName:   "admin.example.com.",
				serial:  202,
				refresh: 300,
				retry:   100,
				expire:  2560,
				minimum: 256,
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
			wantError: ErrInvalidRecordData,
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
			if got.mName != want.mName {
				t.Errorf("Decode() mName got = %s, want = %s, data = %v\n", got.mName, want.mName, tt.data)
			}
			if got.rName != want.rName {
				t.Errorf("Decode() rName got = %s, want = %s, data = %v\n", got.rName, want.rName, tt.data)
			}
			if got.serial != want.serial {
				t.Errorf("Decode() serial got = %d, want = %d, data = %v\n", got.serial, want.serial, tt.data)
			}
			if got.refresh != want.refresh {
				t.Errorf("Decode() refresh got = %d, want = %d, data = %v\n", got.refresh, want.refresh, tt.data)
			}
			if got.retry != want.retry {
				t.Errorf("Decode() retry got = %d, want = %d, data = %v\n", got.retry, want.retry, tt.data)
			}
			if got.expire != want.expire {
				t.Errorf("Decode() expire got = %d, want = %d, data = %v\n", got.expire, want.expire, tt.data)
			}
			if got.minimum != want.minimum {
				t.Errorf("Decode() minimum got = %d, want = %d, data = %v\n", got.minimum, want.minimum, tt.data)
			}

			// Test String
			gotString := got.String()
			wantString := want.mName + " " + want.rName + " " + strconv.Itoa(int(want.serial)) + " " + strconv.Itoa(int(want.refresh)) + " " + strconv.Itoa(int(want.retry)) + " " + strconv.Itoa(int(want.expire)) + " " + strconv.Itoa(int(want.minimum))
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
