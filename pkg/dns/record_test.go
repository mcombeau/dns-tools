package dns

import (
	"errors"
	"net/netip"
	"testing"
)

func TestDecodeResourceRecord(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		want      ResourceRecord
		wantError error
	}{
		{
			name: "A record",
			data: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 1, // RType: 1
				0, 1, // RClass: 1
				0, 0, 1, 44, // TTL: 300
				0, 4, // RDLength: 4
				93, 184, 216, 34, // RData: 93.184.216.34
			},
			want: ResourceRecord{
				Name:     "example.com.",
				RType:    A,
				RClass:   IN,
				TTL:      300,
				RDLength: 4,
				RData: &RDataA{
					IP: netip.AddrFrom4([4]byte{93, 184, 216, 34}), // 93.184.216.34
				},
			},
			wantError: nil,
		},
		{
			name: "AAAA record",
			data: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 28, // RType: 28 (AAAA)
				0, 1, // RClass: 1
				0, 0, 1, 44, // TTL: 300
				0, 16, // RDLength: 16
				32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // RData: 2001:db8::1
			},
			want: ResourceRecord{
				Name:     "example.com.",
				RType:    AAAA,
				RClass:   IN,
				TTL:      300,
				RDLength: 16,
				RData: &RDataAAAA{
					IP: netip.AddrFrom16([16]byte{32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}), //2001:db8::1
				},
			},
			wantError: nil,
		},
		{
			name: "CNAME record",
			data: []byte{
				3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: www.example.com
				0, 5, // RType: 5 (CNAME)
				0, 1, // RClass: 1
				0, 0, 1, 44, // TTL: 300
				0, 13, // RDLength: 13
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // RData: example.com
			},
			want: ResourceRecord{
				Name:     "www.example.com.",
				RType:    CNAME,
				RClass:   IN,
				TTL:      300,
				RDLength: 13,
				RData: &RDataCNAME{
					DomainName: "example.com.",
				},
			},
			wantError: nil,
		},
		{
			name: "PTR record",
			data: []byte{
				3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: www.example.com
				0, 12, // RType: 12 (PTR)
				0, 1, // RClass: 1
				0, 0, 1, 44, // TTL: 300
				0, 13, // RDLength: 13
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // RData: example.com
			},
			want: ResourceRecord{
				Name:     "www.example.com.",
				RType:    PTR,
				RClass:   IN,
				TTL:      300,
				RDLength: 13,
				RData: &RDataPTR{
					DomainName: "example.com.",
				},
			},
			wantError: nil,
		},
		{
			name: "NS record",
			data: []byte{
				3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: www.example.com
				0, 2, // RType: 2 (NS)
				0, 1, // RClass: 1
				0, 0, 1, 44, // TTL: 300
				0, 16, // RDLength: 16
				2, 'n', 's', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // RData: example.com
			},
			want: ResourceRecord{
				Name:     "www.example.com.",
				RType:    NS,
				RClass:   IN,
				TTL:      300,
				RDLength: 16,
				RData: &RDataNS{
					DomainName: "ns.example.com.",
				},
			},
			wantError: nil,
		},
		{
			name: "TXT record",
			data: []byte{
				3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: www.example.com
				0, 16, // RType: 16 (TXT)
				0, 1, // RClass: 1
				0, 0, 1, 44, // TTL: 300
				0, 10, // RDLength: 10
				'h', 'e', 'l', 'l', 'o', 'w', 'o', 'r', 'l', 'd', // RData: helloworld
			},
			want: ResourceRecord{
				Name:     "www.example.com.",
				RType:    TXT,
				RClass:   IN,
				TTL:      300,
				RDLength: 10,
				RData: &RDataTXT{
					Text: "helloworld",
				},
			},
			wantError: nil,
		},
		{
			name: "MX record",
			data: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 15, // RType: 15 (MX)
				0, 1, // RClass: 1
				0, 0, 1, 44, // TTL: 300
				0, 20, // RDLength: 16
				0, 10, // Preference: 10
				4, 'm', 'a', 'i', 'l', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // RData: mail.example.com
			},
			want: ResourceRecord{
				Name:     "example.com.",
				RType:    MX,
				RClass:   IN,
				TTL:      300,
				RDLength: 20,
				RData: &RDataMX{
					Preference: 10,
					DomainName: "mail.example.com.",
				},
			},
			wantError: nil,
		},
		{
			name: "SOA record",
			data: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 6, // RType: 6 (SOA)
				0, 1, // RClass: 1 (IN)
				0, 0, 1, 44, // TTL: 300
				0, 39, // RDLength: 39
				3, 'n', 's', '1', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // MName: ns1.example.com
				5, 'a', 'd', 'm', 'i', 'n', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // RName: admin.example.com
				0, 0, 0, 202, // Serial: 202
				0, 0, 1, 44, // Refresh: 300
				0, 0, 0, 100, // Retry: 100
				0, 0, 10, 0, // Expire: 2560
				0, 0, 1, 0, // Minimum: 256
			},
			want: ResourceRecord{
				Name:     "example.com.",
				RType:    SOA,
				RClass:   IN,
				TTL:      300,
				RDLength: 39,
				RData: &RDataSOA{
					MName:   "ns1.example.com.",
					RName:   "admin.example.com.",
					Serial:  202,
					Refresh: 300,
					Retry:   100,
					Expire:  2560,
					Minimum: 256,
				},
			},
			wantError: nil,
		},
		{
			name: "Invalid A record: bad domain encoding",
			data: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', // Name: example.com
				0, 1, // RType: 1
				0, 1, // RClass: 1
				0, 0, 1, 44, // TTL: 300
				0, 4, // RDLength: 4
				93, 184, 216, 34, // RData: 93.184.216.34
			},
			want:      ResourceRecord{},
			wantError: ErrInvalidLengthTooShort,
		},
		{
			name: "Invalid A record: missing data field",
			data: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name: example.com
				0, 1, // RType: 1
				0, 1, // RClass: 1
				0, 0, 1, 44, // TTL: 300
				0, 4, // RDLength: 4
				// Missing RData
			},
			want:      ResourceRecord{},
			wantError: ErrInvalidLengthTooShort,
		},
		{
			name: "Unknown record",
			data: []byte{
				0,    // Name: 0
				0, 3, // RType: 3 (MD - Obsolete)
				0, 1, // RClass: 1
				0, 0, 1, 44, // TTL: 300
				0, 5, // RDLength: 5
				'h', 'e', 'l', 'l', 'o', // RData: some bytes
			},
			want: ResourceRecord{
				Name:     ".",
				RType:    MD,
				RClass:   IN,
				TTL:      300,
				RDLength: 5,
				RData: &RDataUnknown{
					Raw: []byte{'h', 'e', 'l', 'l', 'o'},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &dnsReader{data: tt.data}

			got, err := reader.readResourceRecord()

			if tt.wantError != nil {
				if err == nil || !errors.Is(err, tt.wantError) {
					t.Fatalf("decodeDNSResourceRecord() error = %v, want error = %v, data = %v\n", err.Error(), tt.wantError.Error(), tt.data)
				}
				return
			}

			assertRessourceRecord(t, got, tt.want, tt.data)
		})
	}
}

func assertRessourceRecord(t *testing.T, got ResourceRecord, want ResourceRecord, data []byte) {
	if got.Name != want.Name {
		t.Errorf("decodeDNSResourceRecord() Name got = %s, want = %s, data = %v\n", got.Name, want.Name, data)
	}
	if got.RType != want.RType {
		t.Errorf("decodeDNSResourceRecord() RType got = %d, want = %d, data = %v\n", got.RType, want.RType, data)
	}
	if got.RClass != want.RClass {
		t.Errorf("decodeDNSResourceRecord() RClass got = %d, want = %d, data = %v\n", got.RClass, want.RClass, data)
	}
	if got.TTL != want.TTL {
		t.Errorf("decodeDNSResourceRecord() TTL got = %d, want = %d, data = %v\n", got.TTL, want.TTL, data)
	}
	if got.RDLength != want.RDLength {
		t.Errorf("decodeDNSResourceRecord() RDLength got = %d, want = %d, data = %v\n", got.RDLength, want.RDLength, data)
	}
	if got.RData.String() != want.RData.String() {
		t.Errorf("decodeDNSResourceRecord() RData got = %s, want = %s, data = %v\n", got.RData.String(), want.RData.String(), data)
	}
}
