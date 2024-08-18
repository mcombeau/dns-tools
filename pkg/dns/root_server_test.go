package dns

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseRootServerHints(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      []Server
		wantError error
	}{
		{
			name: "Valid input with IPv4 and IPv6",
			input: `
.                        3600000      NS    A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:ba3e::2:30
      `,
			want: []Server{
				{
					Fqdn: "A.ROOT-SERVERS.NET.",
					IPv4: netip.MustParseAddr("198.41.0.4"),
					IPv6: netip.MustParseAddr("2001:503:ba3e::2:30"),
				},
			},
			wantError: nil,
		},
		{
			name: "Valid input with comments and IPv4 and IPv6",
			input: `
;
.                        3600000      NS    A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:ba3e::2:30
; 
; FORMERLY NS1.ISI.EDU 
;
      `,
			want: []Server{
				{
					Fqdn: "A.ROOT-SERVERS.NET.",
					IPv4: netip.MustParseAddr("198.41.0.4"),
					IPv6: netip.MustParseAddr("2001:503:ba3e::2:30"),
				},
			},
			wantError: nil,
		},
		{
			name: "Valid input with IPv4 only",
			input: `
;
.                        3600000      NS    A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
; 
; FORMERLY NS1.ISI.EDU 
;
      `,
			want: []Server{
				{
					Fqdn: "A.ROOT-SERVERS.NET.",
					IPv4: netip.MustParseAddr("198.41.0.4"),
				},
			},
			wantError: nil,
		},
		{
			name: "Valid input with IPv6 only",
			input: `
.                        3600000      NS    A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:ba3e::2:30
      `,
			want: []Server{
				{
					Fqdn: "A.ROOT-SERVERS.NET.",
					IPv6: netip.MustParseAddr("2001:503:ba3e::2:30"),
				},
			},
			wantError: nil,
		},
		{
			name: "Input with missing IPv6 field",
			input: `
.                        3600000      NS    A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
A.ROOT-SERVERS.NET.      3600000      AAAA
      `,
			want: []Server{
				{
					Fqdn: "A.ROOT-SERVERS.NET.",
					IPv4: netip.MustParseAddr("198.41.0.4"),
				},
			},
			wantError: nil,
		},
		{
			name: "Invalid input with invalid IPv4",
			input: `
.                        3600000      NS    A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      A     198.41.0.
      `,
			want:      []Server{},
			wantError: nil,
		},
		{
			name: "Invalid input with no FQDN",
			input: `
A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:ba3e::2:30
      `,
			want:      []Server{},
			wantError: nil,
		},
		{
			name: "Invalid input with missing type field",
			input: `
.                        3600000      A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      198.41.0.4
      `,
			want:      []Server{},
			wantError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.input)
			got, err := ParseRootServerHints(reader)

			if err != nil && err != tt.wantError {
				t.Fatalf("ParseRootServerHints() error = %v, wantError %v, input: %s", err, tt.wantError, tt.input)
				return
			}

			if len(got) != len(tt.want) {
				t.Errorf("ParseRootServerHints () got %d root servers, want %d, input: %s", len(got), len(tt.want), tt.input)
			}

			for i, want := range tt.want {
				if got[i].Fqdn != want.Fqdn {
					t.Errorf("ParseRootServerHints () got fqdn: %s, want %s, input: %s", got[i].Fqdn, want.Fqdn, tt.input)
				}
				if got[i].IPv4 != want.IPv4 {
					t.Errorf("ParseRootServerHints () got IPv4: %v, want %v, input: %s", got[i].IPv4, want.IPv4, tt.input)
				}
				if got[i].IPv6 != want.IPv6 {
					t.Errorf("ParseRootServerHints () got IPv4: %v, want %v, input: %s", got[i].IPv6, want.IPv6, tt.input)
				}
			}
		})
	}
}

func FuzzParseRootServerHints(f *testing.F) {
	f.Add(`
.                        3600000      NS    A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:ba3e::2:30
    `)
	f.Add(`
; 
; FORMERLY NS.INTERNIC.NET 
;
    `)
	f.Add(`
; OPERATED BY ICANN
;
.                        3600000      NS    L.ROOT-SERVERS.NET.
L.ROOT-SERVERS.NET.      3600000      A     199.7.83.42
L.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:9f::42
; 
; OPERATED BY WIDE
;
.                        3600000      NS    M.ROOT-SERVERS.NET.
M.ROOT-SERVERS.NET.      3600000      A     202.12.27.33
M.ROOT-SERVERS.NET.      3600000      AAAA  2001:dc3::35
; End of file
    `)
	f.Add(`
;
;       last update:     August 14, 2024
;       related version of root zone:     2024081401
    `)

	f.Fuzz(func(t *testing.T, data string) {
		reader := strings.NewReader(data)

		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic occured: %v", r)
			}
		}()

		got, err := ParseRootServerHints(reader)
		if err != nil {
			t.Logf("Error: %v", err)
		}

		for _, server := range got {
			if server.Fqdn == "" {
				t.Errorf("ParseRootServerHints() returned a server with an empty FQDN")
			}
			if !server.IPv4.IsValid() && !server.IPv6.IsValid() {
				t.Errorf("ParseRootServerHints() returned a server with no valid IP addresses")
			}
		}
	})
}
