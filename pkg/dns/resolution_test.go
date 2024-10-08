package dns_test

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/mcombeau/dns-tools/pkg/dns"
)

const testRootServerHintsFile = "../../config/named.root"

func TestResolveQuery(t *testing.T) {
	// Define the test cases
	testCases := []struct {
		name         string
		mockFunction func(string, netip.AddrPort, []byte) ([]byte, error)
		queryFqdn    string
		wantResponse dns.Message
		wantError    error
	}{
		{
			name:         "Test immediate NoError answer",
			mockFunction: mockResponseImmediateNoErrorAnswer,
			queryFqdn:    "example.com.",
			wantResponse: createNoErrorAuthoritativeAnswer(updateTestQueryDomain("example.com."), authoritativeAnswerIP),
			wantError:    nil,
		},
		{
			name:         "Test response: additional -> NoError answer",
			mockFunction: mockResponseAdditionalSectionToNoErrorAnswer,
			queryFqdn:    "toto.example.com.",
			wantResponse: createNoErrorAuthoritativeAnswer(updateTestQueryDomain("toto.example.com."), authoritativeAnswerIP),
			wantError:    nil,
		},
		{
			name:         "Test response: authority NS -> NoError answer -> NoError answer",
			mockFunction: mockResponseAuthoritySectionToNoErrorAnswer,
			queryFqdn:    "titi.example.com.",
			wantResponse: createNoErrorAuthoritativeAnswer(updateTestQueryDomain("titi.example.com."), authoritativeAnswerIP),
			wantError:    nil,
		},
		{
			name:         "Test immediate SOA answer",
			mockFunction: mockResponseImmediateSOAAnswer,
			queryFqdn:    "tata.example.com.",
			wantResponse: createSOAAuthoritativeAnswer(updateTestQueryDomain("tata.example.com."), dns.NOERROR),
			wantError:    nil,
		},
		{
			name:         "Test immediate NXDOMAIN answer",
			mockFunction: mockResponseImmediateNxDomainAnswer,
			queryFqdn:    "tutu.example.com.",
			wantResponse: createSOAAuthoritativeAnswer(updateTestQueryDomain("tutu.example.com."), dns.NXDOMAIN),
			wantError:    nil,
		},
	}

	resolver, err := dns.NewResolver(testRootServerHintsFile)
	if err != nil {
		t.Fatalf("Root servers not loaded into resolver: %v: %v", resolver.RootServers, err)
	}

	// Restore the original query function after the tests complete
	defer func() { resolver.QueryFunc = dns.QueryResponse }()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testQueryBytes, _ := dns.EncodeMessage(updateTestQueryDomain(tc.queryFqdn))
			want, _ := dns.EncodeMessage(tc.wantResponse)

			// Inject the mock QueryResponse function for the current test case
			resolver.QueryFunc = func(transmissionProtocol string, serverAddrPort netip.AddrPort, dnsRequest []byte) ([]byte, error) {
				defer func() { mockFunctionCalledCount++ }()
				return tc.mockFunction(transmissionProtocol, serverAddrPort, dnsRequest)
			}
			defer func() { mockFunctionCalledCount = 0 }()

			got, err := resolver.ResolveQuery(testQueryBytes)

			// Check the error is one is expected
			if tc.wantError != nil {
				if err == nil || err != tc.wantError {
					t.Fatalf("expected error: %v, got: %v", tc.wantError, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
			}

			if len(got) != len(want) {
				t.Errorf("ResolveQuery() response length: want = %d, got = %d", len(want), len(got))
			}

			if !reflect.DeepEqual(got, want) {
				t.Errorf("ResolveQuery() bytes want = %v, got = %v\n", want, got)
			}

		})
	}
}

func updateTestQueryDomain(fqdn string) dns.Message {
	testQuery.Questions[0].Name = fqdn
	return testQuery
}
