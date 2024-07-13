package dnsparser

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func mockDNSResponse() []byte {
	msg := new(dns.Msg)
	msg.SetReply(&dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 1234,
			Response:           true,
			Authoritative:      true,
			RecursionAvailable: true,
		},
	})

	msg.Question = []dns.Question{
		{
			Name:   "example.com.",
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		},
	}

	rr, _ := dns.NewRR("example.com. 3600 IN A 93.184.216.34")
	msg.Answer = []dns.RR{rr}

	response, _ := msg.Pack()
	return response
}

func TestParseTransactionID(t *testing.T) {
	mockResponse := mockDNSResponse()

	var unpackedMockResponse dns.Msg
	err := unpackedMockResponse.Unpack(mockResponse)

	if err != nil {
		t.Fatalf("Failed to unpack mock response: %v\n", err)
	}

	want := unpackedMockResponse.Id
	got := parseTransactionID(mockResponse)

	assert.Equal(t, want, got)
}

func TestParseHeader(t *testing.T) {
	mockResponse := mockDNSResponse()

	var unpackedMockResponse dns.Msg
	err := unpackedMockResponse.Unpack(mockResponse)

	if err != nil {
		t.Fatalf("Failed to unpack mock response: %v\n", err)
	}

	want := unpackedMockResponse
	got, err := ParseDNSHeader(mockResponse)

	assert.NoError(t, err)
	assert.Equal(t, want.Id, got.TransactionID)
}

// func viewtMockDNSResponse(t *testing.T) {
// 	mockResponse := mockDNSResponse()

// 	fmt.Println("------------------")

// 	fmt.Printf("mock: %s\n", mockResponse)

// 	fmt.Println("------------------")

// 	for _, n := range mockResponse {
// 		fmt.Printf("%08b ", n)
// 	}

// 	fmt.Println("\n------------------")

// 	var msg dns.Msg
// 	err := msg.Unpack(mockResponse)
// 	if err != nil {
// 		t.Fatalf("Failed to unpack mock response: %v\n", err)
// 	}
// 	fmt.Printf("Question domain: %s\n", msg.Question[0].Name)
// 	fmt.Printf("Answer IP: %s\n", msg.Answer[0].(*dns.A).A.String())
// 	fmt.Printf(msg.String())

// 	fmt.Println("------------------")

// 	// parsedResponse, err := ParseDNSResponse(mockResponse)

// 	// assert.NoError(t, err)
// 	// assert.Equal(t, "example.com.", parsedResponse.Question[0].Name)
// 	// assert.Equal(t, "93.184.216.34", parsedResponse.Answer[0].(*dns.A).A.String())
// }
