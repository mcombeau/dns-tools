package dns_test

import (
	"fmt"
	"net/netip"

	"github.com/mcombeau/dns-tools/pkg/dns"
)

// -----------------------------------------------------------------------
// Define mock functions to replace the QueryResponse for testing purposes.
// This allows us to control the responses the resolver receives.
// Each mock function will be called multiple times during the resolution
// process, and will create different sequences of responses.
// -----------------------------------------------------------------------

// Allows returning different mock responses
// depending on how many times the mock function was called
var mockFunctionCalledCount int

var testQuery = dns.Message{
	Header: dns.Header{
		Id:            1234,
		Flags:         dns.Flags{},
		QuestionCount: 1,
	},
	Questions: []dns.Question{
		{
			Name:   "www.example.com.",
			QType:  dns.A,
			QClass: dns.IN,
		},
	},
}

var authoritativeAnswerIP = "192.0.0.200"

// -------------- Mock QueryResponse functions

// Simulate a response chain such as:
// query -> authoritative answer
var mockResponseImmediateNoErrorAnswer = func(transmissionProtocol string, serverAddrPort netip.AddrPort, dnsRequest []byte) ([]byte, error) {
	parsedRequest, err := dns.DecodeMessage(dnsRequest)
	if err != nil {
		return nil, err
	}

	var response dns.Message

	switch mockFunctionCalledCount {
	case 0:
		response = createNoErrorAuthoritativeAnswer(parsedRequest, authoritativeAnswerIP)
	default:
		return nil, fmt.Errorf("exceeded max call count")
	}
	return dns.EncodeMessage(response)
}

// Simulate a response chain such as:
// query -> additional -> additional -> authoritative answer
var mockResponseAdditionalSectionToNoErrorAnswer = func(transmissionProtocol string, serverAddrPort netip.AddrPort, dnsRequest []byte) ([]byte, error) {
	parsedRequest, err := dns.DecodeMessage(dnsRequest)
	if err != nil {
		return nil, err
	}

	var response dns.Message

	switch mockFunctionCalledCount {
	case 0:
		response = createARecordAdditionalResponse(parsedRequest, "abc.example.com.", "192.0.0.1")
	case 1:
		response = createARecordAdditionalResponse(parsedRequest, "def.example.com.", "192.0.0.2")
	case 2:
		response = createNoErrorAuthoritativeAnswer(parsedRequest, authoritativeAnswerIP)
	default:
		return nil, fmt.Errorf("exceeded max call count")
	}
	return dns.EncodeMessage(response)
}

// Simulate a chain such as: query -> authority section response -> authoritative answer for NS -> authoritative answer for original query
var mockResponseAuthoritySectionToNoErrorAnswer = func(transmissionProtocol string, serverAddrPort netip.AddrPort, dnsRequest []byte) ([]byte, error) {
	parsedRequest, err := dns.DecodeMessage(dnsRequest)
	if err != nil {
		return nil, err
	}

	var response dns.Message

	switch mockFunctionCalledCount {
	case 0:
		response = createNSResponse(parsedRequest, "ghi.example.com.")
	case 1:
		response = createNoErrorAuthoritativeAnswer(parsedRequest, "192.0.0.1")
	case 2:
		response = createARecordAdditionalResponse(parsedRequest, "jkl.example.com.", "192.0.0.2")
	case 3:
		response = createNoErrorAuthoritativeAnswer(parsedRequest, authoritativeAnswerIP)
	default:
		return nil, fmt.Errorf("exceeded max call count")
	}
	return dns.EncodeMessage(response)
}

// Simulate a response chain such as:
// query -> SOA authority answer
var mockResponseImmediateSOAAnswer = func(transmissionProtocol string, serverAddrPort netip.AddrPort, dnsRequest []byte) ([]byte, error) {
	parsedRequest, err := dns.DecodeMessage(dnsRequest)
	if err != nil {
		return nil, err
	}

	var response dns.Message

	switch mockFunctionCalledCount {
	case 0:
		response = createSOAAuthoritativeAnswer(parsedRequest, dns.NOERROR)
	default:
		return nil, fmt.Errorf("exceeded max call count")
	}
	return dns.EncodeMessage(response)
}

// Simulate a response chain such as:
// query -> NXDOMAIN
var mockResponseImmediateNxDomainAnswer = func(transmissionProtocol string, serverAddrPort netip.AddrPort, dnsRequest []byte) ([]byte, error) {
	parsedRequest, err := dns.DecodeMessage(dnsRequest)
	if err != nil {
		return nil, err
	}

	var response dns.Message

	switch mockFunctionCalledCount {
	case 0:
		response = createSOAAuthoritativeAnswer(parsedRequest, dns.NXDOMAIN)
	default:
		return nil, fmt.Errorf("exceeded max call count")
	}
	return dns.EncodeMessage(response)
}

// -------------- Helper functions for response creation

func resetResourceRecords(message *dns.Message) {
	message.Header.AnswerRRCount = 0
	message.Header.AdditionalRRCount = 0
	message.Header.NameserverRRCount = 0
	message.Answers = []dns.ResourceRecord{}
	message.Additionals = []dns.ResourceRecord{}
	message.NameServers = []dns.ResourceRecord{}
}

func createNoErrorAuthoritativeAnswer(message dns.Message, ip string) dns.Message {
	resetResourceRecords(&message)

	message.Header.Flags.ResponseCode = dns.NOERROR
	message.Header.AnswerRRCount = 1
	message.Answers = []dns.ResourceRecord{
		{
			Name:     message.Questions[0].Name,
			RType:    dns.A,
			RClass:   dns.IN,
			TTL:      300,
			RDLength: 4,
			RData:    &dns.RDataA{IP: netip.MustParseAddr(ip)},
		},
	}
	return message
}

func createARecordAdditionalResponse(message dns.Message, name string, ip string) dns.Message {
	resetResourceRecords(&message)

	message.Header.AdditionalRRCount = 1
	message.Additionals = []dns.ResourceRecord{
		{
			Name:     "ns0.example.com",
			RType:    dns.A,
			RClass:   dns.IN,
			TTL:      300,
			RDLength: 4,
			RData:    &dns.RDataA{IP: netip.MustParseAddr(ip)},
		},
	}
	return message
}

func createNSResponse(message dns.Message, name string) dns.Message {
	resetResourceRecords(&message)

	message.Header.NameserverRRCount = 1
	message.NameServers = []dns.ResourceRecord{
		{
			Name:     "example",
			RType:    dns.NS,
			RClass:   dns.IN,
			TTL:      300,
			RDLength: 4,
			RData:    &dns.RDataNS{DomainName: name},
		},
	}
	return message
}

func createSOAAuthoritativeAnswer(message dns.Message, rCode uint16) dns.Message {
	resetResourceRecords(&message)

	message.Header.Flags.ResponseCode = rCode
	message.Header.NameserverRRCount = 1
	message.NameServers = []dns.ResourceRecord{
		{
			Name:     "ns0.example.com",
			RType:    dns.SOA,
			RClass:   dns.IN,
			TTL:      300,
			RDLength: 4,
			RData: &dns.RDataSOA{
				MName:   "ns.example.com.",
				RName:   "admin.example.com.",
				Serial:  123456789,
				Refresh: 2000,
				Retry:   500,
				Expire:  10000,
				Minimum: 20000,
			},
		},
	}
	return message
}
