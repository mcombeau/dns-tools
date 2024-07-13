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
	// Manually set the DO bit in the packed response
	response[3] |= 0x40 // Set the DO bit (6th bit of the 3rd byte)

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

func TestParseQuestionCount(t *testing.T) {
	mockResponse := mockDNSResponse()

	var unpackedMockResponse dns.Msg
	err := unpackedMockResponse.Unpack(mockResponse)

	if err != nil {
		t.Fatalf("Failed to unpack mock response: %v\n", err)
	}

	want := uint16(len(unpackedMockResponse.Question))
	got := parseQuestionCount(mockResponse)

	assert.Equal(t, want, got)
}

func TestParseFlags(t *testing.T) {
	mockResponse := mockDNSResponse()

	var unpackedMockResponse dns.Msg
	err := unpackedMockResponse.Unpack(mockResponse)

	if err != nil {
		t.Fatalf("Failed to unpack mock response: %v\n", err)
	}

	want := unpackedMockResponse
	got, err := ParseDNSHeader(mockResponse)

	assert.NoError(t, err)

	assert.Equal(t, want.Response, got.Response)
	assert.Equal(t, int(want.Opcode), int(got.Opcode))
	assert.Equal(t, want.Authoritative, got.Authoritative)
	assert.Equal(t, want.Truncated, got.Truncated)
	assert.Equal(t, want.RecursionDesired, got.RecursionDesired)
	assert.Equal(t, want.RecursionAvailable, got.RecursionAvailable)
	assert.True(t, got.DnssecOk)
	assert.Equal(t, want.AuthenticatedData, got.AuthenticatedData)
	assert.Equal(t, want.CheckingDisabled, got.CheckingDisabled)
	assert.Equal(t, int(want.Rcode), int(got.ResponseCode))
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
	assert.Equal(t, want.Id, got.Id)
	assert.Equal(t, want.Response, got.Response)
	assert.Equal(t, int(want.Opcode), int(got.Opcode))
	assert.Equal(t, want.Authoritative, got.Authoritative)
	assert.Equal(t, want.Truncated, got.Truncated)
	assert.Equal(t, want.RecursionDesired, got.RecursionDesired)
	assert.Equal(t, want.RecursionAvailable, got.RecursionAvailable)
	assert.True(t, got.DnssecOk)
	assert.Equal(t, want.AuthenticatedData, got.AuthenticatedData)
	assert.Equal(t, want.CheckingDisabled, got.CheckingDisabled)
	assert.Equal(t, int(want.Rcode), int(got.ResponseCode))
}
