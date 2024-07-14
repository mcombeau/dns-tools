package testutils

import (
	"github.com/miekg/dns"
)

func MockDNSResponse() ([]byte, error) {
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

	response, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	// Manually set the DO bit in the packed response
	response[3] |= 0x40 // Set the DO bit (6th bit of the 3rd byte)

	return response, nil
}

func MockDNSCompressedResponse() ([]byte, error) {
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

	// Compress domain names
	msg.Compress = true

	response, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	// Manually set the DO bit in the packed response
	response[3] |= 0x40 // Set the DO bit (6th bit of the 3rd byte)

	// fmt.Printf("Packed Response: %v\n", response)
	return response, nil
}
