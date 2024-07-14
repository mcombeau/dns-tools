package decoder

import (
	"errors"

	"github.com/mcombeau/go-dns-tools/utils"
)

// 12 bytes long
// bytes 0-1: transaction ID
// bytes 2-3: flags
// bytes 4-5: Number of Questions
// bytes 6-7: Number of Answer Resource Record (RR)
// bytes 8-9: Number of Authority (nameserver) RRs
// bytes 10-11: Number of Additional RRs
type DNSHeader struct {
	Id                uint16
	Flags             *DNSFlags
	QuestionCount     uint16
	AnswerRRCount     uint16
	NameserverRRCount uint16
	AdditionalRRCount uint16
}

type DNSFlags struct {
	Response           bool
	Opcode             uint16
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	DnssecOk           bool // RFC 3225
	AuthenticatedData  bool // RFC 4035
	CheckingDisabled   bool // RFC 4035
	ResponseCode       uint16
}

func DecodeDNSHeader(data []byte) (*DNSHeader, error) {
	if len(data) < 12 {
		return nil, errors.New("invalid DNS header")
	}

	header := DNSHeader{
		Id:                utils.ParseUint16(data, 0),
		Flags:             decodeDNSFlags(data),
		QuestionCount:     utils.ParseUint16(data, 4),
		AnswerRRCount:     utils.ParseUint16(data, 6),
		NameserverRRCount: utils.ParseUint16(data, 8),
		AdditionalRRCount: utils.ParseUint16(data, 10),
	}

	return &header, nil
}

func decodeDNSFlags(data []byte) *DNSFlags {
	return &DNSFlags{
		// QR (Query/Response): Bit 15 (0x8000)
		Response: data[2]&0x80 != 0,
		// Opcode: Bits 11-14 (0x7800)
		Opcode: (uint16(data[2]) >> 3) & 0x0F,
		// AA (Authoritative Answer): Bit 10 (0x0400)
		Authoritative: data[2]&0x04 != 0,
		// TC (Truncated): Bit 9 (0x0200)
		Truncated: data[2]&0x02 != 0,
		// RD (Recursion Desired): Bit 8 (0x0100)
		RecursionDesired: data[2]&0x01 != 0,
		// RA (Recursion Available): Bit 7 (0x0080)
		RecursionAvailable: data[3]&0x80 != 0,
		// DO (DNSSEC OK): Bit 6 (0x0040)
		DnssecOk: data[3]&0x40 != 0,
		// AD (Authenticated Data): Bit 5 (0x0020)
		AuthenticatedData: data[3]&0x20 != 0,
		// CD (Checking Disabled): Bit 4 (0x0010)
		CheckingDisabled: data[3]&0x10 != 0,
		// Rcode (Response Code): Bits 0-3 (0x000F)
		ResponseCode: uint16(data[3]) & 0x0F,
	}
}
