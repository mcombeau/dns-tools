package dnsparser

import "errors"

// 12 bytes long
// bytes 0-1: transaction ID
// bytes 2-3: flags
// bytes 4-5: Number of Questions
// bytes 6-7: Number of Answer Resource Record (RR)
// bytes 8-9: Number of Authority RRs
// bytes 10-11: Number of Additional RRs
type DNSHeader struct {
	Id                 uint16
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
	QuestionCount      uint16
}

func ParseDNSHeader(data []byte) (*DNSHeader, error) {
	if len(data) < 12 {
		return nil, errors.New("invalid DNS header")
	}

	header := DNSHeader{
		Id:                 parseTransactionID(data),
		Response:           parseResponseFlag(data),
		Opcode:             parseOpcode(data),
		Authoritative:      parseAuthoritativeFlag(data),
		Truncated:          parseTruncatedFlag(data),
		RecursionDesired:   parseRecursionDesiredFlag(data),
		RecursionAvailable: parseRecursionAvailableFlag(data),
		DnssecOk:           parseDnssecOKFlag(data),
		AuthenticatedData:  parseAuthenticatedDataFlag(data),
		CheckingDisabled:   parseCheckingDisabledFlag(data),
		ResponseCode:       parseResponseCode(data),
	}

	return &header, nil
}

/*
parse header sections:
"Concatenate" two bytes of header into int16.

Ex. TransactionId = 1234:

data[0]: 0x12:	00010010
data[1]: 0x34:	00110100

uint16(data[0]):	00000000 00010010
uint16(data[1]):	00000000 00110100

data[0] << 8:		00010010 00000000
uint16(data[1]):	00000000 00110100
|:					00010010 00110100

hex:				0x12	 0x34		: 0x1234
*/

func parseTransactionID(data []byte) uint16 {
	return uint16(data[0])<<8 | uint16(data[1])
}

func parseQuestionCount(data []byte) uint16 {
	return uint16(data[4])<<8 | uint16(data[5])
}

/*
Parse flag section of header:
flag section is 2 bytes, need to pick the correct bytes
*/

func parseResponseFlag(data []byte) bool {
	// QR (Query/Response): Bit 15 (0x8000)
	return data[2]&0x80 != 0
}

func parseOpcode(data []byte) uint16 {
	// Opcode: Bits 11-14 (0x7800)
	return (uint16(data[2]) >> 3) & 0x0F
}

func parseAuthoritativeFlag(data []byte) bool {
	// AA (Authoritative Answer): Bit 10 (0x0400)
	return data[2]&0x04 != 0
}

func parseTruncatedFlag(data []byte) bool {
	// TC (Truncated): Bit 9 (0x0200)
	return data[2]&0x02 != 0
}

func parseRecursionDesiredFlag(data []byte) bool {
	// RD (Recursion Desired): Bit 8 (0x0100)
	return data[2]&0x01 != 0
}

func parseRecursionAvailableFlag(data []byte) bool {
	// RA (Recursion Available): Bit 7 (0x0080)
	return data[3]&0x80 != 0
}

func parseDnssecOKFlag(data []byte) bool {
	// DO (DNSSEC OK): Bit 6 (0x0040) - Defined in RFC 3225
	return data[3]&0x40 != 0
}

func parseAuthenticatedDataFlag(data []byte) bool {
	// AD (Authenticated Data): Bit 5 (0x0020)
	return data[3]&0x20 != 0
}

func parseCheckingDisabledFlag(data []byte) bool {
	// CD (Checking Disabled): Bit 4 (0x0010)
	return data[3]&0x10 != 0
}

func parseResponseCode(data []byte) uint16 {
	// Rcode (Response Code): Bits 0-3 (0x000F)
	return uint16(data[3]) & 0x0F
}
