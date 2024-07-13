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
	TransactionID uint16
}

func ParseDNSHeader(data []byte) (*DNSHeader, error) {
	if len(data) < 12 {
		return nil, errors.New("invalid DNS header")
	}

	header := DNSHeader{
		TransactionID: parseTransactionID(data),
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
