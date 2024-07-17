package decoder

import (
	"errors"

	"github.com/mcombeau/dns-tools/dns"
	"github.com/mcombeau/dns-tools/utils"
)

// DNS Header is 12 bytes long
// bytes 0-1: transaction ID
// bytes 2-3: flags
// bytes 4-5: Number of Questions
// bytes 6-7: Number of Answer Resource Record (RR)
// bytes 8-9: Number of Authority (nameserver) RRs
// bytes 10-11: Number of Additional RRs

func DecodeDNSHeader(data []byte) (*dns.Header, error) {
	if len(data) < 12 {
		return nil, errors.New("invalid DNS header")
	}

	header := dns.Header{
		Id:                utils.DecodeUint16(data, 0),
		Flags:             decodeDNSFlags(data[2:4]),
		QuestionCount:     utils.DecodeUint16(data, 4),
		AnswerRRCount:     utils.DecodeUint16(data, 6),
		NameserverRRCount: utils.DecodeUint16(data, 8),
		AdditionalRRCount: utils.DecodeUint16(data, 10),
	}

	return &header, nil
}

const (
	QRMask     = 0b10000000_00000000 // QR: Bit 15
	OpcodeMask = 0b01111000_00000000 // Opcode: Bits 11-14
	AAMask     = 0b00000100_00000000 // AA: Bit 10
	TCMask     = 0b00000010_00000000 // TC: Bit 9
	RDMask     = 0b00000001_00000000 // RD: Bit 8
	RAMask     = 0b00000000_10000000 // RA: Bit 7
	DOMask     = 0b00000000_01000000 // DO: Bit 6
	ADMask     = 0b00000000_00100000 // AD: Bit 5
	CDMask     = 0b00000000_00010000 // CD: Bit 4
	RCodeMask  = 0b00000000_00001111 // Rcode: Bits 0-3
)

func decodeDNSFlags(data []byte) *dns.Flags {
	return &dns.Flags{
		Response:           data[0]&uint8(QRMask>>8) != 0,
		Opcode:             (uint16(data[0]) >> 3) & (OpcodeMask >> 11),
		Authoritative:      data[0]&uint8(AAMask>>8) != 0,
		Truncated:          data[0]&uint8(TCMask>>8) != 0,
		RecursionDesired:   data[0]&uint8(RDMask>>8) != 0,
		RecursionAvailable: data[1]&uint8(RAMask) != 0,
		DnssecOk:           data[1]&uint8(DOMask) != 0,
		AuthenticatedData:  data[1]&uint8(ADMask) != 0,
		CheckingDisabled:   data[1]&uint8(CDMask) != 0,
		ResponseCode:       uint16(data[1]) & RCodeMask,
	}
}
