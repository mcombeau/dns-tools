package encoder

import (
	"bytes"

	"github.com/mcombeau/go-dns-tools/dns"
	"github.com/mcombeau/go-dns-tools/utils"
)

func encodeDNSHeader(buf *bytes.Buffer, msg *dns.Message) {
	buf.Write(utils.EncodeUint16(msg.Header.Id))
	buf.Write(encodeDNSFlags(msg.Header.Flags))
	buf.Write(utils.EncodeUint16(msg.Header.QuestionCount))
	buf.Write(utils.EncodeUint16(msg.Header.AnswerRRCount))
	buf.Write(utils.EncodeUint16(msg.Header.NameserverRRCount))
	buf.Write(utils.EncodeUint16(msg.Header.AdditionalRRCount))
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

func encodeDNSFlags(flags *dns.Flags) []byte {
	var result uint16
	if flags.Response {
		result |= QRMask
	}
	result |= (flags.Opcode << 11) & OpcodeMask
	if flags.Authoritative {
		result |= AAMask
	}
	if flags.Truncated {
		result |= TCMask
	}
	if flags.RecursionDesired {
		result |= RDMask
	}
	if flags.RecursionAvailable {
		result |= RAMask
	}
	if flags.DnssecOk {
		result |= DOMask
	}
	if flags.AuthenticatedData {
		result |= ADMask
	}
	if flags.CheckingDisabled {
		result |= CDMask
	}
	result |= flags.ResponseCode & RCodeMask

	return []byte{byte(result >> 8), byte(result & 0xFF)}
}
