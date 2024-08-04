package dns

// Header section format
// The header contains the following fields:

//                                     1  1  1  1  1  1
//       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                      ID                       |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   | <- flags
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    QDCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    ANCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    NSCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    ARCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

const DNSHeaderLength = 12

type Header struct {
	Id                uint16
	Flags             Flags
	QuestionCount     uint16
	AnswerRRCount     uint16
	NameserverRRCount uint16
	AdditionalRRCount uint16
}

type Flags struct {
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

func (reader *dnsReader) readHeader() (Header, error) {
	if len(reader.data) < DNSHeaderLength {
		return Header{}, invalidHeaderError("too short")
	}

	header := Header{
		Id:                reader.readUint16(), // bytes 0-1: transaction ID
		Flags:             reader.readFlags(),  // bytes 2-3: flags
		QuestionCount:     reader.readUint16(), // bytes 4-5: Number of Questions
		AnswerRRCount:     reader.readUint16(), // bytes 6-7: Number of Answer Resource Record (RR)
		NameserverRRCount: reader.readUint16(), // bytes 8-9: Number of Authority (nameserver) RRs
		AdditionalRRCount: reader.readUint16(), // bytes 10-11: Number of Additional RRs
	}

	return header, nil
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

func (reader *dnsReader) readFlags() Flags {
	flags := reader.readUint16()

	return Flags{
		Response:           flags&QRMask != 0,
		Opcode:             (flags & OpcodeMask) >> 11,
		Authoritative:      flags&AAMask != 0,
		Truncated:          flags&TCMask != 0,
		RecursionDesired:   flags&RDMask != 0,
		RecursionAvailable: flags&RAMask != 0,
		DnssecOk:           flags&DOMask != 0,
		AuthenticatedData:  flags&ADMask != 0,
		CheckingDisabled:   flags&CDMask != 0,
		ResponseCode:       flags & RCodeMask,
	}
}

func (writer *dnsWriter) writeHeader(message Message) {
	writer.writeUint16(message.Header.Id)
	writer.writeFlags(message.Header.Flags)
	writer.writeUint16(message.Header.QuestionCount)
	writer.writeUint16(message.Header.AnswerRRCount)
	writer.writeUint16(message.Header.NameserverRRCount)
	writer.writeUint16(message.Header.AdditionalRRCount)
}

func (writer *dnsWriter) writeFlags(flags Flags) {
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

	writer.writeUint16(result)
}
