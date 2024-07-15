package dns

type Message struct {
	Header      *Header
	Questions   []Question
	Answers     []ResourceRecord
	NameServers []ResourceRecord
	Additionals []ResourceRecord
}

type Header struct {
	Id                uint16
	Flags             *Flags
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

type Question struct {
	Name   string
	QType  uint16
	QClass uint16
}

type ResourceRecord struct {
	Name     string
	RType    uint16
	RClass   uint16
	TTL      uint32
	RDLength uint16
	RData    RData
}

type RData struct {
	Raw     []byte
	Decoded string
}
