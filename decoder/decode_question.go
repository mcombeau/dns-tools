package decoder

import "errors"

type DNSQuestion struct {
	Name   string
	QType  uint16
	QClass uint16
}

func decodeDNSQuestion(data []byte, offset int) (*DNSQuestion, int, error) {
	name, newOffset := parseDomainName(data, offset)
	offset += newOffset

	if len(data) < offset+4 {
		return &DNSQuestion{}, 0, errors.New("invalid DNS question")
	}

	question := DNSQuestion{
		Name:   name,
		QType:  parseUint16(data, offset),
		QClass: parseUint16(data, offset+2),
	}

	return &question, offset + 4, nil
}
