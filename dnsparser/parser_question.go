package dnsparser

import "errors"

const questionOffset int = 12 //header ends at 12 bytes

type DNSQuestion struct {
	Name   string
	QType  uint16
	QClass uint16
}

func parseDNSQuestion(data []byte) (*DNSQuestion, int, error) {
	name, offset := parseDomainName(data, questionOffset)
	offset += questionOffset

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
