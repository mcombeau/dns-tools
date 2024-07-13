package dnsparser

import "errors"

const questionOffset int = 12 //header ends at 12 bytes

type DNSQuestion struct {
	Name  string
	Qtype uint16
	// Class uint16
}

func parseDNSQuestion(data []byte) (*DNSQuestion, int, error) {
	name, offset := parseDomainName(data, questionOffset)
	offset += questionOffset

	if len(data) < offset+4 {
		return &DNSQuestion{}, 0, errors.New("invalid DNS question")
	}

	question := DNSQuestion{
		Name:  name,
		Qtype: parseUint16(data, offset),
	}

	return &question, offset, nil
}

/*
Domain name in DNS encoded with labels, each label prefixed with length:
[7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0]
*/

func parseDomainName(data []byte, offset int) (string, int) {
	var name string
	originalOffset := offset
	for {
		lenLabel := int(data[offset])
		if lenLabel == 0 {
			offset++
			name += "." //for root domain
			break
		}
		if len(name) > 0 {
			name += "."
		}
		name += string(data[offset+1 : offset+1+lenLabel])
		offset += lenLabel + 1
	}
	return name, offset - originalOffset
}
