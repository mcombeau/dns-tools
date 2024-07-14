package decoder

import (
	"errors"

	"github.com/mcombeau/go-dns-tools/dns"
	"github.com/mcombeau/go-dns-tools/utils"
)

func decodeDNSQuestion(data []byte, offset int) (*dns.Question, int, error) {
	name, newOffset, err := decodeDomainName(data, offset)
	if err != nil {
		return &dns.Question{}, 0, err
	}

	offset += newOffset

	if len(data) < offset+4 {
		return &dns.Question{}, 0, errors.New("invalid DNS question")
	}

	question := dns.Question{
		Name:   name,
		QType:  utils.DecodeUint16(data, offset),
		QClass: utils.DecodeUint16(data, offset+2),
	}

	return &question, offset + 4, nil
}
