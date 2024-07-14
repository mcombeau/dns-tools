package encoder

import (
	"bytes"

	"github.com/mcombeau/go-dns-tools/dns"
)

func EncodeDNSMessage(msg *dns.Message) ([]byte, error) {
	buf := new(bytes.Buffer)

	encodeDNSHeader(buf, msg)

	for _, question := range msg.Questions {
		encodeDNSQuestion(buf, question)
	}

	for _, rr := range msg.Answers {
		encodeDNSResourceRecord(buf, rr)
	}
	for _, rr := range msg.NameServers {
		encodeDNSResourceRecord(buf, rr)
	}
	for _, rr := range msg.Additionals {
		encodeDNSResourceRecord(buf, rr)
	}

	return buf.Bytes(), nil
}
