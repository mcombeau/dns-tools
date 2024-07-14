package encoder

import (
	"bytes"
	"strings"
)

func EncodeDNSQuestion(domain string) []byte {
	var buf bytes.Buffer

	header := []byte{
		0, 0, //Transaction ID
		1, 0, //Flags: standard query, recusion desired
		0, 1, //Questions: 1
		0, 0, //Answer RRs
		0, 0, //Authority (nameserver) RRs
		0, 0, //Additional RRs
	}

	buf.Write(header)

	parts := strings.Split(domain, ".")

	for _, part := range parts {
		buf.WriteByte(byte(len(part)))
		buf.WriteString(part)
	}

	buf.WriteByte(0)        //End of QNAME
	buf.Write([]byte{0, 1}) //QTYPE: A
	buf.Write([]byte{0, 1}) //QCLASS: IN

	return buf.Bytes()
}
