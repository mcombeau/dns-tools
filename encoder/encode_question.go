package encoder

import (
	"bytes"

	"github.com/mcombeau/dns-tools/dns"
	"github.com/mcombeau/dns-tools/utils"
)

func encodeDNSQuestion(buf *bytes.Buffer, question dns.Question) {
	encodeDomainName(buf, question.Name)
	buf.Write(utils.EncodeUint16(question.QType))
	buf.Write(utils.EncodeUint16(question.QClass))
}
