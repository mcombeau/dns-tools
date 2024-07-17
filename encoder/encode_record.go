package encoder

import (
	"bytes"

	"github.com/mcombeau/dns-tools/dns"
	"github.com/mcombeau/dns-tools/utils"
)

func encodeDNSResourceRecord(buf *bytes.Buffer, rr dns.ResourceRecord) {
	encodeDomainName(buf, rr.Name)
	buf.Write(utils.EncodeUint16(rr.RType))
	buf.Write(utils.EncodeUint16(rr.RClass))
	buf.Write(utils.EncodeUint32(rr.TTL))
	buf.Write(utils.EncodeUint16(rr.RDLength))
	buf.Write(rr.RData.Raw)
}
