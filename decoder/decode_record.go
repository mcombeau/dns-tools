package decoder

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/mcombeau/dns-tools/dns"
	"github.com/mcombeau/dns-tools/utils"
)

func decodeDNSResourceRecord(data []byte, offset int) (*dns.ResourceRecord, int, error) {
	name, newOffset, err := decodeDomainName(data, offset)
	if err != nil {
		return &dns.ResourceRecord{}, 0, err
	}

	offset += newOffset

	if len(data) < offset+10 {
		return &dns.ResourceRecord{}, 0, errors.New("invalid DNS resource record")
	}
	rtype := utils.DecodeUint16(data, offset)
	rclass := utils.DecodeUint16(data, offset+2)
	ttl := utils.DecodeUint32(data, offset+4)
	rdlength := utils.DecodeUint16(data, offset+8)
	offset += 10

	if len(data) < offset+int(rdlength) {
		return &dns.ResourceRecord{}, 0, errors.New("invalid DNS resource record RDATA length")
	}

	rdata := decodeRData(data, rtype, offset, int(rdlength))

	record := dns.ResourceRecord{
		Name:     name,
		RType:    rtype,
		RClass:   rclass,
		TTL:      ttl,
		RDLength: rdlength,
		RData:    *rdata,
	}

	offset += int(record.RDLength)

	return &record, offset, nil
}

func decodeRData(data []byte, rtype uint16, offset int, length int) *dns.RData {
	rdata := dns.RData{
		Raw:     data[offset : offset+length],
		Decoded: "",
	}

	switch rtype {
	case dns.A, dns.AAAA:
		rdata.Decoded = decodeA(data, offset, offset+length)

	case dns.CNAME, dns.PTR, dns.NS:
		rdata.Decoded = decodeCNAME(data, offset)

	case dns.MX:
		rdata.Decoded = decodeMX(data, offset)

	case dns.TXT:
		rdata.Decoded = decodeTXT(data, offset, offset+length)

	case dns.SOA:
		rdata.Decoded = decodeSOA(data, offset)

	default:
		rdata.Decoded = ""
	}

	return &rdata
}

// A RDATA format
// ADDRESS:	A 32 bit Internet address.
// AAAA RDATA format
// A 128 bit IPv6 address is encoded in the data portion of an AAAA resource record in network byte order (high-order byte first).
func decodeA(data []byte, start int, end int) string {
	return net.IP(data[start:end]).String()
}

// CNAME RDATA format
// CNAME:	A <domain-name> which specifies the canonical or primary name for the owner.  The owner name is an alias.
// PTR RDATA format
// PTRDNAME:	A <domain-name> which points to some location in the domain name space.
// NS RDATA format
// NSDNAME:	A <domain-name> which specifies a host which should be authoritative for the specified class and domain.
func decodeCNAME(data []byte, offset int) string {
	domainName, _, err := decodeDomainName(data, offset)
	if err != nil {
		return ""
	}
	return domainName
}

// MX RDATA format
// PREFERENCE:	A 16 bit integer which specifies the preference given to this RR among others at the same owner.  Lower values are preferred.
// EXCHANGE:	A <domain-name> which specifies a host willing to act as a mail exchange for the owner name.
func decodeMX(data []byte, offset int) string {
	preference := utils.DecodeUint16(data, offset)

	domainName, _, err := decodeDomainName(data, offset+2)
	if err != nil {
		return ""
	}

	return fmt.Sprintf("%d %s", preference, domainName)
}

// TXT RDATA format
// TXT-DATA:	One or more <character-string>s.
func decodeTXT(data []byte, start int, end int) string {
	return string(data[start:end])
}

// SOA RDATA format
// MNAME:	The <domain-name> of the name server that was the original or primary source of data for this zone.
// RNAME:	A <domain-name> which specifies the mailbox of the person responsible for this zone.
// SERIAL:	The unsigned 32 bit version number of the original copy of the zone.  Zone transfers preserve this value.  This value wraps and should be compared using sequence space arithmetic.
// REFRESH:	A 32 bit time interval before the zone should be refreshed.
// RETRY:	A 32 bit time interval that should elapse before a failed refresh should be retried.
// EXPIRE:	A 32 bit time value that specifies the upper limit on the time interval that can elapse before the zone is no longer authoritative.
// MINIMUM:	The unsigned 32 bit minimum TTL field that should be exported with any RR from this zone.
func decodeSOA(data []byte, offset int) string {
	soa := make([]string, 7)

	mname, newoffset, err := decodeDomainName(data, offset)
	if err != nil {
		return ""
	}
	offset += newoffset
	soa = append(soa, mname)

	rname, newoffset, err := decodeDomainName(data, offset)
	if err != nil {
		return ""
	}
	offset += newoffset
	soa = append(soa, rname)

	serial := int(utils.DecodeUint32(data, offset))
	soa = append(soa, strconv.Itoa(serial))

	refresh := int(utils.DecodeUint32(data, offset+4))
	soa = append(soa, strconv.Itoa(refresh))

	retry := int(utils.DecodeUint32(data, offset+8))
	soa = append(soa, strconv.Itoa(retry))

	expire := int(utils.DecodeUint32(data, offset+12))
	soa = append(soa, strconv.Itoa(expire))

	minimum := int(utils.DecodeUint32(data, offset+16))
	soa = append(soa, strconv.Itoa(minimum))

	return strings.Join(soa, " ")
}
