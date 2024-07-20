package dns

import (
	"bytes"
	"errors"
	"net"
	"strconv"
	"strings"
)

type RData interface {
	String() string
	Encode(buf *bytes.Buffer) error
	Decode(data []byte, offset int, length uint16) (int, error)
}

// -------------- A
// A RDATA format
// ADDRESS:	A 32 bit Internet address.

type RDataA struct {
	IP net.IP
}

func (rdata *RDataA) String() string {
	return rdata.IP.String()
}

func (rdata *RDataA) Encode(buf *bytes.Buffer) error {
	_, err := buf.Write(rdata.IP)
	return err
}

func (rdata *RDataA) Decode(data []byte, offset int, length uint16) (int, error) {
	rdata.IP = net.IP(data[offset : offset+int(length)])
	return offset + int(length), nil
}

// -------------- AAAA
// AAAA RDATA format
// A 128 bit IPv6 address is encoded in the data portion of an AAAA resource record in network byte order (high-order byte first).

type RDataAAAA struct {
	IP net.IP
}

func (rdata *RDataAAAA) String() string {
	return rdata.IP.String()
}

func (rdata *RDataAAAA) Encode(buf *bytes.Buffer) error {
	_, err := buf.Write(rdata.IP)
	return err
}

func (rdata *RDataAAAA) Decode(data []byte, offset int, length uint16) (int, error) {
	rdata.IP = net.IP(data[offset : offset+int(length)])
	return offset + int(length), nil
}

// -------------- CNAME
// CNAME RDATA format
// CNAME:	A <domain-name> which specifies the canonical or primary name for the owner.  The owner name is an alias.

type RDataCNAME struct {
	domainName string
}

func (rdata *RDataCNAME) String() string {
	return rdata.domainName
}

func (rdata *RDataCNAME) Encode(buf *bytes.Buffer) error {
	encodeDomainName(buf, rdata.domainName)
	return nil
}

func (rdata *RDataCNAME) Decode(data []byte, offset int, length uint16) (int, error) {
	var newOffset int
	var err error

	rdata.domainName, newOffset, err = decodeDomainName(data, offset)
	if err != nil {
		return newOffset, errors.New("could not decode domain name for CNAME record")
	}
	return newOffset, nil
}

// -------------- PTR
// PTR RDATA format
// PTRDNAME:	A <domain-name> which points to some location in the domain name space.

type RDataPTR struct {
	domainName string
}

func (rdata *RDataPTR) String() string {
	return rdata.domainName
}

func (rdata *RDataPTR) Encode(buf *bytes.Buffer) error {
	encodeDomainName(buf, rdata.domainName)
	return nil
}

func (rdata *RDataPTR) Decode(data []byte, offset int, length uint16) (int, error) {
	var newOffset int
	var err error

	rdata.domainName, newOffset, err = decodeDomainName(data, offset)
	if err != nil {
		return newOffset, errors.New("could not decode domain name for PTR record")
	}
	return newOffset, nil
}

// -------------- NS
// NS RDATA format
// NSDNAME:	A <domain-name> which specifies a host which should be authoritative for the specified class and domain.

type RDataNS struct {
	domainName string
}

func (rdata *RDataNS) String() string {
	return rdata.domainName
}

func (rdata *RDataNS) Encode(buf *bytes.Buffer) error {
	encodeDomainName(buf, rdata.domainName)
	return nil
}

func (rdata *RDataNS) Decode(data []byte, offset int, length uint16) (int, error) {
	var newOffset int
	var err error

	rdata.domainName, newOffset, err = decodeDomainName(data, offset)
	if err != nil {
		return newOffset, errors.New("could not decode domain name for NS record")
	}
	return newOffset, nil
}

// -------------- TXT
// TXT RDATA format
// TXT-DATA:	One or more <character-string>s.

type RDataTXT struct {
	text string
}

func (rdata *RDataTXT) String() string {
	return rdata.text
}

func (rdata *RDataTXT) Encode(buf *bytes.Buffer) error {
	buf.WriteString(rdata.text)
	return nil
}

func (rdata *RDataTXT) Decode(data []byte, offset int, length uint16) (int, error) {
	rdata.text = string(data[offset : offset+int(length)])
	return offset + int(length), nil
}

// -------------- MX
// MX RDATA format
// PREFERENCE:	A 16 bit integer which specifies the preference given to this RR among others at the same owner.  Lower values are preferred.
// EXCHANGE:	A <domain-name> which specifies a host willing to act as a mail exchange for the owner name.

type RDataMX struct {
	preference uint16
	domainName string
}

func (rdata *RDataMX) String() string {
	return strconv.Itoa(int(rdata.preference)) + " " + rdata.domainName
}

func (rdata *RDataMX) Encode(buf *bytes.Buffer) error {
	buf.Write(encodeUint16(rdata.preference))
	encodeDomainName(buf, rdata.domainName)
	return nil
}

func (rdata *RDataMX) Decode(data []byte, offset int, length uint16) (int, error) {
	var newOffset int
	var err error

	rdata.preference = decodeUint16(data, offset)
	rdata.domainName, newOffset, err = decodeDomainName(data, offset+2)
	if err != nil {
		return newOffset, errors.New("could not decode domain name for MX record")
	}
	return newOffset, nil
}

// -------------- SOA
// SOA RDATA format
// MNAME:	The <domain-name> of the name server that was the original or primary source of data for this zone.
// RNAME:	A <domain-name> which specifies the mailbox of the person responsible for this zone.
// SERIAL:	The unsigned 32 bit version number of the original copy of the zone.  Zone transfers preserve this value.  This value wraps and should be compared using sequence space arithmetic.
// REFRESH:	A 32 bit time interval before the zone should be refreshed.
// RETRY:	A 32 bit time interval that should elapse before a failed refresh should be retried.
// EXPIRE:	A 32 bit time value that specifies the upper limit on the time interval that can elapse before the zone is no longer authoritative.
// MINIMUM:	The unsigned 32 bit minimum TTL field that should be exported with any RR from this zone.

type RDataSOA struct {
	mName   string
	rName   string
	serial  uint32
	refresh uint32
	retry   uint32
	expire  uint32
	minimum uint32
}

func (rdata *RDataSOA) String() string {
	soa := []string{
		rdata.mName,
		rdata.rName,
		strconv.Itoa(int(rdata.serial)),
		strconv.Itoa(int(rdata.refresh)),
		strconv.Itoa(int(rdata.retry)),
		strconv.Itoa(int(rdata.expire)),
		strconv.Itoa(int(rdata.minimum)),
	}

	return strings.Join(soa, " ")
}

func (rdata *RDataSOA) Encode(buf *bytes.Buffer) error {
	encodeDomainName(buf, rdata.mName)
	encodeDomainName(buf, rdata.rName)
	buf.Write(encodeUint32(rdata.serial))
	buf.Write(encodeUint32(rdata.refresh))
	buf.Write(encodeUint32(rdata.retry))
	buf.Write(encodeUint32(rdata.expire))
	buf.Write(encodeUint32(rdata.minimum))
	return nil
}

func (rdata *RDataSOA) Decode(data []byte, offset int, length uint16) (int, error) {
	var newOffset int
	var err error

	rdata.mName, newOffset, err = decodeDomainName(data, offset)
	if err != nil {
		return newOffset, errors.New("could not decode domain name for SOA record")
	}
	offset += newOffset

	rdata.rName, newOffset, err = decodeDomainName(data, offset)
	if err != nil {
		return newOffset, errors.New("could not decode domain name for SOA record")
	}
	offset += newOffset

	rdata.serial = decodeUint32(data, offset)
	rdata.refresh = decodeUint32(data, offset+4)
	rdata.retry = decodeUint32(data, offset+8)
	rdata.expire = decodeUint32(data, offset+12)
	rdata.minimum = decodeUint32(data, offset+16)

	return newOffset, nil
}
