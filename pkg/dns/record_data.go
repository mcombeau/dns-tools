package dns

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type RData interface {
	String() string
	WriteRecordData(writer *dnsWriter) error
	ReadRecordData(reader *dnsReader, length uint16) error
}

// -------------- A
// A RDATA format
// ADDRESS:	A 32 bit Internet address.

type RDataA struct {
	IP netip.Addr
}

func (rdata *RDataA) String() string {
	return rdata.IP.String()
}

func (rdata *RDataA) WriteRecordData(writer *dnsWriter) error {
	if !rdata.IP.Is4() {
		return invalidRecordDataError(ErrInvalidIP.Error())
	}
	ip4 := rdata.IP.As4()
	writer.writeData(ip4[:])
	return nil
}

func (rdata *RDataA) ReadRecordData(reader *dnsReader, length uint16) (err error) {
	if length != 4 {
		return invalidRecordDataError(fmt.Sprintf("invalid length for IPv4 address: %d", length))
	}

	var ipArray [4]byte
	copy(ipArray[:], reader.data[reader.offset:reader.offset+int(length)])

	ip4 := netip.AddrFrom4(ipArray)

	if !ip4.IsValid() || !ip4.Is4() {
		return invalidRecordDataError(ErrInvalidIP.Error())
	}

	reader.offset += int(length)
	rdata.IP = ip4

	return nil
}

// -------------- AAAA
// AAAA RDATA format
// A 128 bit IPv6 address is encoded in the data portion of an AAAA resource record in network byte order (high-order byte first).

type RDataAAAA struct {
	IP netip.Addr
}

func (rdata *RDataAAAA) String() string {
	return rdata.IP.String()
}

func (rdata *RDataAAAA) WriteRecordData(writer *dnsWriter) error {
	if !rdata.IP.Is6() {
		return invalidRecordDataError(ErrInvalidIP.Error())
	}
	ip6 := rdata.IP.As16()
	writer.writeData(ip6[:])
	return nil
}

func (rdata *RDataAAAA) ReadRecordData(reader *dnsReader, length uint16) (err error) {
	if length != 16 {
		return invalidRecordDataError(fmt.Sprintf("invalid length for IPv6 address: %d", length))
	}

	var ipArray [16]byte
	copy(ipArray[:], reader.data[reader.offset:reader.offset+int(length)])

	ip6 := netip.AddrFrom16(ipArray)

	if !ip6.IsValid() || !ip6.Is6() {
		return invalidRecordDataError(ErrInvalidIP.Error())
	}

	reader.offset += int(length)
	rdata.IP = ip6

	return nil
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

func (rdata *RDataCNAME) WriteRecordData(writer *dnsWriter) error {
	writer.writeDomainName(rdata.domainName)
	return nil
}

func (rdata *RDataCNAME) ReadRecordData(reader *dnsReader, length uint16) (err error) {
	rdata.domainName, err = reader.readDomainName()
	if err != nil {
		return invalidRecordDataError(fmt.Sprintf("CNAME RData: %s", err.Error()))
	}
	return nil
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

func (rdata *RDataPTR) WriteRecordData(writer *dnsWriter) error {
	writer.writeDomainName(rdata.domainName)
	return nil
}

func (rdata *RDataPTR) ReadRecordData(reader *dnsReader, length uint16) (err error) {
	rdata.domainName, err = reader.readDomainName()
	if err != nil {
		return invalidRecordDataError(fmt.Sprintf("PTR RData: %s", err.Error()))
	}
	return nil
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

func (rdata *RDataNS) WriteRecordData(writer *dnsWriter) error {
	writer.writeDomainName(rdata.domainName)
	return nil
}

func (rdata *RDataNS) ReadRecordData(reader *dnsReader, length uint16) (err error) {
	rdata.domainName, err = reader.readDomainName()
	if err != nil {
		return invalidRecordDataError(fmt.Sprintf("NS RData: %s", err.Error()))
	}
	return nil
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

func (rdata *RDataTXT) WriteRecordData(writer *dnsWriter) error {
	writer.writeData([]byte(rdata.text))
	return nil
}

func (rdata *RDataTXT) ReadRecordData(reader *dnsReader, length uint16) (err error) {
	rdata.text = string(reader.data[reader.offset : reader.offset+int(length)])
	return nil
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

func (rdata *RDataMX) WriteRecordData(writer *dnsWriter) error {
	writer.writeUint16(rdata.preference)
	writer.writeDomainName(rdata.domainName)
	return nil
}

func (rdata *RDataMX) ReadRecordData(reader *dnsReader, length uint16) (err error) {
	rdata.preference = reader.readUint16()
	rdata.domainName, err = reader.readDomainName()
	if err != nil {
		return invalidRecordDataError(fmt.Sprintf("MX RData: %s", err.Error()))
	}
	return nil
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

func (rdata *RDataSOA) WriteRecordData(writer *dnsWriter) error {
	writer.writeDomainName(rdata.mName)
	writer.writeDomainName(rdata.rName)

	writer.writeUint32(rdata.serial)
	writer.writeUint32(rdata.refresh)
	writer.writeUint32(rdata.retry)
	writer.writeUint32(rdata.expire)
	writer.writeUint32(rdata.minimum)
	return nil
}

func (rdata *RDataSOA) ReadRecordData(reader *dnsReader, length uint16) (err error) {
	rdata.mName, err = reader.readDomainName()
	if err != nil {
		return invalidRecordDataError(fmt.Sprintf("SOA RData: %s", err.Error()))
	}

	rdata.rName, err = reader.readDomainName()
	if err != nil {
		return invalidRecordDataError(fmt.Sprintf("SOA RData: %s", err.Error()))
	}

	rdata.serial = reader.readUint32()
	rdata.refresh = reader.readUint32()
	rdata.retry = reader.readUint32()
	rdata.expire = reader.readUint32()
	rdata.minimum = reader.readUint32()

	return nil
}

// -------------- UNKNOWN

type RDataUnknown struct {
	raw []byte
}

func (rdata *RDataUnknown) String() string {
	return string(rdata.raw)
}

func (rdata *RDataUnknown) WriteRecordData(writer *dnsWriter) error {
	writer.writeData(rdata.raw)
	return nil
}

func (rdata *RDataUnknown) ReadRecordData(reader *dnsReader, length uint16) (err error) {
	rdata.raw, err = reader.readUntil(int(length))
	if err != nil {
		return err
	}
	return nil
}
