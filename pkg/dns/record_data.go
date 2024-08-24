package dns

import (
	"fmt"
	"net"
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
		return fmt.Errorf("invalid A record data: %w", ErrInvalidIP)
	}
	ip4 := rdata.IP.As4()
	writer.writeData(ip4[:])
	return nil
}

func (rdata *RDataA) ReadRecordData(reader *dnsReader, length uint16) (err error) {
	if length != net.IPv4len {
		return fmt.Errorf("invalid A record data length: expected %d, has %d: %w", net.IPv4len, length, ErrInvalidIP)
	}

	var ipArray [4]byte
	copy(ipArray[:], reader.data[reader.offset:reader.offset+int(length)])

	ip4 := netip.AddrFrom4(ipArray)

	if !ip4.IsValid() || !ip4.Is4() {
		return fmt.Errorf("invalid A record data: %w", ErrInvalidIP)
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
		return fmt.Errorf("invalid AAAA record data: %w", ErrInvalidIP)
	}
	ip6 := rdata.IP.As16()
	writer.writeData(ip6[:])
	return nil
}

func (rdata *RDataAAAA) ReadRecordData(reader *dnsReader, length uint16) (err error) {
	if length != net.IPv6len {
		return fmt.Errorf("invalid AAAA record data length: expected %d, has %d: %w", net.IPv6len, length, ErrInvalidIP)
	}

	var ipArray [net.IPv6len]byte
	copy(ipArray[:], reader.data[reader.offset:reader.offset+int(length)])

	ip6 := netip.AddrFrom16(ipArray)

	if !ip6.IsValid() || !ip6.Is6() {
		return fmt.Errorf("invalid AAAA record data: %w", ErrInvalidIP)
	}

	reader.offset += int(length)
	rdata.IP = ip6

	return nil
}

// -------------- CNAME
// CNAME RDATA format
// CNAME:	A <domain-name> which specifies the canonical or primary name for the owner.  The owner name is an alias.

type RDataCNAME struct {
	DomainName string
}

func (rdata *RDataCNAME) String() string {
	return rdata.DomainName
}

func (rdata *RDataCNAME) WriteRecordData(writer *dnsWriter) error {
	writer.writeDomainName(rdata.DomainName)
	return nil
}

func (rdata *RDataCNAME) ReadRecordData(reader *dnsReader, length uint16) (err error) {
	rdata.DomainName, err = reader.readDomainName()
	if err != nil {
		return fmt.Errorf("invalid CNAME record data: %w", err)
	}
	return nil
}

// -------------- PTR
// PTR RDATA format
// PTRDNAME:	A <domain-name> which points to some location in the domain name space.

type RDataPTR struct {
	DomainName string
}

func (rdata *RDataPTR) String() string {
	return rdata.DomainName
}

func (rdata *RDataPTR) WriteRecordData(writer *dnsWriter) error {
	writer.writeDomainName(rdata.DomainName)
	return nil
}

func (rdata *RDataPTR) ReadRecordData(reader *dnsReader, length uint16) (err error) {
	rdata.DomainName, err = reader.readDomainName()
	if err != nil {
		return fmt.Errorf("invalid PTR record data: %w", err)
	}
	return nil
}

// -------------- NS
// NS RDATA format
// NSDNAME:	A <domain-name> which specifies a host which should be authoritative for the specified class and domain.

type RDataNS struct {
	DomainName string
}

func (rdata *RDataNS) String() string {
	return rdata.DomainName
}

func (rdata *RDataNS) WriteRecordData(writer *dnsWriter) error {
	writer.writeDomainName(rdata.DomainName)
	return nil
}

func (rdata *RDataNS) ReadRecordData(reader *dnsReader, length uint16) (err error) {
	rdata.DomainName, err = reader.readDomainName()
	if err != nil {
		return fmt.Errorf("invalid NS record data: %w", err)
	}
	return nil
}

// -------------- TXT
// TXT RDATA format
// TXT-DATA:	One or more <character-string>s.

type RDataTXT struct {
	Text string
}

func (rdata *RDataTXT) String() string {
	return rdata.Text
}

func (rdata *RDataTXT) WriteRecordData(writer *dnsWriter) error {
	writer.writeData([]byte(rdata.Text))
	return nil
}

func (rdata *RDataTXT) ReadRecordData(reader *dnsReader, length uint16) (err error) {
	rdata.Text = string(reader.data[reader.offset : reader.offset+int(length)])
	return nil
}

// -------------- MX
// MX RDATA format
// PREFERENCE:	A 16 bit integer which specifies the preference given to this RR among others at the same owner.  Lower values are preferred.
// EXCHANGE:	A <domain-name> which specifies a host willing to act as a mail exchange for the owner name.

type RDataMX struct {
	Preference uint16
	DomainName string
}

func (rdata *RDataMX) String() string {
	return strconv.Itoa(int(rdata.Preference)) + " " + rdata.DomainName
}

func (rdata *RDataMX) WriteRecordData(writer *dnsWriter) error {
	writer.writeUint16(rdata.Preference)
	writer.writeDomainName(rdata.DomainName)
	return nil
}

func (rdata *RDataMX) ReadRecordData(reader *dnsReader, length uint16) (err error) {
	rdata.Preference = reader.readUint16()
	rdata.DomainName, err = reader.readDomainName()
	if err != nil {
		return fmt.Errorf("invalid MX record data: %w", err)
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
	MName   string
	RName   string
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minimum uint32
}

func (rdata *RDataSOA) String() string {
	soa := []string{
		rdata.MName,
		rdata.RName,
		strconv.Itoa(int(rdata.Serial)),
		strconv.Itoa(int(rdata.Refresh)),
		strconv.Itoa(int(rdata.Retry)),
		strconv.Itoa(int(rdata.Expire)),
		strconv.Itoa(int(rdata.Minimum)),
	}

	return strings.Join(soa, " ")
}

func (rdata *RDataSOA) WriteRecordData(writer *dnsWriter) error {
	writer.writeDomainName(rdata.MName)
	writer.writeDomainName(rdata.RName)

	writer.writeUint32(rdata.Serial)
	writer.writeUint32(rdata.Refresh)
	writer.writeUint32(rdata.Retry)
	writer.writeUint32(rdata.Expire)
	writer.writeUint32(rdata.Minimum)
	return nil
}

func (rdata *RDataSOA) ReadRecordData(reader *dnsReader, length uint16) (err error) {
	rdata.MName, err = reader.readDomainName()
	if err != nil {
		return fmt.Errorf("invalid SOA record data: %w", err)
	}

	rdata.RName, err = reader.readDomainName()
	if err != nil {
		return fmt.Errorf("invalid SOA record data: %w", err)
	}

	rdata.Serial = reader.readUint32()
	rdata.Refresh = reader.readUint32()
	rdata.Retry = reader.readUint32()
	rdata.Expire = reader.readUint32()
	rdata.Minimum = reader.readUint32()

	return nil
}

// -------------- UNKNOWN

type RDataUnknown struct {
	Raw []byte
}

func (rdata *RDataUnknown) String() string {
	return string(rdata.Raw)
}

func (rdata *RDataUnknown) WriteRecordData(writer *dnsWriter) error {
	writer.writeData(rdata.Raw)
	return nil
}

func (rdata *RDataUnknown) ReadRecordData(reader *dnsReader, length uint16) (err error) {
	rdata.Raw, err = reader.readUntil(int(length))
	if err != nil {
		return err
	}
	return nil
}
