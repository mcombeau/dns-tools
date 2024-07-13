package dnsparser

import "errors"

type DNSResourceRecord struct {
	Name     string
	RType    uint16
	RClass   uint16
	TTL      uint32
	RDLength uint16
	// RData    []byte
}

func parseDNSResourceRecord(data []byte, offset int) (*DNSResourceRecord, int, error) {
	name, newOffset := parseDomainName(data, offset)
	offset += newOffset

	if len(data) < offset+10 {
		return &DNSResourceRecord{}, 0, errors.New("invalid DNS resource record")
	}

	record := DNSResourceRecord{
		Name:     name,
		RType:    parseUint16(data, offset),
		RClass:   parseUint16(data, offset+2),
		TTL:      parseUint32(data, offset+4),
		RDLength: parseUint16(data, offset+8),
	}

	return &record, offset + 10, nil
}
