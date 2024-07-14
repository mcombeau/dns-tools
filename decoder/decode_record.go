package decoder

import (
	"errors"

	"github.com/mcombeau/go-dns-tools/utils"
)

type DNSResourceRecord struct {
	Name     string
	RType    uint16
	RClass   uint16
	TTL      uint32
	RDLength uint16
	RData    []byte
}

func decodeDNSResourceRecord(data []byte, offset int) (*DNSResourceRecord, int, error) {
	name, newOffset, err := utils.DecodeDomainName(data, offset)
	if err != nil {
		return &DNSResourceRecord{}, 0, err
	}

	offset += newOffset

	if len(data) < offset+10 {
		return &DNSResourceRecord{}, 0, errors.New("invalid DNS resource record")
	}

	record := DNSResourceRecord{
		Name:     name,
		RType:    utils.ParseUint16(data, offset),
		RClass:   utils.ParseUint16(data, offset+2),
		TTL:      utils.ParseUint32(data, offset+4),
		RDLength: utils.ParseUint16(data, offset+8),
	}
	offset += 10

	if len(data) < offset+int(record.RDLength) {
		return &DNSResourceRecord{}, 0, errors.New("invalid DNS resource record RDATA length")
	}

	record.RData = data[offset : offset+int(record.RDLength)]
	offset += int(record.RDLength)

	return &record, offset, nil
}
