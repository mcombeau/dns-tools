package decoder

import (
	"errors"

	"github.com/mcombeau/go-dns-tools/dns"
	"github.com/mcombeau/go-dns-tools/utils"
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

	record := dns.ResourceRecord{
		Name:     name,
		RType:    utils.DecodeUint16(data, offset),
		RClass:   utils.DecodeUint16(data, offset+2),
		TTL:      utils.DecodeUint32(data, offset+4),
		RDLength: utils.DecodeUint16(data, offset+8),
	}
	offset += 10

	if len(data) < offset+int(record.RDLength) {
		return &dns.ResourceRecord{}, 0, errors.New("invalid DNS resource record RDATA length")
	}

	record.RData = data[offset : offset+int(record.RDLength)]
	offset += int(record.RDLength)

	return &record, offset, nil
}
