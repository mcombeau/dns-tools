package dns

import (
	"bytes"
	"fmt"
)

// Resource record format

// The answer, authority, and additional sections all share the same
// format: a variable number of resource records, where the number of
// records is specified in the corresponding count field in the header.
// Each resource record has the following format:
//                                     1  1  1  1  1  1
//       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                                               |
//     /                                               /
//     /                      NAME                     /
//     |                                               |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                      TYPE                     |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                     CLASS                     |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                      TTL                      |
//     |                                               |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                   RDLENGTH                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
//     /                     RDATA                     /
//     /                                               /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

type ResourceRecord struct {
	Name     string
	RType    uint16
	RClass   uint16
	TTL      uint32
	RDLength uint16
	RData    RData
}

func decodeResourceRecord(data []byte, offset int) (ResourceRecord, int, error) {
	name, newOffset, err := decodeDomainName(data, offset)
	if err != nil {
		return ResourceRecord{}, 0, invalidResourceRecordError(err.Error())
	}

	offset += newOffset

	if len(data) < offset+10 {
		return ResourceRecord{}, 0, invalidResourceRecordError("too short")
	}
	rtype := decodeUint16(data, offset)
	rclass := decodeUint16(data, offset+2)
	ttl := decodeUint32(data, offset+4)
	rdlength := decodeUint16(data, offset+8)
	offset += 10

	if len(data) < offset+int(rdlength) {
		return ResourceRecord{}, 0, invalidResourceRecordError("invalid RData length: too short")
	}

	rdata, err := getRDataStruct(rtype)
	if err != nil {
		return ResourceRecord{}, 0, invalidResourceRecordError(err.Error())
	}

	_, err = rdata.Decode(data, offset, rdlength)
	if err != nil {
		return ResourceRecord{}, 0, invalidResourceRecordError(err.Error())
	}

	record := ResourceRecord{
		Name:     name,
		RType:    rtype,
		RClass:   rclass,
		TTL:      ttl,
		RDLength: rdlength,
		RData:    rdata,
	}

	offset += int(record.RDLength)

	return record, offset, nil
}

func getRDataStruct(rtype uint16) (RData, error) {

	var rdata RData
	switch rtype {
	case A:
		rdata = &RDataA{}
	case AAAA:
		rdata = &RDataAAAA{}
	case CNAME:
		rdata = &RDataCNAME{}
	case PTR:
		rdata = &RDataPTR{}
	case NS:
		rdata = &RDataNS{}
	case TXT:
		rdata = &RDataTXT{}
	case MX:
		rdata = &RDataMX{}
	case SOA:
		rdata = &RDataSOA{}
	default:
		// TODO: Get a better error type for this
		// or define a default way of handling unsupported RDATA types
		return nil, invalidResourceRecordError(fmt.Sprintf("unsupported RDATA type: %s", DNSType(rtype)))
	}
	return rdata, nil
}

func encodeResourceRecord(buf *bytes.Buffer, rr ResourceRecord) {
	encodeDomainName(buf, rr.Name)
	buf.Write(encodeUint16(rr.RType))
	buf.Write(encodeUint16(rr.RClass))
	buf.Write(encodeUint32(rr.TTL))
	buf.Write(encodeUint16(rr.RDLength))
	rr.RData.Encode(buf)
}
