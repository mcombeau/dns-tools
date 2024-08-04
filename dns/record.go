package dns

import (
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

func (reader *dnsReader) readResourceRecords(count uint16) (records []ResourceRecord, err error) {
	records = make([]ResourceRecord, 0, count)
	for i := 0; i < int(count); i++ {
		record, err := reader.readResourceRecord()
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func (reader *dnsReader) readResourceRecord() (record ResourceRecord, err error) {
	name, err := reader.readDomainName()
	if err != nil {
		return ResourceRecord{}, invalidResourceRecordError(err.Error())
	}

	if len(reader.data) < reader.offset+10 {
		return ResourceRecord{}, invalidResourceRecordError("too short")
	}
	rtype := reader.readUint16()
	rclass := reader.readUint16()
	ttl := reader.readUint32()
	rdlength := reader.readUint16()

	if len(reader.data) < reader.offset+int(rdlength) {
		return ResourceRecord{}, invalidResourceRecordError("invalid RData length: too short")
	}

	rdata, err := getRDataStruct(rtype)
	if err != nil {
		return ResourceRecord{}, invalidResourceRecordError(err.Error())
	}

	err = rdata.ReadRecordData(reader, rdlength)
	if err != nil {
		return ResourceRecord{}, invalidResourceRecordError(err.Error())
	}

	record = ResourceRecord{
		Name:     name,
		RType:    rtype,
		RClass:   rclass,
		TTL:      ttl,
		RDLength: rdlength,
		RData:    rdata,
	}

	return record, nil
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

func (writer *dnsWriter) writeResourceRecords(resourceRecords []ResourceRecord) {
	for _, record := range resourceRecords {
		writer.writeResourceRecord(record)
	}
}

func (writer *dnsWriter) writeResourceRecord(record ResourceRecord) {
	writer.writeDomainName(record.Name)
	writer.writeUint16(record.RType)
	writer.writeUint16(record.RClass)
	writer.writeUint32(record.TTL)
	writer.writeUint16(record.RDLength)
	record.RData.WriteRecordData(writer)
}
