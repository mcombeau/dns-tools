package dns

type dnsReader struct {
	data   []byte
	offset int
}

// readuint16:
// "Concatenate" two bytes in a slice to int16.

// Ex.:

// data[0]: 0x12:	00010010
// data[1]: 0x34:	00110100

// uint16(data[0]):	00000000 00010010
// uint16(data[1]):	00000000 00110100

// uint16(data[0]) << 8:	00010010 00000000
// uint16(data[1]):			00000000 00110100
// |:						00010010 00110100

// hex:					0x12	 0x34		: 0x1234

func (reader *dnsReader) readUint16() (value uint16) {
	value = uint16(reader.data[reader.offset])<<8 |
		uint16(reader.data[reader.offset+1])

	reader.offset += 2

	return value
}

func (reader *dnsReader) readUint32() (value uint32) {
	value = uint32(reader.data[reader.offset])<<24 |
		uint32(reader.data[reader.offset+1])<<16 |
		uint32(reader.data[reader.offset+2])<<8 |
		uint32(reader.data[reader.offset+3])

	reader.offset += 4

	return value
}
