package dns

type dnsWriter struct {
	data   []byte
	offset int
}

func (writer *dnsWriter) writeUint16(value uint16) {
	// Ensure there is enough space
	if writer.offset+2 > len(writer.data) {
		writer.data = append(writer.data, make([]byte, writer.offset+2-len(writer.data))...)
	}
	// Write the value
	writer.data[writer.offset] = byte(value >> 8)
	writer.data[writer.offset+1] = byte(value & 0xFF)
	writer.offset += 2
}

func (writer *dnsWriter) writeUint32(value uint32) {
	// Ensure there is enough space
	if writer.offset+4 > len(writer.data) {
		writer.data = append(writer.data, make([]byte, writer.offset+4-len(writer.data))...)
	}
	// Write the value
	writer.data[writer.offset] = byte(value >> 24)
	writer.data[writer.offset+1] = byte((value >> 16) & 0xFF)
	writer.data[writer.offset+2] = byte((value >> 8) & 0xFF)
	writer.data[writer.offset+3] = byte(value & 0xFF)
	writer.offset += 4
}

func (writer *dnsWriter) writeData(data []byte) {
	// Ensure there is enough space
	if writer.offset+len(data) > len(writer.data) {
		writer.data = append(writer.data, make([]byte, writer.offset+len(data)-len(writer.data))...)
	}
	//Copy the data
	copy(writer.data[writer.offset:], data)
	writer.offset += len(data)
}
