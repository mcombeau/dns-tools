package dns

import (
	"bytes"
	"errors"
)

type Question struct {
	Name   string
	QType  uint16
	QClass uint16
}

func decodeQuestion(data []byte, offset int) (*Question, int, error) {
	name, newOffset, err := decodeDomainName(data, offset)
	if err != nil {
		return &Question{}, 0, err
	}

	offset += newOffset

	if len(data) < offset+4 {
		return &Question{}, 0, errors.New("invalid DNS question")
	}

	question := Question{
		Name:   name,
		QType:  decodeUint16(data, offset),
		QClass: decodeUint16(data, offset+2),
	}

	return &question, offset + 4, nil
}

func encodeQuestion(buf *bytes.Buffer, question Question) {
	encodeDomainName(buf, question.Name)
	buf.Write(encodeUint16(question.QType))
	buf.Write(encodeUint16(question.QClass))
}
