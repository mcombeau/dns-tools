package dns

import (
	"bytes"
)

// Question section format
// The question section is used to carry the "question" in most queries,
// i.e., the parameters that define what is being asked.  The section
// contains QDCOUNT (usually 1) entries, each of the following format:

//                                     1  1  1  1  1  1
//       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                                               |
//     /                     QNAME                     /
//     /                                               /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                     QTYPE                     |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                     QCLASS                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

type Question struct {
	Name   string
	QType  uint16
	QClass uint16
}

func decodeQuestion(data []byte, offset int) (Question, int, error) {
	name, newOffset, err := decodeDomainName(data, offset)
	if err != nil {
		return Question{}, 0, invalidQuestionError(err.Error())
	}

	offset += newOffset

	if len(data) < offset+4 {
		return Question{}, 0, invalidQuestionError("too short")
	}

	question := Question{
		Name:   name,
		QType:  decodeUint16(data, offset),
		QClass: decodeUint16(data, offset+2),
	}

	return question, offset + 4, nil
}

func encodeQuestion(buf *bytes.Buffer, question Question) {
	encodeDomainName(buf, question.Name)
	buf.Write(encodeUint16(question.QType))
	buf.Write(encodeUint16(question.QClass))
}
