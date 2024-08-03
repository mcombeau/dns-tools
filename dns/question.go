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

func (reader *dnsReader) readQuestions(count uint16) (questions []Question, err error) {
	questions = make([]Question, 0, count)
	for i := 0; i < int(count); i++ {
		question, err := reader.readQuestion()
		if err != nil {
			return nil, err
		}
		questions = append(questions, question)
	}
	return questions, nil
}

func (reader *dnsReader) readQuestion() (question Question, err error) {
	name, err := reader.readDomainName()
	if err != nil {
		return Question{}, invalidQuestionError(err.Error())
	}

	if len(reader.data) < reader.offset+4 {
		return Question{}, invalidQuestionError("too short")
	}

	question = Question{
		Name:   name,
		QType:  reader.readUint16(),
		QClass: reader.readUint16(),
	}

	return question, nil
}

func encodeQuestion(buf *bytes.Buffer, question Question) {
	encodeDomainName(buf, question.Name)
	buf.Write(encodeUint16(question.QType))
	buf.Write(encodeUint16(question.QClass))
}
