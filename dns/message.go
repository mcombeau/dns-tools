package dns

import (
	"bytes"
	"fmt"
)

// Message format:
// All communications inside of the domain protocol are carried in a single
// format called a message.  The top level format of message is divided
// into 5 sections (some of which are empty in certain cases) shown below:

//     +---------------------+
//     |        Header       |
//     +---------------------+
//     |       Question      | the question for the name server
//     +---------------------+
//     |        Answer       | RRs answering the question
//     +---------------------+
//     |      Authority      | RRs pointing toward an authority
//     +---------------------+
//     |      Additional     | RRs holding additional information
//     +---------------------+

type Message struct {
	Header      Header
	Questions   []Question
	Answers     []ResourceRecord
	NameServers []ResourceRecord
	Additionals []ResourceRecord
}

// DecodeMessage parses DNS message data and returns a Message structure.
//
// Parameters:
//   - data: The DNS message in a byte slice.
//
// Returns:
//   - *Message: The decoded DNS message in a structure.
//   - error: If the message is invalid or decoding fails.
func DecodeMessage(data []byte) (Message, error) {
	reader := &dnsReader{data: data}

	header, err := reader.readHeader()
	if err != nil {
		return Message{}, invalidMessageError(err.Error())
	}
	if reader.offset != HeaderLength {
		return Message{}, invalidMessageError("invalid offset after reading header")

	}

	questions, err := reader.readQuestions(header.QuestionCount)
	if err != nil {
		return Message{}, invalidMessageError(fmt.Sprintf("question section: %s", err.Error()))
	}

	answers, err := reader.readResourceRecords(header.AnswerRRCount)
	if err != nil {
		return Message{}, invalidMessageError(fmt.Sprintf("answer section: %s", err.Error()))
	}

	nameServers, err := reader.readResourceRecords(header.NameserverRRCount)
	if err != nil {
		return Message{}, invalidMessageError(fmt.Sprintf("authority section: %s", err.Error()))
	}

	additionals, err := reader.readResourceRecords(header.AdditionalRRCount)
	if err != nil {
		return Message{}, invalidMessageError(fmt.Sprintf("additional section: %s", err.Error()))
	}

	return Message{
		Header:      header,
		Questions:   questions,
		Answers:     answers,
		NameServers: nameServers,
		Additionals: additionals,
	}, nil
}

// EncodeMessage converts a Message structure into DNS message bytes.
//
// Parameters:
//   - msg: A pointer to a Message structure to encode.
//
// Returns:
//   - []byte: The encoded DNS message bytes.
//   - error: If encoding fails.
func EncodeMessage(msg Message) ([]byte, error) {
	buf := new(bytes.Buffer)

	encodeHeader(buf, msg)

	encodeQuestions(msg.Questions, buf)
	encodeResourceRecords(msg.Answers, buf)
	encodeResourceRecords(msg.NameServers, buf)
	encodeResourceRecords(msg.Additionals, buf)

	return buf.Bytes(), nil
}

func encodeQuestions(questions []Question, buf *bytes.Buffer) {
	for _, question := range questions {
		encodeQuestion(buf, question)
	}
}

func encodeResourceRecords(resourceRecords []ResourceRecord, buf *bytes.Buffer) {
	for _, rr := range resourceRecords {
		encodeResourceRecord(buf, rr)
	}
}
