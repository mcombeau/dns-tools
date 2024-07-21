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
	Header      *Header
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
func DecodeMessage(data []byte) (*Message, error) {
	header, err := decodeHeader(data)
	if err != nil {
		return nil, invalidMessageError(err.Error())
	}
	offset := 12

	questions := make([]Question, 0, header.QuestionCount)
	for i := 0; i < int(header.QuestionCount); i++ {
		question, newOffset, err := decodeQuestion(data, offset)
		if err != nil {
			return nil, invalidMessageError(err.Error())
		}
		questions = append(questions, *question)
		offset = newOffset
	}

	answers, offset, err := decodeResourceRecords(data, offset, header.AnswerRRCount)
	if err != nil {
		return nil, invalidMessageError(fmt.Sprintf("answer section: %s", err.Error()))
	}

	nameServers, offset, err := decodeResourceRecords(data, offset, header.NameserverRRCount)
	if err != nil {
		return nil, invalidMessageError(fmt.Sprintf("authority section: %s", err.Error()))
	}

	additionals, _, err := decodeResourceRecords(data, offset, header.AdditionalRRCount)
	if err != nil {
		return nil, invalidMessageError(fmt.Sprintf("additional section: %s", err.Error()))
	}

	return &Message{
		Header:      header,
		Questions:   questions,
		Answers:     answers,
		NameServers: nameServers,
		Additionals: additionals,
	}, nil
}

func decodeResourceRecords(data []byte, offset int, count uint16) ([]ResourceRecord, int, error) {
	records := make([]ResourceRecord, 0, count)
	for i := 0; i < int(count); i++ {
		record, newOffset, err := decodeResourceRecord(data, offset)
		if err != nil {
			return nil, 0, err
		}
		records = append(records, *record)
		offset = newOffset
	}
	return records, offset, nil
}

// EncodeMessage converts a Message structure into DNS message bytes.
//
// Parameters:
//   - msg: A pointer to a Message structure to encode.
//
// Returns:
//   - []byte: The encoded DNS message bytes.
//   - error: If encoding fails.
func EncodeMessage(msg *Message) ([]byte, error) {
	buf := new(bytes.Buffer)

	encodeHeader(buf, msg)

	for _, question := range msg.Questions {
		encodeQuestion(buf, question)
	}

	for _, rr := range msg.Answers {
		encodeResourceRecord(buf, rr)
	}
	for _, rr := range msg.NameServers {
		encodeResourceRecord(buf, rr)
	}
	for _, rr := range msg.Additionals {
		encodeResourceRecord(buf, rr)
	}

	return buf.Bytes(), nil
}
