package dns

import (
	"bytes"
	"errors"
	"fmt"
)

type Message struct {
	Header      *Header
	Questions   []Question
	Answers     []ResourceRecord
	NameServers []ResourceRecord
	Additionals []ResourceRecord
}

func DecodeMessage(data []byte) (*Message, error) {
	if len(data) < 12 {
		return nil, errors.New("invalid DNS message: too short")
	}

	header, err := DecodeHeader(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DNS header: %v", err)
	}
	offset := 12

	questions := make([]Question, 0, header.QuestionCount)
	for i := 0; i < int(header.QuestionCount); i++ {
		question, newOffset, err := decodeQuestion(data, offset)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DNS question: %v", err)
		}
		questions = append(questions, *question)
		offset = newOffset
	}

	answers, offset, err := decodeResourceRecords(data, offset, header.AnswerRRCount)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DNS answer: %v", err)
	}

	nameServers, offset, err := decodeResourceRecords(data, offset, header.NameserverRRCount)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DNS authority name server: %v", err)
	}

	additionals, _, err := decodeResourceRecords(data, offset, header.AdditionalRRCount)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DNS answer: %v", err)
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
