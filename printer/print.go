package printer

import (
	"fmt"
	"strings"

	"github.com/mcombeau/go-dns-tools/dns"
)

func PrintDNSMessage(message *dns.Message) {
	printDNSHeader(message.Header)
	if message.Header.QuestionCount > 0 {
		printDNSQuestions(message.Questions)
	}
	if message.Header.AnswerRRCount > 0 {
		printDNSResourceRecord(message.Answers, "Answers")
	}
	if message.Header.NameserverRRCount > 0 {
		printDNSResourceRecord(message.NameServers, "Authorities")
	}
	if message.Header.AdditionalRRCount > 0 {
		printDNSResourceRecord(message.Additionals, "Additionals")
	}
}

func printDNSHeader(header *dns.Header) {
	fmt.Println("---------------HEADER")
	fmt.Printf("Transaction ID: %d\n", header.Id)
	fmt.Println("Flags:")
	fmt.Printf("\tResponse: %t\n", header.Flags.Response)
	fmt.Printf("\tOpcode: %d\n", header.Flags.Opcode)
	fmt.Printf("\tAuthoritative: %t\n", header.Flags.Authoritative)
	fmt.Printf("\tTruncated: %t\n", header.Flags.Truncated)
	fmt.Printf("\tRecursionDesired: %t\n", header.Flags.RecursionDesired)
	fmt.Printf("\tRecursionAvailable: %t\n", header.Flags.RecursionAvailable)
	fmt.Printf("\tDnssecOk: %t\n", header.Flags.DnssecOk)
	fmt.Printf("\tAuthenticatedData: %t\n", header.Flags.AuthenticatedData)
	fmt.Printf("\tCheckingDisabled: %t\n", header.Flags.CheckingDisabled)
	fmt.Printf("\tResponseCode: %s\n", DNSRCode(header.Flags.ResponseCode))
	fmt.Printf("Question count: %d\n", header.QuestionCount)
	fmt.Printf("Answer RR count: %d\n", header.AnswerRRCount)
	fmt.Printf("Authority RR count: %d\n", header.NameserverRRCount)
	fmt.Printf("Additional RR count: %d\n", header.AdditionalRRCount)
}

func printDNSQuestions(questions []dns.Question) {
	fmt.Println("---------------QUESTIONS")
	for _, question := range questions {
		fmt.Println("Question:")
		fmt.Printf("\tName: %s\n", question.Name)
		fmt.Printf("\tQType: %s\n", DNSType(question.QType).String())
		fmt.Printf("\tQClass: %s\n", DNSClass(question.QClass).String())
	}
}

func printDNSResourceRecord(records []dns.ResourceRecord, title string) {
	fmt.Printf("---------------%s\n", strings.ToUpper(title))
	for _, record := range records {
		fmt.Println("Record:")
		fmt.Printf("\tName: %s\n", record.Name)
		fmt.Printf("\tRType: %s\n", DNSType(record.RType).String())
		fmt.Printf("\tRClass: %s\n", DNSClass(record.RClass).String())
		fmt.Printf("\tTTL: %d\n", record.TTL)
		fmt.Printf("\tRDLength: %d\n", record.RDLength)
		fmt.Printf("\tRData: %v\n", record.RData)
	}
}
