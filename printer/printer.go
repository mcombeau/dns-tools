package printer

import (
	"fmt"

	"github.com/mcombeau/go-dns-tools/dns"
)

func PrintDNSMessage(message *dns.Message) {
	printDNSHeader(message.Header)
	printDNSQuestions(message.Questions)
	printDNSResourceRecord(message.Answers, "Answers:")
	printDNSResourceRecord(message.NameServers, "Authorities:")
	printDNSResourceRecord(message.Additionals, "Additionals:")
}

func printDNSHeader(header *dns.Header) {
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
	fmt.Printf("\tResponseCode: %d\n", header.Flags.ResponseCode)
	fmt.Printf("Question count: %d\n", header.QuestionCount)
	fmt.Printf("Answer RR count: %d\n", header.AnswerRRCount)
	fmt.Printf("Authority RR count: %d\n", header.NameserverRRCount)
	fmt.Printf("Additional RR count: %d\n", header.AdditionalRRCount)
}

func printDNSQuestions(questions []dns.Question) {
	fmt.Println("Questions:")
	for _, question := range questions {
		fmt.Printf("\tName: %s\n", question.Name)
		fmt.Printf("\tQType: %d\n", question.QType)
		fmt.Printf("\tQClass: %d\n", question.QClass)
	}
}

func printDNSResourceRecord(records []dns.ResourceRecord, title string) {
	fmt.Println(title)
	for _, record := range records {
		fmt.Printf("\tName: %s\n", record.Name)
		fmt.Printf("\tRType: %d\n", record.RType)
		fmt.Printf("\tRClass: %d\n", record.RClass)
		fmt.Printf("\tTTL: %d\n", record.TTL)
		fmt.Printf("\tRDLength: %d\n", record.RDLength)
		fmt.Printf("\tRData: %v\n", record.RData)
	}
}
