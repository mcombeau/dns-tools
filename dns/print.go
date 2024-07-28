package dns

import (
	"fmt"
	"strings"
	"time"
)

// PrintQueryInfo prints information about a DNS query.
//
// Parameters:
//   - dnsServer: The DNS server the query is sent to.
//   - queryTime: The duration of the query.
//   - tcpQuery: Indicates if the query was over TCP (true) or UDP (false).
//   - messageLength: The length of the message.
func PrintQueryInfo(dnsServer string, queryTime time.Duration, tcpQuery bool, messageLength int) {
	fmt.Printf("\n;; Query time: %v\n", queryTime)
	fmt.Printf(";; SERVER: %s ", dnsServer)
	if tcpQuery {
		fmt.Printf("(TCP)\n")
	} else {
		fmt.Printf("(UDP)\n")
	}
	fmt.Println(";; WHEN:", time.Now().Format(time.RFC1123))
	fmt.Println(";; MSG SIZE recvd:", messageLength)
}

// PrintBasicQueryInfo prints the basic query information.
//
// Parameters:
//   - domainName: The domain name being queried.
//   - questionType: The type of DNS query.
func PrintBasicQueryInfo(domainName string, questionType uint16) {
	fmt.Printf("; <<>> DNSTool <<>> %s %s\n", domainName, DNSType(questionType))
}

// PrintMessage prints the details of a DNS message.
//
// Parameters:
//   - message: A pointer to the Message structure to print.
func PrintMessage(message Message) {
	fmt.Println(";; Got answer:")

	printHeader(message.Header)

	if message.Header.QuestionCount > 0 {
		printQuestions(message.Questions)
	}

	if message.Header.AnswerRRCount > 0 {
		printResourceRecord(message.Answers, "Answer")
	}

	if message.Header.NameserverRRCount > 0 {
		printResourceRecord(message.NameServers, "Authority")
	}

	if message.Header.AdditionalRRCount > 0 {
		printResourceRecord(message.Additionals, "Additional")
	}
}

func printHeader(header Header) {

	fmt.Printf(";; ->>HEADER<<- ")
	fmt.Printf("opcode: %s, ", DNSOpCode(header.Flags.Opcode))
	fmt.Printf("status: %s, ", DNSRCode(header.Flags.ResponseCode))
	fmt.Printf("id: %d\n", header.Id)

	fmt.Printf(";; flags: %s; ", getFlagString(header.Flags))
	fmt.Printf("QUERY: %d; ", header.QuestionCount)
	fmt.Printf("ANSWER: %d; ", header.AnswerRRCount)
	fmt.Printf("AUTHORITY: %d; ", header.NameserverRRCount)
	fmt.Printf("ADDITIONAL: %d\n", header.AdditionalRRCount)
}

func getFlagString(flags Flags) string {
	flagStrings := []string{}

	if flags.Response {
		flagStrings = append(flagStrings, "qr")
	}
	if flags.Authoritative {
		flagStrings = append(flagStrings, "aa")
	}
	if flags.Truncated {
		flagStrings = append(flagStrings, "tc")
	}
	if flags.RecursionDesired {
		flagStrings = append(flagStrings, "rd")
	}
	if flags.RecursionAvailable {
		flagStrings = append(flagStrings, "ra")
	}
	if flags.DnssecOk {
		flagStrings = append(flagStrings, "do")
	}
	if flags.AuthenticatedData {
		flagStrings = append(flagStrings, "ad")
	}
	if flags.CheckingDisabled {
		flagStrings = append(flagStrings, "cd")
	}

	return strings.Join(flagStrings, " ")
}

func printQuestions(questions []Question) {
	fmt.Printf("\n;; QUESTION SECTION:\n")
	for _, question := range questions {
		fmt.Printf(";%s\t\t", question.Name)
		fmt.Printf("%s\t", DNSClass(question.QClass).String())
		fmt.Printf("%s\n", DNSType(question.QType).String())
	}
}

func printResourceRecord(records []ResourceRecord, title string) {
	fmt.Printf("\n;; %s SECTION:\n", strings.ToUpper(title))
	for _, record := range records {
		fmt.Printf(";%s\t", record.Name)
		fmt.Printf("%d\t", record.TTL)
		fmt.Printf("%s\t", DNSClass(record.RClass).String())
		fmt.Printf("%s\t", DNSType(record.RType).String())
		fmt.Printf("%s\n", record.RData.String())
	}
}
