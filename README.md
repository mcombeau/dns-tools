# dns-tools

A small DNS message toolkit in Go. It includes encoding and decoding functions and is mostly RFC 1035 compliant. It's able to handle compressed DNS messages.

It also includes a main which is able to encode and send a DNS question and print the answer in a human-readable dig-like format.

## Usage

To test:

```shell
go test ./... -v
```

To run main:

```shell
go run ./cmd/main.go [-s server] [-p port] [-x] <domain_or_ip> [question_type]
```

Options:

- `-h`: show help
- `-s`: specify the DNS resolver server IP to query (defaults to local resolver)
- `-p`: specify the DNS resolver server port to query (defaults to 53)
- `-x`: enable reverse DNS query (default: false)

---
Made by mcombeau | LinkedIn: [mcombeau](https://www.linkedin.com/in/mia-combeau-86653420b/) | Website: [codequoi.com](https://www.codequoi.com)