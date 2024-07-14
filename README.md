# go-dns-tools

A small Golang DNS message toolkit. It includes encoding and decoding functions and is mostly RFC 1035 compliant. It's able to handle compressed DNS messages.

It also includes a main which is able to encode and send a DNS question and print the answer in a human-readable dig-like format.

## Usage

To test:

```shell
go test ./... -v
```

To run main:

```shell
go run ./cmd/example/main.go <domain> [question type]
```

---
Made by mcombeau | LinkedIn: [mcombeau](https://www.linkedin.com/in/mia-combeau-86653420b/) | Website: [codequoi.com](https://www.codequoi.com)