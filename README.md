# dns-tools

A small DNS message toolkit in Go, which is mostly RFC 1035 compliant. It includes encoding and decoding functions and is able to handle compressed DNS messages.

It also includes a client which is able to encode and send a DNS question and print the answer in a human-readable dig-like format.

## Usage

To run tests:

```shell
go test ./... -v
```

### DNS Client

To run the DNS client:

```shell
go run ./cmd/client/client.go [-s server] [-p port] [-x] <domain_or_ip> [question_type]
```

Options:

- `-h`: show help
- `-s`: specify the DNS resolver server IP to query (defaults to local resolver)
- `-p`: specify the DNS resolver server port to query (defaults to 53)
- `-x`: enable reverse DNS query (default: false)

### DNS Server

To run the DNS server:

```shell
go run ./cmd/server/server.go
```

The server runs on `127.0.0.1:5553`.

To test the server with `dig`:

```shell
dig @127.0.0.1 -p 5553 example.com A
```

To test the server with the included client:

```shell
go run ./cmd/client/client.go -s 127.0.0.1 -p 5553 example.com A
```

---
Made by mcombeau | LinkedIn: [mcombeau](https://www.linkedin.com/in/mia-combeau-86653420b/) | Website: [codequoi.com](https://www.codequoi.com)
