package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/mcombeau/dns-tools/pkg/dns"
)

const RootServerHintsFile = "config/named.root"
const ServerIP = "0.0.0.0"
const ServerPort = 5553

func main() {

	resolver, err := dns.NewResolver(RootServerHintsFile)
	if err != nil {
		log.Fatalf("Failed to create resolver: %v", err)
	}

	err = startUDPServer(resolver)
	if err != nil {
		log.Fatalf("Failed to start UDP server: %v", err)
	}
}

func startUDPServer(resolver *dns.Resolver) (err error) {
	var wg sync.WaitGroup

	addr := net.UDPAddr{
		Port: ServerPort,
		IP:   net.ParseIP(ServerIP),
	}

	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		return fmt.Errorf("failed to set up UDP listener: %w", err)
	}
	defer conn.Close()

	log.Printf("DNS resolver UDP server listening on port: %d", addr.Port)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutdown signal received, closing UDP connection...")
		conn.Close()
	}()

	buffer := [dns.MaxUDPMessageLength]byte{}
	for {
		n, clientAddr, err := conn.ReadFromUDP(buffer[:])
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Println("Server listener connection closed")
				break
			}
			log.Printf("Error reading from UDP: %v", err)
			continue
		}

		wg.Add(1)
		go handleRequest(resolver, &wg, conn, clientAddr, buffer[:n])
	}

	wg.Wait()
	log.Println("Server shutdown gracefully")
	return nil
}

func handleRequest(resolver *dns.Resolver, wg *sync.WaitGroup, conn *net.UDPConn, clientAddr *net.UDPAddr, request []byte) {
	defer wg.Done()
	log.Printf("Handling client %v request: %v\n", clientAddr, request)

	response, err := resolver.ResolveQuery(request)
	if err != nil {
		log.Printf("Failed to resolve DNS request from client %v: %v", clientAddr, err)
	}

	log.Printf("Sending response to client %v", clientAddr)
	_, err = conn.WriteToUDP(response, clientAddr)
	if err != nil {
		log.Printf("Failed to send response to client %v: %v", clientAddr, err)
		return
	}
}
