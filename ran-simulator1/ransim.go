package main

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"log"
	"net"
)

// Generate a 256-bit random key
func generateRandomKey() ([]byte, error) {
	key := make([]byte, 32) // 256-bit key
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func main() {
	// Load server TLS certificate and key
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatalf("Failed to load server certificate: %v", err)
	}

	// TLS configuration (NO client auth for now)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Start TLS server
	listener, err := tls.Listen("tcp", ":8080", tlsConfig)
	if err != nil {
		log.Fatalf("Failed to start TLS server: %v", err)
	}
	defer listener.Close()
	fmt.Println("RAN-Simulator (Standalone) listening on port 8080...")

	// Accept connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

// Handle a new connection (SGX enclave)
func handleConnection(conn net.Conn) {
	defer conn.Close()

	fmt.Println("Secure connection established with SGX!")

	// Generate a 256-bit random key
	key, err := generateRandomKey()
	if err != nil {
		log.Println("Error generating key:", err)
		return
	}

	// Send the key over TLS
	_, err = conn.Write(key)
	if err != nil {
		log.Println("Error sending key:", err)
		return
	}

	fmt.Println("Key securely sent to SGX.")
}
