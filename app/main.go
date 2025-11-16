package main

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Ensures gofmt doesn't remove the "net" import in stage 1 (feel free to remove this!)
var _ = net.ListenUDP

type DNSHeader struct {
	ID      uint16
	QR      uint8 // 1 bit
	OPCODE  uint8 // 4 bits
	AA      uint8 // 1 bit
	TC      uint8 // 1 bit
	RD      uint8 // 1 bit
	RA      uint8 // 1 bit
	Z       uint8 // 3 bits
	RCODE   uint8 // 4 bits
	QDCOUNT uint16
	ANCOUNT uint16
	NSCOUNT uint16
	ARCOUNT uint16
}

func (m *DNSHeader) Encode() []byte {
	// Allocating 12 bytes for the header
	header := make([]byte, 12)

	// Writing ID , bytes 0-1
	binary.BigEndian.PutUint16(header[0:2], m.ID)

	// Writing Flags, bytes 2-3
	// Byte 2: QR(1) | OPCODE(4) | AA(1) | TC(1) | RD(1)
	// Byte 3: RA(1) | Z(3) | RCODE(4)
	flags := uint16(0)
	flags |= uint16(m.QR&1) << 15
	flags |= uint16(m.OPCODE&0x0F) << 11
	flags |= uint16(m.AA&1) << 10
	flags |= uint16(m.TC&1) << 9
	flags |= uint16(m.RD&1) << 8
	flags |= uint16(m.RA&1) << 7
	flags |= uint16(m.Z&0x07) << 4
	flags |= uint16(m.RCODE & 0x0F)

	// Inserting flags into header
	binary.BigEndian.PutUint16(header[2:4], flags)

	// Writing QDCOUNT, bytes 4-5
	binary.BigEndian.PutUint16((header[4:6]), m.QDCOUNT)

	// Writing ANCOUNT, bytes 6-7
	binary.BigEndian.PutUint16(header[6:8], m.ANCOUNT)

	// Writing NSCOUNT, bytes 8-9
	binary.BigEndian.PutUint16(header[8:10], m.NSCOUNT)

	// Writing ARCOUNT, bytes 10-11
	binary.BigEndian.PutUint16(header[10:12], m.ARCOUNT)

	return header
}

func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}

	// called when the surrounding function exits
	defer udpConn.Close()

	buf := make([]byte, 512)
	fmt.Println(buf)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		// Parsing request ID from the first 2 bytes
		var requestID uint16
		if size >= 2 {
			requestID = binary.BigEndian.Uint16(buf[0:2])
		}

		// Creating respone header
		response := DNSHeader{
			ID:      requestID,
			QR:      1, // Response
			OPCODE:  0, // Standard query
			AA:      0, // Not authoritative
			TC:      0, // Not truncated
			RD:      0, // Recursion not desired
			RA:      0, // Recursion not available
			Z:       0, // Reserved
			RCODE:   0, // No error
			QDCOUNT: 0, // No questions
			ANCOUNT: 0, // No answers
			NSCOUNT: 0, // No authority records
			ARCOUNT: 0, // No additional records
		}

		responseBytes := response.Encode()

		_, err = udpConn.WriteToUDP(responseBytes, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
