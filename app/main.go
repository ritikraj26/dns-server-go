package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
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

type DNSQuestion struct {
	NAME  string
	TYPE  uint16
	CLASS uint16
}

type DNSAnswer struct {
	NAME   string
	TYPE   uint16
	CLASS  uint16
	TTL    uint32
	LENGTH uint16
	DATA   string
}

type DNSResponse struct {
	HEADER   DNSHeader
	QUESTION DNSQuestion
	ANSWER   DNSAnswer
}

func (h *DNSHeader) EncodeHeader() []byte {
	// Allocating 12 bytes for the header
	header := make([]byte, 12)

	// Writing ID , bytes 0-1
	binary.BigEndian.PutUint16(header[0:2], h.ID)

	// Writing Flags, bytes 2-3
	// Byte 2: QR(1) | OPCODE(4) | AA(1) | TC(1) | RD(1)
	// Byte 3: RA(1) | Z(3) | RCODE(4)
	flags := uint16(0)
	flags |= uint16(h.QR&1) << 15
	flags |= uint16(h.OPCODE&0x0F) << 11
	flags |= uint16(h.AA&1) << 10
	flags |= uint16(h.TC&1) << 9
	flags |= uint16(h.RD&1) << 8
	flags |= uint16(h.RA&1) << 7
	flags |= uint16(h.Z&0x07) << 4
	flags |= uint16(h.RCODE & 0x0F)

	// Inserting flags into header
	binary.BigEndian.PutUint16(header[2:4], flags)

	// Writing QDCOUNT, bytes 4-5
	binary.BigEndian.PutUint16((header[4:6]), h.QDCOUNT)

	// Writing ANCOUNT, bytes 6-7
	binary.BigEndian.PutUint16(header[6:8], h.ANCOUNT)

	// Writing NSCOUNT, bytes 8-9
	binary.BigEndian.PutUint16(header[8:10], h.NSCOUNT)

	// Writing ARCOUNT, bytes 10-11
	binary.BigEndian.PutUint16(header[10:12], h.ARCOUNT)

	return header
}

func (q *DNSQuestion) EncodeQuestion() []byte {
	question := []byte{} // 4 extra bytes for TYPE and CLASS

	// Encoding NAME
	labels := strings.Split(q.NAME, ".")

	for _, label := range labels {
		question = append(question, byte(len(label)))
		question = append(question, []byte(label)...)
	}
	// Appending the null byte to terminate the NAME
	question = append(question, 0x00)

	// Encoding TYPE
	{
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, q.TYPE)
		question = append(question, buf...)
	}

	// Encoding CLASS
	{
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, q.CLASS)
		question = append(question, buf...)
	}

	return question
}

func (a *DNSAnswer) EncodeAnswer() []byte {
	answer := []byte{}

	labels := strings.Split(a.NAME, ".")

	for _, label := range labels {
		answer = append(answer, byte(len(label)))
		answer = append(answer, []byte(label)...)
	}
	// Null byte to terminate NAME
	answer = append(answer, 0x00)

	// Encoding TYPE
	{
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, a.TYPE)
		answer = append(answer, buf...)
	}

	// Encoding CLASS
	{
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, a.CLASS)
		answer = append(answer, buf...)
	}

	// Encoding TTL
	{
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, a.TTL)
		answer = append(answer, buf...)
	}

	// Encoding LENGTH
	{
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, a.LENGTH)
		answer = append(answer, buf...)
	}

	// Encoding DATA
	{
		// buf := []byte{}

		// labels := strings.Split(a.DATA, ".")
		// for _, label := range labels {
		// 	buf = append(buf, byte(len(label)))
		// 	buf = append(buf, []byte(label)...)
		// }

		// buf = append(buf, 0x00) // Null byte to terminate DATA
		// answer = append(answer, buf...)

		ipParts := strings.Split(a.DATA, ".")
		for _, part := range ipParts {
			var bytePart uint8
			fmt.Sscanf(part, "%d", &bytePart)
			answer = append(answer, byte(bytePart))
		}
	}

	return answer
}

func ParseHeader(buf []byte, size int) (uint16, uint8, uint8, uint8, uint8, uint8, uint8, uint8, uint8, uint16, uint16, uint16, uint16) {
	var ID uint16
	if size >= 2 {
		ID = binary.BigEndian.Uint16(buf[0:2])
	}

	var QR uint8 = 1
	// if size >= 4 {
	// 	QR = buf[2] >> 7 & 0x01
	// }

	var OPCODE uint8
	if size >= 4 {
		OPCODE = buf[2] >> 3 & 0x0F
	}

	var AA uint8 = 0
	// if size >= 4 {
	// 	AA = (buf[2] >> 2) & 0x01
	// }

	var TC uint8 = 0
	// if size >= 4 {
	// 	TC = (buf[2] >> 1) & 0x01
	// }

	var RD uint8 = 0
	if size >= 4 {
		RD = buf[2] & 0x01
	}

	var RA uint8 = 0
	// if size >= 4 {
	// 	RA = (buf[3] >> 7) & 0x01
	// }

	var Z uint8 = 0
	// if size >= 4 {
	// 	Z = (buf[3] >> 4) & 0x07
	// }

	var RCODE uint8 = 4
	// if OPCODE == 0 {
	// 	RCODE = 0
	// } else {
	// 	RCODE = 4
	// }
	// if size >= 4 {
	// 	RCODE = buf[3] & 0x0F
	// }

	var QDCOUNT uint16 = 0
	if size >= 6 {
		QDCOUNT = binary.BigEndian.Uint16(buf[4:6])
	}

	var ANCOUNT uint16 = QDCOUNT
	// if size >= 8 {
	// 	ANCOUNT = binary.BigEndian.Uint16(buf[6:8])
	// }

	var NSCOUNT uint16 = 0
	if size >= 10 {
		NSCOUNT = binary.BigEndian.Uint16(buf[8:10])
	}

	var ARCOUNT uint16 = 0
	if size >= 12 {
		ARCOUNT = binary.BigEndian.Uint16(buf[10:12])
	}

	return ID, QR, OPCODE, AA, TC, RD, RA, Z, RCODE, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
}

// function to check if the current byte starts with the compression bits 11
func isCompressed(buf []byte, offset int) bool {
	bufbyte := buf[offset]
	return bufbyte&0xC0 == 0xC0
}

func parseName(buf []byte, offset int) (string, int) {
	var labels []string
	originalOffset := offset
	jumped := false

	for {
		length := int(buf[offset])

		if length == 0 {
			offset++
			break
		}

		if isCompressed(buf, offset) {
			if !jumped {
				originalOffset = offset + 2
			}
			pointer := int(binary.BigEndian.Uint16(buf[offset:offset+2]) & 0x3FFF)
			offset = pointer
			jumped = true
			continue
		} else {
			offset++
			labels = append(labels, string(buf[offset:offset+length]))
			offset += length
		}
	}

	name := strings.Join(labels, ".")
	if jumped {
		return name, originalOffset
	}
	return name, offset
}

func parseQuestion(buf []byte, offset int) (DNSQuestion, int) {
	// Parsing NAME
	NAME, offset := parseName(buf, offset)

	// Parsing TYPE
	var TYPE uint16 = 1
	offset += 2
	// if offset+2 <= size {
	// 	TYPE = binary.BigEndian.Uint16(buf[offset : offset+2])
	// 	offset += 2
	// }

	// Parsing CLASS
	var CLASS uint16 = 1
	offset += 2
	// if offset+2 <= size {
	// 	CLASS = binary.BigEndian.Uint16(buf[offset : offset+2])
	// 	offset += 2
	// }

	return DNSQuestion{
		NAME:  NAME,
		TYPE:  TYPE,
		CLASS: CLASS,
	}, offset
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
		ID, QR, OPCODE, AA, TC, RD, RA, Z, RCODE, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT := ParseHeader(buf, size)

		// Creating respone header
		header := DNSHeader{
			ID:      ID,
			QR:      QR,      // Response
			OPCODE:  OPCODE,  // Standard query
			AA:      AA,      // Not authoritative
			TC:      TC,      // Not truncated
			RD:      RD,      // Recursion not desired
			RA:      RA,      // Recursion not available
			Z:       Z,       // Reserved
			RCODE:   RCODE,   // No error
			QDCOUNT: QDCOUNT, // 1 question
			ANCOUNT: ANCOUNT, // 1 answer
			NSCOUNT: NSCOUNT, // No authority records
			ARCOUNT: ARCOUNT, // No additional records
		}
		headerBytes := header.EncodeHeader()

		// Creating question
		offset := 12
		var questions []DNSQuestion
		for i := 0; i < int(QDCOUNT); i++ {
			var question DNSQuestion
			question, offset = parseQuestion(buf, offset)
			questions = append(questions, question)
		}
		var questionBytes []byte
		for i := 0; i < int(QDCOUNT); i++ {
			questionBytes = append(questionBytes, questions[i].EncodeQuestion()...)
		}

		// Creating answer
		var answers []DNSAnswer
		for i := 0; i < int(QDCOUNT); i++ {
			answers = append(answers, DNSAnswer{
				NAME:   questions[i].NAME,
				TYPE:   questions[i].TYPE,
				CLASS:  questions[i].CLASS,
				TTL:    60,
				LENGTH: 4,
				DATA:   "8.8.8.8",
			})
		}
		var answerBytes []byte
		for i := 0; i < int(QDCOUNT); i++ {
			answerBytes = append(answerBytes, answers[i].EncodeAnswer()...)
		}

		responseBytes := append(headerBytes, questionBytes...)
		responseBytes = append(responseBytes, answerBytes...)

		_, err = udpConn.WriteToUDP(responseBytes, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
