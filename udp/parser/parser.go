package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
)

type UDPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}

// Calculate Internet checksum (RFC 1071)
func calculateChecksum(data []byte) uint16 {
	var sum uint32

	// Sum all 16-bit words
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}

	// Add odd byte if exists
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	// Add carry bits
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// Return one's complement
	return uint16(^sum)
}

func createUDPPseudoHeader(srcIP, dstIP net.IP, udpLength uint16) []byte {
	pseudo := make([]byte, 12)

	// Source IP (4 bytes)
	copy(pseudo[0:4], srcIP.To4())

	// Destination IP (4 bytes)
	copy(pseudo[4:8], dstIP.To4())

	// Zero (1 byte)
	pseudo[8] = 0

	// Protocol = 17 for UDP (1 byte)
	pseudo[9] = 17

	// UDP Length (2 bytes)
	binary.BigEndian.PutUint16(pseudo[10:12], udpLength)

	return pseudo
}

func validateUDPChecksum(srcIP, dstIP net.IP, udpData []byte) bool {
	if len(udpData) < 8 {
		return false
	}

	// Extract header info
	length := binary.BigEndian.Uint16(udpData[4:6])
	originalChecksum := binary.BigEndian.Uint16(udpData[6:8])

	// If checksum is 0, validation is disabled (allowed in UDP)
	if originalChecksum == 0 {
		return true
	}

	// Create copy and zero out checksum field
	udpCopy := make([]byte, len(udpData))
	copy(udpCopy, udpData)
	binary.BigEndian.PutUint16(udpCopy[6:8], 0)

	// Create pseudo-header
	pseudoHeader := createUDPPseudoHeader(srcIP, dstIP, length)

	// Combine for checksum calculation
	checksumData := append(pseudoHeader, udpCopy...)

	// Calculate checksum
	calculatedChecksum := calculateChecksum(checksumData)

	return calculatedChecksum == originalChecksum
}

func parseUDP(srcIP, dstIP net.IP, data []byte) (*UDPHeader, []byte, bool, error) {

	if len(data) < 8 {
		return nil, nil, false, fmt.Errorf("Package to short for UDP header")
	}

	header := &UDPHeader{
		SrcPort:  binary.BigEndian.Uint16(data[0:2]),
		DstPort:  binary.BigEndian.Uint16(data[2:4]),
		Length:   binary.BigEndian.Uint16(data[4:6]),
		Checksum: binary.BigEndian.Uint16(data[6:8]),
	}

	payload := data[8:]
	checksumValid := validateUDPChecksum(srcIP, dstIP, data)

	return header, payload, checksumValid, nil
}

func main() {

	conn, err := net.ListenPacket("ip4:udp", "0.0.0.0")

	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()

	fmt.Println("Listening for UDP packets...")
	buf := make([]byte, 1500)
	for {
		n, addr, err := conn.ReadFrom(buf)

		if err != nil {
			log.Fatal(err)
		}

		// Parse address to get IP
		srcIP := net.ParseIP(addr.String())
		dstIP := net.ParseIP("127.0.0.1") // Assuming localhost for now

		fmt.Printf("\n=== Packet from %v ===\n", addr)
		fmt.Printf("Raw bytes (%d): %x\n", n, buf[:n])

		header, payload, checksumValid, err := parseUDP(srcIP, dstIP, buf[:n])

		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("  Source Port: %d\n", header.SrcPort)
		fmt.Printf("  Dest Port: %d\n", header.DstPort)
		fmt.Printf("  Length: %d bytes\n", header.Length)
		fmt.Printf("  Checksum: 0x%04x\n", header.Checksum)

		if header.Checksum == 0 {
			fmt.Printf(" (disabled)\n")
		} else if checksumValid {
			fmt.Printf(" ✓ (valid)\n")
		} else {
			fmt.Printf(" ✗ (INVALID)\n")
		}

		fmt.Printf("Payload (%d bytes): %s\n", len(payload), string(payload))
	}
}
