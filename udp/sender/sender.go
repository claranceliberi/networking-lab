package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
)

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

func createUDPPseudoHeader(srcIp, dstIP net.IP, udpLength uint16) []byte {
	pseudo := make([]byte, 12)

	// Source IP (4 bytes)
	copy(pseudo[0:4], srcIp.To4())

	// Destination IP (4 bytes)
	copy(pseudo[4:8], srcIp.To4())

	// Zero (1 byte)
	pseudo[8] = 0

	// Protocol = 17 for UDP (1 byte)
	pseudo[9] = 17

	binary.BigEndian.PutUint16(pseudo[10:12], udpLength)

	return pseudo
}

func createUDPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	//UDP header is 8 bytes
	header := make([]byte, 8)

	// Source Port (2 bytes)
	binary.BigEndian.PutUint16(header[0:2], srcPort)

	// Destination Port (2 bytes)
	binary.BigEndian.PutUint16(header[2:4], dstPort)

	// Length = header(8) + payload (2 bytes)
	length := uint16(8 + len(payload))
	binary.BigEndian.PutUint16(header[4:6], length)

	// Checksum - ignore it for now
	binary.BigEndian.PutUint16(header[6:8], 0)

	// Create pseudo-header for checksum calculation
	pseudoHeader := createUDPPseudoHeader(srcIP, dstIP, length)

	// Combine pseudo-header + UDP header + payload for checksum
	checksumData := append(pseudoHeader, header...)
	checksumData = append(checksumData, payload...)

	// Calculate checksum
	checksum := calculateChecksum(checksumData)

	// Set the checksum in header
	binary.BigEndian.PutUint16(header[6:8], checksum)

	// combine header + payload
	packet := append(header, payload...)

	return packet

}

func sendRawUDP(dstIp string, packet []byte) error {
	// Create raw ip socket
	conn, err := net.Dial("ip4:udp", dstIp)

	if err != nil {
		return err
	}

	_, err = conn.Write(packet)

	return err
}

func main() {

	if len(os.Args) < 3 {
		fmt.Printf("Usage: %s <destination_ip> <message> \n", os.Args[0])
		fmt.Printf("Example: %s 127.0.0.1 \"hello world \" \n", os.Args[0])
		os.Exit(1)
	}

	dstIP := os.Args[1]
	message := os.Args[2]

	// Parse IP addresses
	srcIPAddr := net.ParseIP("127.0.0.1") // Assuming localhost
	dstIPAddr := net.ParseIP(dstIP)

	packet := createUDPPacket(srcIPAddr, dstIPAddr, 1234, 9999, []byte(message))

	fmt.Printf("Created UDP packet (%d bytes):\n", len(packet))
	fmt.Printf("Raw bytes: %x\n", packet)

	// Parse and display what we created
	fmt.Printf("\nPacket breakdown:\n")
	fmt.Printf("Source Port: %d\n", binary.BigEndian.Uint16(packet[0:2]))
	fmt.Printf("Dest Port: %d\n", binary.BigEndian.Uint16(packet[2:4]))
	fmt.Printf("Length: %d\n", binary.BigEndian.Uint16(packet[4:6]))
	fmt.Printf("Checksum: 0x%04x\n", binary.BigEndian.Uint16(packet[6:8]))
	fmt.Printf("Payload: %s\n", string(packet[8:]))

	// Send the packet
	fmt.Printf("\nSending packet to %s...\n", dstIP)
	err := sendRawUDP(dstIP, packet)
	if err != nil {
		log.Fatal("Failed to send packet:", err)
	}

	fmt.Println("Packet sent successfully!")

}
