package magicpacket

import (
	"fmt"
	"net"
)

// MagicPacket represents a wake-on-LAN packet
type MagicPacket struct {
	// The MAC address of the machine to wake up
	MacAddress net.HardwareAddr
}

// NewMagicPacket creates a new MagicPacket for the given MAC address
func NewMagicPacket(macAddress net.HardwareAddr) *MagicPacket {
	return &MagicPacket{MacAddress: macAddress}
}

func ipForInterface(ifname string) (*net.UDPAddr, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipnet.IP.IsMulticast() {
			continue
		}
		if ipnet.IP.IsLoopback() {
			continue
		}

		return &net.UDPAddr{IP: ipnet.IP}, nil
	}
	return nil, nil
}

// Broadcast sends the magic packet to the broadcast address
func (p *MagicPacket) Broadcast(ifname string) error {
	// Build the actual packet
	packet := make([]byte, 102)
	// Set the synchronization stream (first 6 bytes are 0xFF)
	for i := range 6 {
		packet[i] = 0xFF
	}
	// Copy the MAC address 16 times into the packet
	for i := 1; i <= 16; i++ {
		copy(packet[i*6:], p.MacAddress)
	}

	// Broadcast the packet
	// TODO: Broadcast to more common ports and addresses?
	addr := &net.UDPAddr{
		IP:   net.IPv4bcast,
		Port: 9,
	}
	var (
		srcAddr *net.UDPAddr
		err     error
	)
	if ifname != "" {
		srcAddr, err = ipForInterface(ifname)
		if err != nil {
			return fmt.Errorf("unable to find ip for interface", err)
		}
	}
	conn, err := net.DialUDP("udp", srcAddr, addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write(packet)
	return err
}
