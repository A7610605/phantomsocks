package phantomtcp

import (
	"fmt"
	"log"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func DevicePrint() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Devices found:")
	for _, device := range devices {
		fmt.Println("\nName: ", device.Name)
		fmt.Println("Description: ", device.Description)
		fmt.Println("Devices addresses: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}
	}
}

type ConnectionInfo struct {
	Link gopacket.LinkLayer
	IP   gopacket.NetworkLayer
	TCP  layers.TCP
}

var ConnSyn4 [65536]bool
var ConnSyn6 [65536]bool
var ConnInfo4 [65536]*ConnectionInfo
var ConnInfo6 [65536]*ConnectionInfo

var pcapHandle *pcap.Handle

func ConnectionMonitor(deviceName string) {
	snapLen := int32(65535)

	filter := "tcp[13]=2 and (tcp dst port 443)"

	fmt.Printf("Device: %v\n", deviceName)

	var err error
	pcapHandle, err = pcap.OpenLive(deviceName, snapLen, true, pcap.BlockForever)
	if err != nil {
		fmt.Printf("pcap open live failed: %v", err)
		return
	}

	if err = pcapHandle.SetBPFFilter(filter); err != nil {
		fmt.Printf("set bpf filter failed: %v", err)
		return
	}
	defer pcapHandle.Close()

	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())
	packetSource.NoCopy = false
	for {
		packet, err := packetSource.NextPacket()
		if err != nil {
			logPrintln(1, err)
			continue
		}

		link := packet.LinkLayer()
		ip := packet.NetworkLayer()
		switch ip := ip.(type) {
		case *layers.IPv4:
			tcp := packet.TransportLayer().(*layers.TCP)

			srcPort := tcp.SrcPort
			if ConnSyn4[srcPort] {
				ConnInfo4[srcPort] = &ConnectionInfo{link, ip, *tcp}
			}
		case *layers.IPv6:
			tcp := packet.TransportLayer().(*layers.TCP)

			srcPort := tcp.SrcPort
			if ConnSyn6[srcPort] {
				ConnInfo6[srcPort] = &ConnectionInfo{link, ip, *tcp}
			}
		}
	}
}

func SendFakePacket(connInfo *ConnectionInfo, payload []byte, config *Config, count int) error {
	linkLayer := connInfo.Link
	ipLayer := connInfo.IP

	tcpLayer := &layers.TCP{
		SrcPort:    connInfo.TCP.SrcPort,
		DstPort:    connInfo.TCP.DstPort,
		Seq:        connInfo.TCP.Seq + 1,
		Ack:        connInfo.TCP.Ack,
		DataOffset: 5,
		ACK:        true,
		PSH:        true,
		Window:     connInfo.TCP.Window,
	}

	if config.Option&OPT_WMD5 != 0 {
		tcpLayer.Options = []layers.TCPOption{
			layers.TCPOption{19, 18, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		}
	}

	if config.Option&OPT_WACK != 0 {
		tcpLayer.Ack += uint32(tcpLayer.Window)
	}

	// And create the packet with the layers
	buffer := gopacket.NewSerializeBuffer()
	var options gopacket.SerializeOptions
	options.FixLengths = true
	options.ComputeChecksums = true

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	switch link := linkLayer.(type) {
	case *layers.Ethernet:
		switch ip := ipLayer.(type) {
		case *layers.IPv4:
			if config.Option&OPT_TTL != 0 {
				ip.TTL = config.TTL
			}
			gopacket.SerializeLayers(buffer, options,
				link, ip, tcpLayer, gopacket.Payload(payload),
			)
		case *layers.IPv6:
			if config.Option&OPT_TTL != 0 {
				ip.HopLimit = config.TTL
			}
			gopacket.SerializeLayers(buffer, options,
				link, ip, tcpLayer, gopacket.Payload(payload),
			)
		}
		outgoingPacket := buffer.Bytes()

		for i := 0; i < count; i++ {
			err := pcapHandle.WritePacketData(outgoingPacket)
			if err != nil {
				return err
			}
		}
	case *layers.LinuxSLL:
		var sa syscall.Sockaddr
		var domain int

		switch ip := ipLayer.(type) {
		case *layers.IPv4:
			if config.Option&OPT_TTL != 0 {
				ip.TTL = config.TTL
			}
			gopacket.SerializeLayers(buffer, options,
				ip, tcpLayer, gopacket.Payload(payload),
			)
			var addr [4]byte
			copy(addr[:4], ip.DstIP.To4()[:4])
			sa = &syscall.SockaddrInet4{Addr: addr, Port: 0}
			domain = syscall.AF_INET
		case *layers.IPv6:
			if config.Option&OPT_TTL != 0 {
				ip.HopLimit = config.TTL
			}
			gopacket.SerializeLayers(buffer, options,
				ip, tcpLayer, gopacket.Payload(payload),
			)
			var addr [16]byte
			copy(addr[:16], ip.DstIP[:16])
			sa = &syscall.SockaddrInet6{Addr: addr, Port: 0}
			domain = syscall.AF_INET6
		}

		raw_fd, err := syscall.Socket(domain, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			syscall.Close(raw_fd)
			return err
		}
		outgoingPacket := buffer.Bytes()

		for i := 0; i < count; i++ {
			err = syscall.Sendto(raw_fd, outgoingPacket, 0, sa)
			if err != nil {
				syscall.Close(raw_fd)
				return err
			}
		}
		syscall.Close(raw_fd)
	}

	return nil
}
