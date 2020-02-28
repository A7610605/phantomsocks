package phantomtcp

import (
	"fmt"
	"log"

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

type ConnectionInfo4 struct {
	Eth layers.Ethernet
	IP  layers.IPv4
	TCP layers.TCP
}

type ConnectionInfo6 struct {
	Eth layers.Ethernet
	IP  layers.IPv6
	TCP layers.TCP
}

var ConnPayload4 [65536]*[]byte
var ConnPayload6 [65536]*[]byte
var ConnInfo4 [65536]*ConnectionInfo4
var ConnInfo6 [65536]*ConnectionInfo6

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

		eth := packet.LinkLayer().(*layers.Ethernet)
		ip := packet.NetworkLayer()
		switch ip := ip.(type) {
		case *layers.IPv4:
			tcp := packet.TransportLayer().(*layers.TCP)

			srcPort := tcp.SrcPort
			if ConnPayload4[srcPort] != nil {
				ConnInfo4[srcPort] = &ConnectionInfo4{*eth, *ip, *tcp}
			}
		case *layers.IPv6:
			tcp := packet.TransportLayer().(*layers.TCP)

			srcPort := tcp.SrcPort
			if ConnPayload6[srcPort] != nil {
				ConnInfo6[srcPort] = &ConnectionInfo6{*eth, *ip, *tcp}
			}
		}
	}
}

func SendFakePacket(connInfo *ConnectionInfo4, payload []byte, config *Config, count int) error {
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       connInfo.Eth.SrcMAC,
		DstMAC:       connInfo.Eth.DstMAC,
		EthernetType: connInfo.Eth.EthernetType,
		Length:       connInfo.Eth.Length,
	}
	ipLayer := &layers.IPv4{
		Version:  connInfo.IP.Version,
		IHL:      connInfo.IP.IHL,
		TOS:      connInfo.IP.TOS,
		Length:   0,
		TTL:      config.TTL,
		Protocol: connInfo.IP.Protocol,
		SrcIP:    connInfo.IP.SrcIP,
		DstIP:    connInfo.IP.DstIP,
	}
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

	// And create the packet with the layers
	buffer := gopacket.NewSerializeBuffer()
	var options gopacket.SerializeOptions
	options.FixLengths = true
	options.ComputeChecksums = true

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	gopacket.SerializeLayers(
		buffer,
		options,
		ethernetLayer,
		ipLayer,
		tcpLayer,
		gopacket.Payload(payload),
	)

	outgoingPacket := buffer.Bytes()

	for i := 0; i < count; i++ {
		err := pcapHandle.WritePacketData(outgoingPacket)
		if err != nil {
			return err
		}
	}
	return nil
}
