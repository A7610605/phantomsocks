package phantomtcp

import (
	"fmt"
	"log"
	"time"

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

var PortInfo4 [65536]chan *ConnectionInfo4
var PortInfo6 [65536]chan *ConnectionInfo6

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
			portChan := PortInfo4[srcPort]
			if portChan != nil {
				portChan <- &ConnectionInfo4{*eth, *ip, *tcp}
				PortInfo4[srcPort] = nil
			}
		case *layers.IPv6:
			tcp := packet.TransportLayer().(*layers.TCP)

			srcPort := tcp.SrcPort
			portChan := PortInfo6[srcPort]
			if portChan != nil {
				portChan <- &ConnectionInfo6{*eth, *ip, *tcp}
				PortInfo6[srcPort] = nil
			}
		}
	}
}

func CreatePortChan(port int) chan *ConnectionInfo4 {
	portChan := make(chan *ConnectionInfo4)
	PortInfo4[port] = portChan
	return portChan
}

func GetConnInfo(portChan chan *ConnectionInfo4, port int) *ConnectionInfo4 {
	select {
	case connInfo, ok := <-portChan:
		if ok {
			close(portChan)
			return connInfo
		}
	case <-time.After(time.Second * 5):
	}

	PortInfo4[port] = nil
	close(portChan)
	return nil
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
