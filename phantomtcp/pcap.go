package phantomtcp

import (
	"fmt"
	"log"

	"sync"
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

var mutex sync.RWMutex

func ConnectionMonitor(deviceName string) {
	snapLen := int32(65535)

	filter := "tcp[13]=18 and (tcp src port 443)"

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
	packetSource.NoCopy = true
	//for packet := range packetSource.Packets() {
	for {
		packet, err := packetSource.NextPacket()
		if err != nil {
			logPrintln(1, err)
			continue
		}
		if packet.NetworkLayer() == nil ||
			packet.TransportLayer() == nil ||
			packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
			fmt.Println("unexpected packet")
			continue
		}

		eth := packet.LinkLayer().(*layers.Ethernet)
		ip := packet.NetworkLayer()
		switch ip := ip.(type) {
		case *layers.IPv4:
			tcp := packet.TransportLayer().(*layers.TCP)

			dstPort := tcp.DstPort
			portChan := PortInfo4[dstPort]
			if portChan != nil {
				mutex.Lock()
				if portChan != nil {
					portChan <- &ConnectionInfo4{*eth, *ip, *tcp}
				}
				mutex.Unlock()
			}
		case *layers.IPv6:
			tcp := packet.TransportLayer().(*layers.TCP)

			dstPort := tcp.DstPort
			portChan := PortInfo6[dstPort]
			if portChan != nil {
				mutex.Lock()
				if portChan != nil {
					portChan <- &ConnectionInfo6{*eth, *ip, *tcp}
				}
				mutex.Unlock()
			}
		}
	}
}

func CreatePortChan(port int) chan *ConnectionInfo4 {
	portChan := make(chan *ConnectionInfo4)
	PortInfo4[port] = portChan
	return portChan
}

func DeletePortChan(port int) {
	portChan := PortInfo4[port]
	PortInfo4[port] = nil

	mutex.RLock()
	close(portChan)
	mutex.RUnlock()
}

func GetConnInfo(portChan chan *ConnectionInfo4) *ConnectionInfo4 {
	select {
	case connInfo, ok := <-portChan:
		if ok {
			return connInfo
		}
	case <-time.After(time.Millisecond * 100):
		return nil
	}

	return nil
}

func SendFakePacket(connInfo *ConnectionInfo4, payload []byte, config *Config, count int) error {
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       connInfo.Eth.DstMAC,
		DstMAC:       connInfo.Eth.SrcMAC,
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
		SrcIP:    connInfo.IP.DstIP,
		DstIP:    connInfo.IP.SrcIP,
	}
	tcpLayer := &layers.TCP{
		SrcPort:    connInfo.TCP.DstPort,
		DstPort:    connInfo.TCP.SrcPort,
		Seq:        connInfo.TCP.Ack,
		Ack:        connInfo.TCP.Seq + 1,
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
