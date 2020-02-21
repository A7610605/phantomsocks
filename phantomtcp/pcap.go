package phantomtcp

import (
	"errors"
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

var mutex sync.Mutex

func ConnectionMonitor(deviceName string) {
	snapLen := int32(65535)

	filter := "tcp[13]=18 and (tcp src port 443)"

	fmt.Printf("device:%v, snapLen:%v", deviceName, snapLen)

	var err error
	pcapHandle, err = pcap.OpenLive(deviceName, snapLen, true, pcap.BlockForever)
	if err != nil {
		fmt.Printf("pcap open live failed: %v", err)
		DevicePrint()
		return
	}

	if err = pcapHandle.SetBPFFilter(filter); err != nil {
		fmt.Printf("set bpf filter failed: %v", err)
		return
	}
	defer pcapHandle.Close()

	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())
	packetSource.NoCopy = true
	for packet := range packetSource.Packets() {
		if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
			fmt.Println("unexpected packet")
			continue
		}

		eth := packet.LinkLayer().(*layers.Ethernet)
		ipv4 := packet.NetworkLayer().(*layers.IPv4)
		tcp := packet.TransportLayer().(*layers.TCP)

		dstPort := tcp.DstPort
		portChan := PortInfo4[dstPort]
		mutex.Lock()
		if portChan != nil {
			portChan <- &ConnectionInfo4{*eth, *ipv4, *tcp}
		}
		mutex.Unlock()
	}
}

func SendFakePacket(port int, payload []byte, config *Config) error {
	if config.Option == 0 {
		return nil
	}

	portChan := make(chan *ConnectionInfo4)
	PortInfo4[port] = portChan

	var connInfo *ConnectionInfo4
	var ok bool

	select {
	case connInfo, ok = <-portChan:
	case <-time.After(time.Second):
		PortInfo4[port] = nil
		close(portChan)
		return errors.New("Timeout")
	}

	mutex.Lock()
	PortInfo4[port] = nil
	mutex.Unlock()
	close(portChan)

	if ok {
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
		err := pcapHandle.WritePacketData(outgoingPacket)
		if err != nil {
			return err
		}

		err = pcapHandle.WritePacketData(outgoingPacket)
		return err
	} else {
		return errors.New("Connection does not exist")
	}
	return nil
}
