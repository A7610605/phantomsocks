package main

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"strconv"

	ptcp "./phantomtcp"
)

func GetHost(client net.Conn) string {
	var b [512]byte
	n, err := client.Read(b[:])
	if err != nil {
		log.Println(err)
		return ""
	}

	host := ""

	if b[0] == 0x05 {
		client.Write([]byte{0x05, 0x00})
		n, err = client.Read(b[:])
		port := int(binary.BigEndian.Uint16(b[n-2:]))

		switch b[3] {
		case 0x01: //IPv4
			addr := net.TCPAddr{b[4:8], port, ""}
			host = addr.String()
		case 0x03: //Domain
			addrLen := b[4]
			host = net.JoinHostPort(string(b[5:5+addrLen]), strconv.Itoa(port))
		case 0x04: //IPv6
			addr := net.TCPAddr{b[4:20], port, ""}
			host = addr.String()
		default:
			return ""
		}

		client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	}

	return host
}

func handleProxy(client net.Conn) {
	defer client.Close()

	host := GetHost(client)
	_, ok := ptcp.DomainLookup(host)
	if ok {
	} else {
		server, err := net.Dial("tcp", host)
		if err != nil {
			log.Println(err)
			return
		}
		defer server.Close()

		go io.Copy(server, client)
		io.Copy(client, server)
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	err := ptcp.LoadConfig()
	if err != nil {
		if ptcp.LogLevel > 0 {
			log.Println(err)
		}
		return
	}

	l, err := net.Listen("tcp", ":1080")
	if err != nil {
		log.Panic(err)
	}

	for {
		client, err := l.Accept()
		if err != nil {
			log.Panic(err)
		}

		go handleProxy(client)
	}
}
