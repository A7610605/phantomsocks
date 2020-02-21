package main

import (
	"encoding/binary"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strconv"

	ptcp "./phantomtcp"
)

func handleSocksProxy(client net.Conn) {
	defer client.Close()

	host := ""
	var addr net.TCPAddr
	var conf ptcp.Config
	var ok bool

	var conn net.Conn
	var err error
	var b [1500]byte
	n, err := client.Read(b[:])
	if err != nil || n < 3{
		log.Println(err)
		return
	}

	if b[0] == 0x05 {
		client.Write([]byte{0x05, 0x00})
		n, err = client.Read(b[:])
		port := int(binary.BigEndian.Uint16(b[n-2:]))

		switch b[3] {
		case 0x01: //IPv4
			addr = net.TCPAddr{b[4:8], port, ""}
			conf, ok := ptcp.ConfigLookup(addr.IP.String())
			if ok {
				client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
				n, err = client.Read(b[:])
				conn, err = ptcp.DialTCP(&addr, b[:n], &conf)
			} else {
				conn, err = net.DialTCP("tcp", nil, &addr)
				client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			}
		case 0x03: //Domain
			addrLen := b[4]
			host = string(b[5 : 5+addrLen])
			conf, ok = ptcp.ConfigLookup(host)
			if ok {
				ips := ptcp.NSLookup(host, 1)
				if ptcp.LogLevel > 0 {
					log.Println(host, port, ips)
				}

				ip := net.ParseIP(ips[rand.Intn(len(ips))])
				if ip == nil {
					return
				}
				ip4 := ip.To4()
				if ip4 != nil {
					addr = net.TCPAddr{ip4, port, ""}
				} else {
					addr = net.TCPAddr{ip, port, ""}
				}

				n, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
				if err != nil {
					if ptcp.LogLevel > 0 {
						log.Println(err)
					}
					return
				}


				n, err = client.Read(b[:])
				if err != nil {
					if ptcp.LogLevel > 0 {
						log.Println(err)
					}
					return
				}

				conn, err = ptcp.DialTCP(&addr, b[:n], &conf)
				if err != nil {
					if ptcp.LogLevel > 0 {
						log.Println(host, err)
					}
					return
				}
			} else {
				host = net.JoinHostPort(host, strconv.Itoa(port))
				if ptcp.LogLevel > 0 {
					log.Println(host)
				}
				conn, err = net.Dial("tcp", host)
				if err != nil {
					if ptcp.LogLevel > 0 {
						log.Println(err)
					}
					return
				}
				_, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			}
		case 0x04: //IPv6
			addr = net.TCPAddr{b[4:20], port, ""}
			conn, err = net.DialTCP("tcp", nil, &addr)
			client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		default:
			if ptcp.LogLevel > 0 {
				log.Println("Not Supported")
			}
			return
		}
	} else {
		return
	}

	if err != nil {
		if ptcp.LogLevel > 0 {
			log.Println(err)
		}
		return
	}
	defer conn.Close()
	go io.Copy(client, conn)
	io.Copy(conn, client)
}

func handleSNIProxy(client net.Conn) {
	defer client.Close()

	var addr net.TCPAddr

	var conn net.Conn
	var err error
	var b [1500]byte
	n, err := client.Read(b[:])
	if err != nil {
		log.Println(err)
		return
	}
	offset, length := ptcp.GetSNI(b[:n])
	host := string(b[offset:offset+length])
	conf, ok := ptcp.ConfigLookup(host)
	if ok {
		ips := ptcp.NSLookup(host, 1)
		if ptcp.LogLevel > 0 {
			log.Println(host, ips)
		}

		ip := net.ParseIP(ips[rand.Intn(len(ips))])
		if ip == nil {
			return
		}
		ip4 := ip.To4()
		if ip4 != nil {
			addr = net.TCPAddr{ip4, 443, ""}
		} else {
			addr = net.TCPAddr{ip, 443, ""}
		}

		conn, err = ptcp.DialTCP(&addr, b[:n], &conf)
		if err != nil {
			if ptcp.LogLevel > 0 {
				log.Println(host, err)
			}
			return
		}
	} else {
		host = net.JoinHostPort(host, "443")
		if ptcp.LogLevel > 0 {
			log.Println(host)
		}
		return
		conn, err = net.Dial("tcp", host)
		if err != nil {
			if ptcp.LogLevel > 0 {
				log.Println(err)
			}
			return
		}
	}

	defer conn.Close()
	go io.Copy(client, conn)
	io.Copy(conn, client)
}

func main() {
	runtime.GOMAXPROCS(1)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	sniproxy := false
	for _, args := range os.Args {
		if args == "sniproxy" {
			sniproxy = true
		}
	}

	err := ptcp.LoadConfig()
	if err != nil {
		if ptcp.LogLevel > 0 {
			log.Println(err)
		}
		return
	}
	go ptcp.ConnectionMonitor(ptcp.Device)

	if sniproxy {
		l, err := net.Listen("tcp", ":443")
		if err != nil {
			log.Panic(err)
		}
		for {
			client, err := l.Accept()
			if err != nil {
				log.Panic(err)
			}

			go handleSNIProxy(client)
		}
	} else {
		l, err := net.Listen("tcp", ":1080")
		if err != nil {
			log.Panic(err)
		}
		for {
			client, err := l.Accept()
			if err != nil {
				log.Panic(err)
			}

			go handleSocksProxy(client)
		}
	}
}
