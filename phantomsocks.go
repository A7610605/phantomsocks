package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"runtime"
	"strconv"
	"strings"

	ptcp "./phantomtcp"
)

func handleSocksProxy(client net.Conn) {
	defer client.Close()

	host := ""
	var conf ptcp.Config
	var ok bool

	var conn net.Conn
	{
		var b [1500]byte
		n, err := client.Read(b[:])
		if err != nil || n < 3 {
			log.Println(client.RemoteAddr(), err)
			return
		}

		if b[0] == 0x05 {
			client.Write([]byte{0x05, 0x00})
			n, err = client.Read(b[:4])
			if n != 4 {
				return
			}

			switch b[3] {
			case 0x01: //IPv4
				n, err = client.Read(b[:])
				port := int(binary.BigEndian.Uint16(b[4:6]))
				addr := net.TCPAddr{b[:4], port, ""}
				conf, ok := ptcp.ConfigLookup(addr.IP.String())
				if ok {
					if ptcp.LogLevel > 0 {
						fmt.Println("Socks:", addr.IP.String(), addr.Port)
					}
					client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
					n, err = client.Read(b[:])
					conn, err = ptcp.DialTCP(&addr, b[:n], &conf)
				} else {
					if ptcp.LogLevel > 0 {
						fmt.Println("Socks:", addr.IP.String(), addr.Port)
					}
					conn, err = net.DialTCP("tcp", nil, &addr)
					client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
				}
			case 0x03: //Domain
				n, err = client.Read(b[:])
				port := int(binary.BigEndian.Uint16(b[n-2:]))
				addrLen := b[0]
				host = string(b[1 : addrLen+1])
				conf, ok = ptcp.ConfigLookup(host)
				if ok {
					if ptcp.LogLevel > 0 {
						fmt.Println("Socks:", host, port, conf.Option)
					}

					if conf.Option == 0 {
						conn, err = ptcp.Dial(host, port, nil, nil)
						if err != nil {
							if ptcp.LogLevel > 0 {
								log.Println(err)
							}
							return
						}

						n, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
						if err != nil {
							conn.Close()
							if ptcp.LogLevel > 0 {
								log.Println(err)
							}
							return
						}
					} else {
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

						if port == 80 {
							if conf.Option&ptcp.OPT_HTTPS != 0 {
								ptcp.HttpMove(client, "https", b[:n])
								return
							} else if conf.Option&ptcp.OPT_STRIP != 0 {
								ips := ptcp.NSLookup(host, 1)
								ipaddr := ips[rand.Intn(len(ips))]
								conn, err = ptcp.DialStrip(ipaddr, "")
								if err != nil {
									if ptcp.LogLevel > 0 {
										log.Println(err)
									}
									return
								}
								_, err = conn.Write(b[:n])
							} else if conf.Option&ptcp.OPT_HTTP != 0 {
								ips := ptcp.NSLookup(host, 1)
								addr := ips[rand.Intn(len(ips))] + ":80"
								ptcp.HttpProxy(client, host, addr, b[:n])
								return
							}
						}

						conn, err = ptcp.Dial(host, port, b[:n], &conf)
						if err != nil {
							if ptcp.LogLevel > 0 {
								log.Println(host, err)
							}
							return
						}
					}
				} else {
					addr := net.JoinHostPort(host, strconv.Itoa(port))
					if ptcp.LogLevel > 0 {
						fmt.Println("Socks:", addr)
					}
					conn, err = net.Dial("tcp", addr)
					if err != nil {
						if ptcp.LogLevel > 0 {
							log.Println(err)
						}
						return
					}
					_, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
				}
			case 0x04: //IPv6
				n, err = client.Read(b[:])
				port := int(binary.BigEndian.Uint16(b[16:18]))
				addr := net.TCPAddr{b[:16], port, ""}
				if ptcp.LogLevel > 0 {
					fmt.Println("Socks:", addr.IP.String(), addr.Port)
				}
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
	}

	defer conn.Close()
	go io.Copy(client, conn)
	io.Copy(conn, client)
}

func handleSNIProxy(client net.Conn) {
	defer client.Close()

	var addr net.TCPAddr

	var conn net.Conn
	{
		var b [1500]byte
		n, err := client.Read(b[:])
		if err != nil {
			log.Println(err)
			return
		}
		offset, length := ptcp.GetSNI(b[:n])
		host := string(b[offset : offset+length])
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
	}

	defer conn.Close()
	go io.Copy(client, conn)
	io.Copy(conn, client)
}

func SocksProxy(listenAddr string) {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Panic(err)
	}
	fmt.Println("Socks:", listenAddr)
	for {
		client, err := l.Accept()
		if err != nil {
			log.Panic(err)
		}

		go handleSocksProxy(client)
	}
}

func SNIProxy(listenAddr string) {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Panic(err)
	}
	fmt.Println("SNIProxy:", listenAddr)
	for {
		client, err := l.Accept()
		if err != nil {
			log.Panic(err)
		}

		go handleSNIProxy(client)
	}
}

var configFiles = flag.String("c", "default.conf", "Config")
var hostsFile = flag.String("hosts", "", "Hosts")
var socksListenAddr = flag.String("socks", "", "Socks5")
var sniListenAddr = flag.String("sni", "", "SNIProxy")
var device = flag.String("device", "", "Device")
var logLevel = flag.Int("log", 0, "LogLevel")

func main() {
	runtime.GOMAXPROCS(1)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.Parse()

	if *device == "" {
		ptcp.DevicePrint()
		return
	}

	ptcp.LogLevel = *logLevel
	ptcp.Init()
	for _, filename := range strings.Split(*configFiles, ",") {
		err := ptcp.LoadConfig(filename)
		if err != nil {
			if ptcp.LogLevel > 0 {
				log.Println(err)
			}
			return
		}
	}
	if *hostsFile != "" {
		err := ptcp.LoadHosts(*hostsFile)
		if err != nil {
			if ptcp.LogLevel > 0 {
				log.Println(err)
			}
			return
		}
	}

	if *socksListenAddr != "" {
		go SocksProxy(*socksListenAddr)
	}

	if *sniListenAddr != "" {
		go SNIProxy(*sniListenAddr)
	}

	ptcp.ConnectionMonitor(*device)
}
