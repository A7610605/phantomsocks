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
				addr := net.TCPAddr{[]byte{b[0], b[1], b[2], b[3]}, port, ""}
				conf, ok := ptcp.ConfigLookup(addr.IP.String())
				if ok {
					if ptcp.LogLevel > 0 {
						fmt.Println("Socks:", addr.IP.String(), addr.Port, conf.Option)
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

						if b[0] != 0x16 {
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
							} else {
								conn, err = ptcp.HTTP(client, host, 80, b[:n], &conf)
								if err != nil {
									if ptcp.LogLevel > 0 {
										log.Println(err)
									}
									return
								}
								io.Copy(client, conn)
								return
							}
						} else {
							conn, err = ptcp.Dial(host, port, b[:n], &conf)
							if err != nil {
								if ptcp.LogLevel > 0 {
									log.Println(host, err)
								}
								return
							}
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

	var conn net.Conn
	{
		var b [1500]byte
		n, err := client.Read(b[:])
		if err != nil {
			log.Println(err)
			return
		}

		var host string
		var port int
		if b[0] == 0x16 {
			offset, length := ptcp.GetSNI(b[:n])
			if length == 0 {
				return
			}
			host = string(b[offset : offset+length])
			port = 443
		} else {
			offset, length := ptcp.GetHost(b[:n])
			if length == 0 {
				return
			}
			host = string(b[offset : offset+length])
			portstart := strings.Index(host, ":")
			if portstart == -1 {
				port = 80
			} else {
				port, err = strconv.Atoi(host[portstart+1:])
				if err != nil {
					return
				}
				host = host[:portstart]
			}
		}

		conf, ok := ptcp.ConfigLookup(host)

		if ok {
			if ptcp.LogLevel > 0 {
				fmt.Println("SNI:", host, port, conf.Option)
			}

			if b[0] != 0x16 {
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
				} else {
					conn, err = ptcp.HTTP(client, host, port, b[:n], &conf)
					if err != nil {
						if ptcp.LogLevel > 0 {
							log.Println(err)
						}
						return
					}
					io.Copy(client, conn)
					return
				}
			} else {
				conn, err = ptcp.Dial(host, port, b[:n], &conf)
				if err != nil {
					if ptcp.LogLevel > 0 {
						log.Println(host, err)
					}
					return
				}
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
			_, err = conn.Write(b[:n])
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

func PACServer(listenAddr string, proxyAddr string) {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Panic(err)
	}
	pac := ptcp.GetPAC(proxyAddr)
	response := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length:%d\r\n\r\n%s", len(pac), pac))
	fmt.Println("PACServer:", listenAddr)
	for {
		client, err := l.Accept()
		if err != nil {
			log.Panic(err)
		}

		go func() {
			defer client.Close()
			var b [1024]byte
			_, err := client.Read(b[:])
			if err != nil {
				return
			}
			_, err = client.Write(response)
			if err != nil {
				return
			}
		}()
	}
}

var configFiles = flag.String("c", "default.conf", "Config")
var hostsFile = flag.String("hosts", "", "Hosts")
var socksListenAddr = flag.String("socks", "", "Socks5")
var pacListenAddr = flag.String("pac", "", "PACServer")
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
		if *pacListenAddr != "" {
			go PACServer(*pacListenAddr, *socksListenAddr)
		}
	}

	if *sniListenAddr != "" {
		go SNIProxy(*sniListenAddr)
	}

	ptcp.ConnectionMonitor(*device)
}
