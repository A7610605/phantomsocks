package phantomtcp

import (
	"encoding/binary"
	"io"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"
)

func SocksProxy(client net.Conn) {
	defer client.Close()

	host := ""
	var conf Config
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
				conf, ok := ConfigLookup(addr.IP.String())
				if ok {
					logPrintln(1, "Socks:", addr.IP.String(), addr.Port, conf)
					client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
					n, err = client.Read(b[:])
					addresses := []string{addr.IP.String()}
					if conf.Option&OPT_NAT64 != 0 {
						ans, ok := DNSCache[addresses[0]]
						if ok {
							addresses = ans.Addresses
						}
					}
					conn, err = Dial(addresses, port, b[:n], &conf)
				} else {
					logPrintln(1, "Socks:", addr.IP.String(), addr.Port)

					conn, err = net.DialTCP("tcp", nil, &addr)
					client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
				}
			case 0x03: //Domain
				n, err = client.Read(b[:])
				port := int(binary.BigEndian.Uint16(b[n-2:]))
				addrLen := b[0]
				host = string(b[1 : addrLen+1])
				conf, ok = ConfigLookup(host)
				if ok {
					logPrintln(1, "Socks:", host, port, conf)

					var ips []string
					if conf.Option&OPT_IPV6 != 0 {
						_, ips = NSLookup(host, 28)
					} else {
						_, ips = NSLookup(host, 1)
					}

					if len(ips) == 0 {
						logPrintln(1, host, "no such host")
						return
					}

					if conf.Option == 0 {
						conn, err = Dial(ips, port, nil, nil)
						if err != nil {
							logPrintln(1, err)
							return
						}

						n, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
						if err != nil {
							conn.Close()
							logPrintln(1, err)
							return
						}
					} else {
						n, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
						if err != nil {
							logPrintln(1, err)
							return
						}

						n, err = client.Read(b[:])
						if err != nil {
							logPrintln(1, err)
							return
						}

						if b[0] != 0x16 {
							if conf.Option&OPT_HTTPS != 0 {
								HttpMove(client, "https", b[:n])
								return
							} else if conf.Option&OPT_STRIP != 0 {
								rand.Seed(time.Now().UnixNano())
								ipaddr := ips[rand.Intn(len(ips))]
								conn, err = DialStrip(ipaddr, "")
								if err != nil {
									logPrintln(1, err)
									return
								}
								_, err = conn.Write(b[:n])
							} else {
								conn, err = HTTP(client, ips, 80, b[:n], &conf)
								if err != nil {
									logPrintln(1, err)
									return
								}
								io.Copy(client, conn)
								return
							}
						} else {
							conn, err = Dial(ips, port, b[:n], &conf)
							if err != nil {
								logPrintln(1, host, err)
								return
							}
						}
					}
				} else {
					addr := net.JoinHostPort(host, strconv.Itoa(port))
					logPrintln(1, "Socks:", addr)
					conn, err = net.Dial("tcp", addr)
					if err != nil {
						logPrintln(1, err)
						return
					}
					_, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
				}
			case 0x04: //IPv6
				n, err = client.Read(b[:])
				port := int(binary.BigEndian.Uint16(b[16:18]))
				addr := net.TCPAddr{b[:16], port, ""}
				logPrintln(1, "Socks:", addr.IP.String(), addr.Port)
				conn, err = net.DialTCP("tcp", nil, &addr)
				client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			default:
				logPrintln(1, "not supported")
				return
			}
		} else {
			return
		}

		if err != nil {
			logPrintln(1, err)
			return
		}
	}

	defer conn.Close()
	go io.Copy(client, conn)
	io.Copy(conn, client)
}

func SNIProxy(client net.Conn) {
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
			offset, length := GetSNI(b[:n])
			if length == 0 {
				return
			}
			host = string(b[offset : offset+length])
			port = 443
		} else {
			offset, length := GetHost(b[:n])
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
			if net.ParseIP(host) != nil {
				return
			}
		}

		conf, ok := ConfigLookup(host)

		if ok {
			logPrintln(1, "SNI:", host, port, conf)

			var ips []string
			if conf.Option&OPT_IPV6 != 0 {
				_, ips = NSLookup(host, 28)
			} else {
				_, ips = NSLookup(host, 1)
			}
			if len(ips) == 0 {
				logPrintln(1, host, "no such host")
				return
			}

			if b[0] == 0x16 {
				conn, err = Dial(ips, port, b[:n], &conf)
				if err != nil {
					logPrintln(1, host, err)
					return
				}
			} else {
				if conf.Option&OPT_HTTPS != 0 {
					HttpMove(client, "https", b[:n])
					return
				} else if conf.Option&OPT_STRIP != 0 {
					ipaddr := ips[rand.Intn(len(ips))]
					conn, err = DialStrip(ipaddr, "")
					if err != nil {
						logPrintln(1, err)
						return
					}
					_, err = conn.Write(b[:n])
				} else {
					conn, err = HTTP(client, ips, port, b[:n], &conf)
					if err != nil {
						logPrintln(1, err)
						return
					}
					io.Copy(client, conn)
					return
				}
			}
		} else {
			host = net.JoinHostPort(host, strconv.Itoa(port))
			logPrintln(1, host)

			conn, err = net.Dial("tcp", host)
			if err != nil {
				logPrintln(1, err)
				return
			}
			_, err = conn.Write(b[:n])
			if err != nil {
				logPrintln(1, err)
				return
			}
		}
	}

	defer conn.Close()
	go io.Copy(client, conn)
	io.Copy(conn, client)
}

func Proxy(client net.Conn) {
	defer client.Close()

	var conn net.Conn
	{
		var host string
		var port int
		addr, err := GetOriginalDST(client.(*net.TCPConn))

		ip := []byte(addr.IP)
		iptype := binary.BigEndian.Uint16(ip[:2])
		switch iptype {
		case 0x2000:
			index := int(binary.BigEndian.Uint32(ip[12:16]))
			if index >= len(Nose) {
				return
			}
			host = Nose[index]
		case 0x0600:
			index := int(binary.BigEndian.Uint16(ip[2:4]))
			if index >= len(Nose) {
				return
			}
			host = Nose[index]
		default:
			if addr.String() == client.LocalAddr().String() {
				return
			}
		}

		conf, ok := ConfigLookup(host)

		if ok {
			var b [1500]byte
			n, err := client.Read(b[:])
			if err != nil {
				log.Println(err)
				return
			}

			logPrintln(1, "Proxy:", host, port, conf)

			var ips []string
			if conf.Option&OPT_IPV6 != 0 {
				_, ips = NSLookup(host, 28)
			} else {
				_, ips = NSLookup(host, 1)
			}
			if len(ips) == 0 {
				logPrintln(1, host, "no such host")
				return
			}

			if b[0] == 0x16 {
				conn, err = Dial(ips, port, b[:n], &conf)
				if err != nil {
					logPrintln(1, host, err)
					return
				}
			} else {
				if conf.Option&OPT_HTTPS != 0 {
					HttpMove(client, "https", b[:n])
					return
				} else if conf.Option&OPT_STRIP != 0 {
					ipaddr := ips[rand.Intn(len(ips))]
					conn, err = DialStrip(ipaddr, "")
					if err != nil {
						logPrintln(1, err)
						return
					}
					_, err = conn.Write(b[:n])
				} else {
					conn, err = HTTP(client, ips, port, b[:n], &conf)
					if err != nil {
						logPrintln(1, err)
						return
					}
					io.Copy(client, conn)
					return
				}
			}
		} else {
			logPrintln(1, addr.String())

			conn, err = net.Dial("tcp", addr.String())
			if err != nil {
				logPrintln(1, err)
				return
			}
		}
	}

	defer conn.Close()
	go io.Copy(client, conn)
	io.Copy(conn, client)
}
