package phantomtcp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Option uint32
	TTL    byte
	MAXTTL byte
	MSS    uint16
}

var DomainMap map[string]Config
var IPMap map[string]Config
var DNSCache map[string][]string

var SubdomainDepth = 2
var LogLevel = 0
var Forward bool = false

const (
	OPT_NONE   = 0x0
	OPT_TTL    = 0x1 << 0
	OPT_MD5    = 0x1 << 1
	OPT_ACK    = 0x1 << 2
	OPT_CSUM   = 0x1 << 3
	OPT_BAD    = 0x1 << 4
	OPT_IPOPT  = 0x1 << 5
	OPT_SEQ    = 0x1 << 6
	OPT_HTTPS  = 0x1 << 7
	OPT_MSS    = 0x1 << 8
	OPT_STRIP  = 0x1 << 9
	OPT_HTTP   = 0x1 << 10
	OPT_TFO    = 0x10000 << 0
	OPT_SYN    = 0x10000 << 1
	OPT_NOFLAG = 0x10000 << 2
	OPT_QUIC   = 0x10000 << 3
)

var MethodMap = map[string]uint32{
	"none":    OPT_NONE,
	"ttl":     OPT_TTL,
	"mss":     OPT_MSS,
	"w-md5":   OPT_MD5,
	"w-ack":   OPT_ACK,
	"no-csum": OPT_CSUM,
	"bad":     OPT_BAD,
	"ipopt":   OPT_IPOPT,
	"seq":     OPT_SEQ,
	"https":   OPT_HTTPS,
	"strip":   OPT_STRIP,
	"http":    OPT_HTTP,
	"tfo":     OPT_TFO,
	"syn":     OPT_SYN,
	"no-flag": OPT_NOFLAG,
	"quic":    OPT_QUIC,
}

var Logger *log.Logger

func logPrintln(level int, v ...interface{}) {
	if LogLevel >= level {
		fmt.Println(v)
	}
}

func ConfigLookup(name string) (Config, bool) {
	config, ok := DomainMap[name]
	if ok {
		return config, true
	}

	offset := 0
	for i := 0; i < SubdomainDepth; i++ {
		off := strings.Index(name[offset:], ".")
		if off == -1 {
			break
		}
		offset += off
		config, ok = DomainMap[name[offset:]]
		if ok {
			return config, true
		}
		offset++
	}

	return Config{0, 0, 0, 0}, false
}

func GetSNI(b []byte) (offset int, length int) {
	if b[0] != 0x16 {
		return 0, 0
	}
	if len(b) < 5 {
		return 0, 0
	}
	Version := binary.BigEndian.Uint16(b[1:3])
	if (Version & 0xFFF8) != 0x0300 {
		return 0, 0
	}
	Length := binary.BigEndian.Uint16(b[3:5])
	if len(b) <= int(Length)-5 {
		return 0, 0
	}
	offset = 11 + 32
	SessionIDLength := b[offset]
	offset += 1 + int(SessionIDLength)
	if offset+2 > len(b) {
		return 0, 0
	}
	CipherSuitersLength := binary.BigEndian.Uint16(b[offset : offset+2])
	offset += 2 + int(CipherSuitersLength)
	if offset >= len(b) {
		return 0, 0
	}
	CompressionMethodsLenght := b[offset]
	offset += 1 + int(CompressionMethodsLenght)
	if offset+2 > len(b) {
		return 0, 0
	}
	ExtensionsLength := binary.BigEndian.Uint16(b[offset : offset+2])
	offset += 2
	ExtensionsEnd := offset + int(ExtensionsLength)
	if ExtensionsEnd > len(b) {
		return 0, 0
	}
	for offset < ExtensionsEnd {
		ExtensionType := binary.BigEndian.Uint16(b[offset : offset+2])
		offset += 2
		ExtensionLength := binary.BigEndian.Uint16(b[offset : offset+2])
		offset += 2
		if ExtensionType == 0 {
			offset += 2
			offset++
			ServerNameLength := binary.BigEndian.Uint16(b[offset : offset+2])
			offset += 2
			return offset, int(ServerNameLength)
		} else {
			offset += int(ExtensionLength)
		}
	}
	return 0, 0
}

func getHost(b []byte) (offset int, length int) {
	offset = bytes.Index(b, []byte("Host: "))
	if offset == -1 {
		return 0, 0
	}
	offset += 6
	length = bytes.Index(b[offset:], []byte("\r\n"))
	if offset == -1 {
		return 0, 0
	}

	return
}

func HttpMove(conn net.Conn, host string, b []byte) bool {
	data := make([]byte, 1460)
	n := 0
	if host == "" {
		copy(data[:], []byte("HTTP/1.1 200 OK"))
		n += 15
	} else if host == "https" {
		copy(data[:], []byte("HTTP/1.1 302 Found\r\nLocation: https://"))
		n += 38

		header := string(b)
		start := strings.Index(header, "Host: ") + 6
		end := strings.Index(header[start:], "\r\n") + start
		copy(data[n:], []byte(header[start:end]))
		n += end - start

		start = 4
		end = strings.Index(header[start:], " ") + start
		copy(data[n:], []byte(header[start:end]))
		n += end - start
	} else {
		copy(data[:], []byte("HTTP/1.1 302 Found\r\nLocation: "))
		n += 30
		copy(data[n:], []byte(host))
		n += len(host)

		start := 4
		header := string(b)
		end := strings.Index(header[start:], " ") + start
		copy(data[n:], []byte(header[start:end]))
		n += end - start
	}

	copy(data[n:], []byte("\r\nCache-Control: private\r\nServer: pinocchio\r\nContent-Length: 0\r\n\r\n"))
	n += 66
	conn.Write(data[:n])
	return true
}

func DialStrip(host string, fronting string) (*tls.Conn, error) {
	var conf *tls.Config
	if fronting == "" {
		conf = &tls.Config{
			InsecureSkipVerify: true,
		}
	} else {
		conf = &tls.Config{
			ServerName:         fronting,
			InsecureSkipVerify: true,
		}
	}

	conn, err := tls.Dial("tcp", net.JoinHostPort(host, "443"), conf)
	return conn, err
}

func HttpProxy(client net.Conn, host string, address string, b []byte) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return
	}
	defer conn.Close()

	header := string(b)
	header = strings.Replace(header, " HTTP/1.1\r", "    HTTP/1.1", 10)
	header = strings.Replace(header, "GET ", "GET   ", 10)
	header = strings.Replace(header, "Host: "+host, "Host:\t  "+strings.ToTitle(host), 1)
	header = strings.Replace(header, "Referer: http", "X-Referer: \thttps", 1)
	header = strings.Replace(header, "\r\n", "\n", 10)
	_, err = conn.Write([]byte(header))
	if err != nil {
		logPrintln(1, err)
		return
	}

	go func(conn net.Conn) {
		data := make([]byte, 1460)
		defer conn.Close()
		for {
			n, err := conn.Read(data)
			if err != nil {
				return
			}
			_, err = client.Write(data[:n])
			if err != nil {
				return
			}
		}
	}(conn)

	data := make([]byte, 1460)
	for {
		n, err := client.Read(data)
		if err != nil {
			return
		}
		header := string(data[:n])
		header = strings.Replace(header, "GET /", "GET   /", 1)
		header = strings.Replace(header, "POST /", "POST   /", 1)
		header = strings.Replace(header, " HTTP/1.1\r", "    HTTP/1.1", 1)
		header = strings.Replace(header, "Host: "+host, "HOST:\t  "+strings.ToTitle(host), 1)
		header = strings.Replace(header, "Referer: http", "X-Referer: \thttps", 1)
		header = strings.Replace(header, "\r\n", "\n", 10)

		_, err = conn.Write([]byte(header))
		if err != nil {
			return
		}
	}
}

func getMyIPv6() net.IP {
	s, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range s {
		strIP := strings.SplitN(a.String(), "/", 2)
		if strIP[1] == "128" && strIP[0] != "::1" {
			ip := net.ParseIP(strIP[0])
			ip4 := ip.To4()
			if ip4 == nil {
				return ip
			}
		}
	}
	return nil
}

func Init() {
	DomainMap = make(map[string]Config)
	IPMap = make(map[string]Config)
	DNSCache = make(map[string][]string)
}

func LoadConfig(filename string) error {
	conf, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer conf.Close()

	br := bufio.NewReader(conf)

	var option uint32 = 0
	var minTTL byte = 0
	var maxTTL byte = 0
	var syncMSS uint16 = 0
	ipv6Enable := true
	ipv4Enable := true

	for {
		line, _, err := br.ReadLine()
		if err == io.EOF {
			break
		}

		if len(line) > 0 {
			if line[0] != '#' {
				l := strings.SplitN(string(line), "#", 2)[0]
				keys := strings.SplitN(l, "=", 2)
				if len(keys) > 1 {
					if keys[0] == "server" {
						var tcpAddr *net.TCPAddr
						var err error
						if ipv6Enable {
							if ipv4Enable {
								tcpAddr, err = net.ResolveTCPAddr("tcp", keys[1])
							} else {
								tcpAddr, err = net.ResolveTCPAddr("tcp6", keys[1])
							}
						} else {
							tcpAddr, err = net.ResolveTCPAddr("tcp4", keys[1])
						}
						if err != nil {
							log.Println(string(line), err)
							return err
						}
						DNS = tcpAddr.String()
						IPMap[tcpAddr.IP.String()] = Config{option, minTTL, maxTTL, syncMSS}
						logPrintln(2, string(line))
					} else if keys[0] == "dns64" {
						DNS64 = keys[1]
						logPrintln(2, string(line))
					} else if keys[0] == "ipv6" {
						if keys[1] == "true" {
							ipv6Enable = true
						} else {
							ipv6Enable = false
						}
						logPrintln(2, string(line))
					} else if keys[0] == "ipv4" {
						if keys[1] == "true" {
							ipv4Enable = true
						} else {
							ipv4Enable = false
						}
						logPrintln(2, string(line))
					} else if keys[0] == "method" {
						option = OPT_NONE
						methods := strings.Split(keys[1], ",")
						for _, m := range methods {
							method, ok := MethodMap[m]
							if ok {
								option |= method
							} else {
								logPrintln(1, "unsupported method: "+m)
							}
						}
						logPrintln(2, string(line))
					} else if keys[0] == "ttl" {
						ttl, err := strconv.Atoi(keys[1])
						if err != nil {
							log.Println(string(line), err)
							return err
						}
						minTTL = byte(ttl)
						logPrintln(2, string(line))
					} else if keys[0] == "mss" {
						mss, err := strconv.Atoi(keys[1])
						if err != nil {
							log.Println(string(line), err)
							return err
						}
						syncMSS = uint16(mss)
						logPrintln(2, string(line))
					} else if keys[0] == "max-ttl" {
						ttl, err := strconv.Atoi(keys[1])
						if err != nil {
							log.Println(string(line), err)
							return err
						}
						maxTTL = byte(ttl)
						logPrintln(2, string(line))
					} else if keys[0] == "subdomain" {
						SubdomainDepth, err = strconv.Atoi(keys[1])
						if err != nil {
							log.Println(string(line), err)
							return err
						}
					} else {
						ip := net.ParseIP(keys[0])
						if ip == nil {
							ips := strings.Split(keys[1], ",")

							for _, ip := range ips {
								config, ok := IPMap[ip]
								_option := option
								if ok {
									_option |= config.Option
									if syncMSS == 0 {
										syncMSS = config.MSS
									}
								}
								IPMap[ip] = Config{_option, minTTL, maxTTL, syncMSS}
							}

							DomainMap[keys[0]] = Config{option, minTTL, maxTTL, syncMSS}
							DNSCache[keys[0]] = ips
						} else {
							IPMap[ip.String()] = Config{option, minTTL, maxTTL, syncMSS}
						}
					}
				} else {
					if keys[0] == "ipv6" {
						ipv6Enable = true
						logPrintln(2, string(line))
					} else if keys[0] == "ipv4" {
						ipv4Enable = true
						logPrintln(2, string(line))
					} else if keys[0] == "forward" {
						Forward = true
						logPrintln(2, string(line))
					} else {
						addr, err := net.ResolveTCPAddr("tcp", keys[0])
						if err == nil {
							IPMap[addr.IP.String()] = Config{option, minTTL, maxTTL, syncMSS}
						} else {
							if strings.Index(keys[0], "/") > 0 {
								_, ipnet, err := net.ParseCIDR(keys[0])
								if err == nil {
									IPMap[ipnet.String()] = Config{option, minTTL, maxTTL, syncMSS}
								}
							} else {
								ip := net.ParseIP(keys[0])

								if ip != nil {
									IPMap[keys[0]] = Config{option, minTTL, maxTTL, syncMSS}
								} else {
									DomainMap[keys[0]] = Config{option, minTTL, maxTTL, syncMSS}
								}
							}
						}
					}
				}
			}
		}
	}

	logPrintln(1, filename)

	return nil
}

func LoadHosts(filename string) error {
	hosts, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer hosts.Close()

	br := bufio.NewReader(hosts)

	for {
		line, _, err := br.ReadLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			logPrintln(1, err)
		}

		if len(line) == 0 || line[0] == '#' {
			continue
		}

		k := strings.SplitN(string(line), "\t", 2)
		if len(k) == 2 {
			name := k[1]
			ips, ok := DNSCache[name]
			if ok {
				continue
			}
			offset := 0
			for i := 0; i < SubdomainDepth; i++ {
				off := strings.Index(name[offset:], ".")
				if off == -1 {
					break
				}
				offset += off
				ips, ok = DNSCache[name[offset:]]
				if ok {
					DNSCache[name] = ips
					continue
				}
				offset++
			}

			if !ok {
				DNSCache[name] = []string{k[0]}
			}
		}
	}

	return nil
}
