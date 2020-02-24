package phantomtcp

import (
	"bufio"
	"bytes"
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
	for i := 0; i < 2; i++ {
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

func LoadConfig(filename string) error {
	DomainMap = make(map[string]Config)
	IPMap = make(map[string]Config)
	DNSCache = make(map[string][]string)

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
								logPrintln(1, "Unsupported method: "+m)
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
								if ok {
									option |= config.Option
									if syncMSS == 0 {
										syncMSS = config.MSS
									}
								}
								IPMap[ip] = Config{option, minTTL, maxTTL, syncMSS}
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
