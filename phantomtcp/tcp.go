package phantomtcp

import (
	"errors"
	"io"
	"math/rand"
	"net"
	"os"
	"syscall"
)

const domainBytes = "abcdefghijklmnopqrstuvwxyz0123456789-"

func IsAddressInUse(err error) bool {
	//return errors.Is(err, syscall.EADDRINUSE)
	errOpError, ok := err.(*net.OpError)
	if !ok {
		return false
	}
	errSyscallError, ok := errOpError.Err.(*os.SyscallError)
	if !ok {
		return false
	}
	errErrno, ok := errSyscallError.Err.(syscall.Errno)
	if !ok {
		return false
	}
	if errErrno == syscall.EADDRINUSE {
		return true
	}
	return false
}

func IsNormalError(err error) bool {
	errOpError, ok := err.(*net.OpError)
	if !ok {
		return false
	}
	errSyscallError, ok := errOpError.Err.(*os.SyscallError)
	if !ok {
		return false
	}
	errErrno, ok := errSyscallError.Err.(syscall.Errno)
	if !ok {
		return false
	}
	if errErrno == syscall.EADDRINUSE ||
		errErrno == syscall.ECONNREFUSED ||
		errErrno == syscall.ECONNRESET {
		return true
	}
	return false
}

func DialConnInfo(laddr, raddr *net.TCPAddr) (*net.TCPConn, *ConnectionInfo, error) {
	ip4 := raddr.IP.To4()
	if ip4 != nil {
		ConnSyn4[laddr.Port] = true
		conn, err := net.DialTCP("tcp4", laddr, raddr)
		ConnSyn4[laddr.Port] = false

		if err != nil {
			ConnInfo4[laddr.Port] = nil
			return nil, nil, err
		}

		connInfo := ConnInfo4[laddr.Port]
		ConnInfo4[laddr.Port] = nil
		return conn, connInfo, nil
	} else {
		ConnSyn6[laddr.Port] = true
		conn, err := net.DialTCP("tcp6", laddr, raddr)
		ConnSyn6[laddr.Port] = false

		if err != nil {
			ConnInfo6[laddr.Port] = nil
			return nil, nil, err
		}

		connInfo := ConnInfo6[laddr.Port]
		ConnInfo6[laddr.Port] = nil
		return conn, connInfo, nil
	}
}

func GetLocalAddr(name string, port int, ipv6 bool) (*net.TCPAddr, error) {
	inf, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, _ := inf.Addrs()
	for _, addr := range addrs {
		localAddr, ok := addr.(*net.IPNet)
		if ok {
			ip4 := localAddr.IP.To4()
			if ipv6 {
				if ip4 != nil || localAddr.IP[0] == 0xfe {
					continue
				}
				var ip [16]byte
				copy(ip[:16], localAddr.IP)
				laddr := &net.TCPAddr{IP: ip[:], Port: port}
				return laddr, nil
			} else {
				if ip4 == nil {
					continue
				}
				var ip [4]byte
				copy(ip[:4], ip4)
				laddr := &net.TCPAddr{IP: ip[:], Port: port}
				return laddr, nil
			}
		}
	}

	return nil, nil
}

func Dial(address string, port int, b []byte, conf *Config) (net.Conn, error) {
	var err error
	var conn net.Conn

	var ips []string
	if conf.Option&OPT_IPV6 != 0 {
		ips = NSLookup(address, 28)
	} else {
		ips = NSLookup(address, 1)
	}
	if len(ips) == 0 {
		return nil, errors.New("no such host")
	}

	if b != nil {
		offset, length := GetSNI(b)
		cut := offset + length/2

		if length > 0 {
			var connInfo *ConnectionInfo
			for i := 0; i < 5; i++ {

				ipaddr := ips[rand.Intn(len(ips))]
				ip := net.ParseIP(ipaddr)
				if ip == nil {
					logPrintln(1, address, "Bad Address:", ipaddr)
					continue
				}

				var laddr *net.TCPAddr
				sport := rand.Intn(65535-1024) + 1024
				if conf.Device == "" {
					laddr = &net.TCPAddr{Port: sport}
				} else {
					laddr, err = GetLocalAddr(conf.Device, sport, ip.To4() == nil)
					if laddr == nil {
						continue
					}
				}

				raddr := &net.TCPAddr{ip, port, ""}
				conn, connInfo, err = DialConnInfo(laddr, raddr)

				if err != nil {
					if IsNormalError(err) {
						continue
					}
					return nil, err
				}

				if connInfo != nil {
					logPrintln(2, address, port, ip)
					break
				}
			}

			if connInfo == nil {
				return nil, errors.New("connection does not exist")
			}

			fakepayload := make([]byte, len(b))
			copy(fakepayload, b)

			for i := offset; i < offset+length-3; i++ {
				if fakepayload[i] != '.' {
					fakepayload[i] = domainBytes[rand.Intn(len(domainBytes))]
				}
			}

			count := 2
			if conf.Option&OPT_MODE2 == 0 {
				err = SendFakePacket(connInfo, fakepayload, conf, 1)
				if err != nil {
					conn.Close()
					return nil, err
				}
				count = 1
			}

			_, err = conn.Write(b[:cut])
			if err != nil {
				conn.Close()
				return nil, err
			}

			err = SendFakePacket(connInfo, fakepayload, conf, count)
			if err != nil {
				conn.Close()
				return nil, err
			}

			_, err = conn.Write(b[cut:])
			if err != nil {
				conn.Close()
				return nil, err
			}

			return conn, err
		} else {
			ip := net.ParseIP(ips[rand.Intn(len(ips))])
			if ip == nil {
				return nil, nil
			}
			raddr := &net.TCPAddr{ip, port, ""}
			conn, err = net.DialTCP("tcp", nil, raddr)
			if err != nil {
				return nil, err
			}
			_, err = conn.Write(b)
			if err != nil {
				conn.Close()
			}
			return conn, err
		}
	}

	ip := net.ParseIP(ips[rand.Intn(len(ips))])
	if ip == nil {
		return nil, nil
	}
	raddr := &net.TCPAddr{ip, port, ""}
	conn, err = net.DialTCP("tcp", nil, raddr)

	return conn, err
}

func DialTCP(addr *net.TCPAddr, b []byte, conf *Config) (net.Conn, error) {
	var err error
	var conn net.Conn

	if conf.Option&OPT_NAT64 != 0 {
		ips, ok := DNSCache[addr.IP.String()]
		if ok {
			ip := ips[rand.Intn(len(ips))]
			ip += addr.IP.String()
			addr.IP = net.ParseIP(ip)
		}
	}

	if b != nil {
		offset, length := GetSNI(b)
		cut := offset + length/2

		if length > 0 {
			var connInfo *ConnectionInfo
			for i := 0; i < 5; i++ {
				var laddr *net.TCPAddr
				sport := rand.Intn(65535-1024) + 1024
				if conf.Device == "" {
					laddr = &net.TCPAddr{Port: sport}
				} else {
					laddr, err = GetLocalAddr(conf.Device, sport, addr.IP.To4() == nil)
					if laddr == nil {
						continue
					}
				}

				conn, connInfo, err = DialConnInfo(laddr, addr)

				if err != nil {
					if IsNormalError(err) {
						continue
					}
					return nil, err
				}

				if connInfo != nil {
					break
				}
			}

			if connInfo == nil {
				return nil, errors.New("connection does not exist")
			}

			fakepayload := make([]byte, len(b))
			copy(fakepayload, b)

			for i := offset; i < offset+length-3; i++ {
				if fakepayload[i] != '.' {
					fakepayload[i] = domainBytes[rand.Intn(len(domainBytes))]
				}
			}

			count := 2
			if conf.Option&OPT_MODE2 == 0 {
				err = SendFakePacket(connInfo, fakepayload, conf, 1)
				if err != nil {
					conn.Close()
					return nil, err
				}
				count = 1
			}

			_, err = conn.Write(b[:cut])
			if err != nil {
				conn.Close()
				return nil, err
			}

			err = SendFakePacket(connInfo, fakepayload, conf, count)
			if err != nil {
				conn.Close()
				return nil, err
			}

			_, err = conn.Write(b[cut:])
			if err != nil {
				conn.Close()
				return nil, err
			}

			return conn, err
		} else {
			var laddr *net.TCPAddr = nil
			if conf.Device != "" {
				laddr, err = GetLocalAddr(conf.Device, 0, addr.IP.To4() == nil)
				if err != nil {
					return nil, err
				}
			}
			conn, err = net.DialTCP("tcp", laddr, addr)
			if err != nil {
				return nil, err
			}
			_, err = conn.Write(b)
			if err != nil {
				conn.Close()
			}
			return conn, err
		}
	}

	conn, err = net.DialTCP("tcp", nil, addr)
	return conn, err
}

func HTTP(client net.Conn, address string, port int, b []byte, conf *Config) (net.Conn, error) {
	var err error
	var conn net.Conn

	var ips []string
	if conf.Option&OPT_IPV6 != 0 {
		ips = NSLookup(address, 28)
	} else {
		ips = NSLookup(address, 1)
	}
	if len(ips) == 0 {
		return nil, errors.New("no such host")
	}

	if b != nil {
		offset, length := GetHost(b)
		cut := offset + length/2

		if length > 0 {
			var connInfo *ConnectionInfo
			for i := 0; i < 5; i++ {
				ipaddr := ips[rand.Intn(len(ips))]
				ip := net.ParseIP(ipaddr)
				if ip == nil {
					logPrintln(1, address, "Bad Address:", ipaddr)
					continue
				}

				var laddr *net.TCPAddr
				sport := rand.Intn(65535-1024) + 1024
				if conf.Device == "" {
					laddr = &net.TCPAddr{Port: sport}
				} else {
					laddr, err = GetLocalAddr(conf.Device, sport, ip.To4() == nil)
					if laddr == nil {
						continue
					}
				}

				raddr := &net.TCPAddr{ip, port, ""}
				conn, connInfo, err = DialConnInfo(laddr, raddr)

				if err != nil {
					if IsNormalError(err) {
						continue
					}
					return nil, err
				}

				if connInfo != nil {
					logPrintln(2, address, port, ip)
					break
				}
			}

			if connInfo == nil {
				return nil, errors.New("connection does not exist")
			}

			fakepayload := make([]byte, len(b))
			copy(fakepayload, b)

			for i := offset; i < offset+length-3; i++ {
				if fakepayload[i] != '.' {
					fakepayload[i] = domainBytes[rand.Intn(len(domainBytes))]
				}
			}

			count := 2
			if conf.Option&OPT_MODE2 == 0 {
				err = SendFakePacket(connInfo, fakepayload, conf, 1)
				if err != nil {
					conn.Close()
					return nil, err
				}
				count = 1
			}

			_, err = conn.Write(b[:cut])
			if err != nil {
				conn.Close()
				return nil, err
			}

			err = SendFakePacket(connInfo, fakepayload, conf, count)
			if err != nil {
				conn.Close()
				return nil, err
			}

			_, err = conn.Write(b[cut:])
			if err != nil {
				conn.Close()
				return nil, err
			}

			connInfo.TCP.Seq += uint32(len(b))
			go func() {
				var b [1460]byte
				for {
					n, err := client.Read(b[:])
					if err != nil {
						conn.Close()
						return
					}

					err = SendFakePacket(connInfo, fakepayload, conf, 2)
					if err != nil {
						conn.Close()
						return
					}
					_, err = conn.Write(b[:n])
					if err != nil {
						conn.Close()
						return
					}
					connInfo.TCP.Seq += uint32(n)
				}
			}()

			return conn, err
		} else {
			ip := net.ParseIP(ips[rand.Intn(len(ips))])
			if ip == nil {
				return nil, nil
			}

			var laddr *net.TCPAddr = nil
			if conf.Device != "" {
				laddr, err = GetLocalAddr(conf.Device, 0, ip.To4() == nil)
				if err != nil {
					return nil, err
				}
			}

			raddr := &net.TCPAddr{ip, port, ""}
			conn, err = net.DialTCP("tcp", laddr, raddr)
			if err != nil {
				return nil, err
			}
			_, err = conn.Write(b)
			if err != nil {
				conn.Close()
				return conn, err
			}
			go io.Copy(conn, client)
			return conn, err
		}
	}

	ip := net.ParseIP(ips[rand.Intn(len(ips))])
	raddr := &net.TCPAddr{ip, port, ""}
	conn, err = net.DialTCP("tcp", nil, raddr)
	if err != nil {
		return conn, err
	}

	go io.Copy(conn, client)
	return conn, err
}
