package phantomtcp

import (
	"errors"
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

func Dial(address string, port int, b []byte, conf *Config) (net.Conn, error) {
	var err error
	var conn net.Conn

	ips := NSLookup(address, 1)
	if b != nil {
		offset, length := GetSNI(b)
		cut := offset + length/2

		tfo := conf.Option&OPT_TFO != 0
		if length > 0 {
			var connInfo *ConnectionInfo4
			for i := 0; i < 5; i++ {
				sport := rand.Intn(65535-1024) + 1024
				laddr := &net.TCPAddr{Port: sport}
				portChan := CreatePortChan(sport)
				ipaddr := ips[rand.Intn(len(ips))]
				ip := net.ParseIP(ipaddr)
				if ip == nil {
					continue
				}
				var raddr *net.TCPAddr
				ip4 := ip.To4()
				if ip4 != nil {
					raddr = &net.TCPAddr{ip4, port, ""}
				} else {
					raddr = &net.TCPAddr{ip, port, ""}
				}

				if tfo {
					d := net.Dialer{LocalAddr: laddr,
						Control: func(network, address string, c syscall.RawConn) error {
							err := c.Control(func(fd uintptr) {
								syscall.SetsockoptInt(int(fd), 6, 30, 1)
							})
							return err
						}}
					conn, err = d.Dial("tcp", raddr.String())
					if err != nil {
						continue
					}
					_, err = conn.Write(b[:cut])
				} else {
					conn, err = net.DialTCP("tcp", laddr, raddr)
				}

				logPrintln(2, address, port, ip)
				if err != nil {
					DeletePortChan(sport)
					if IsNormalError(err) {
						continue
					} else {
						return nil, err
					}
				}

				connInfo = GetConnInfo(portChan)
				DeletePortChan(sport)
				break
			}

			fakepayload := make([]byte, len(b))
			copy(fakepayload, b)

			for i := offset; i < offset+length-3; i++ {
				if fakepayload[i] != '.' {
					fakepayload[i] = domainBytes[rand.Intn(len(domainBytes))]
				}
			}

			if connInfo == nil {
				if tfo {
					_, err = conn.Write(b[cut:])
					return conn, err
				}
				return nil, errors.New("Connection does not exist")
			}

			err = SendFakePacket(connInfo, fakepayload, conf, 1)
			if err != nil {
				conn.Close()
				return nil, err
			}

			if !tfo {
				_, err = conn.Write(b[:cut])
				if err != nil {
					conn.Close()
					return nil, err
				}
			}

			err = SendFakePacket(connInfo, fakepayload, conf, 1)
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
		}
	}

	ip := net.ParseIP(ips[rand.Intn(len(ips))])
	if ip == nil {
		return nil, nil
	}
	raddr := &net.TCPAddr{ip, port, ""}
	conn, err = net.DialTCP("tcp", nil, raddr)
	_, err = conn.Write(b)

	return conn, err
}

func DialTCP(addr *net.TCPAddr, b []byte, conf *Config) (net.Conn, error) {
	var err error
	var conn net.Conn

	if b != nil {
		offset, length := GetSNI(b)
		if length > 0 {
			var connInfo *ConnectionInfo4
			for i := 0; i < 5; i++ {
				port := rand.Intn(65535-1024) + 1024
				laddr := net.TCPAddr{IP: []byte{0, 0, 0, 0}, Port: port}
				portChan := CreatePortChan(port)
				conn, err = net.DialTCP("tcp", &laddr, addr)

				if err != nil {
					DeletePortChan(port)
					if IsAddressInUse(err) {
						continue
					} else {
						return nil, err
					}
				}

				connInfo = GetConnInfo(portChan)
				DeletePortChan(port)
				break
			}

			fakepayload := make([]byte, len(b))
			copy(fakepayload, b)

			for i := offset; i < offset+length-3; i++ {
				if fakepayload[i] != '.' {
					fakepayload[i] = domainBytes[rand.Intn(len(domainBytes))]
				}
			}

			if connInfo == nil {
				return nil, errors.New("Connection does not exist")
			}

			err = SendFakePacket(connInfo, fakepayload, conf, 1)
			if err != nil {
				conn.Close()
				return nil, err
			}

			cut := offset + length/2
			_, err = conn.Write(b[:cut])
			if err != nil {
				conn.Close()
				return nil, err
			}

			err = SendFakePacket(connInfo, fakepayload, conf, 1)
			if err != nil {
				conn.Close()
				return nil, err
			}

			_, err = conn.Write(b[cut:])
			if err != nil {
				conn.Close()
				return nil, err
			}
		} else {
			conn, err = net.DialTCP("tcp", nil, addr)
			_, err = conn.Write(b)
		}
	} else {
		conn, err = net.DialTCP("tcp", nil, addr)
	}

	return conn, err
}
