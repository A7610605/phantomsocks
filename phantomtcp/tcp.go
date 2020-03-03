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
	if len(ips) == 0 {
		return nil, errors.New("no such host")
	}

	if b != nil {
		offset, length := GetSNI(b)
		cut := offset + length/2

		if length > 0 {
			var connInfo *ConnectionInfo4
			for i := 0; i < 5; i++ {
				sport := rand.Intn(65535-1024) + 1024
				laddr := &net.TCPAddr{Port: sport}
				ipaddr := ips[rand.Intn(len(ips))]
				ip := net.ParseIP(ipaddr)
				if ip == nil {
					logPrintln(1, address, "Bad Address:", ipaddr)
					continue
				}

				var raddr *net.TCPAddr
				ip4 := ip.To4()
				if ip4 != nil {
					raddr = &net.TCPAddr{ip4, port, ""}
				} else {
					raddr = &net.TCPAddr{ip, port, ""}
				}

				ConnPayload4[sport] = &b
				conn, err = net.DialTCP("tcp", laddr, raddr)
				ConnPayload4[sport] = nil

				if err != nil {
					ConnInfo4[sport] = nil
					if IsNormalError(err) {
						continue
					}
					return nil, err
				}

				connInfo = ConnInfo4[sport]
				ConnInfo4[sport] = nil
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

			count := 1
			if conf.Option&OPT_WACK != 0 {
				err = SendFakePacket(connInfo, fakepayload, conf, 1)
				if err != nil {
					conn.Close()
					return nil, err
				}
				count = 2
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

	if b != nil {
		offset, length := GetSNI(b)
		cut := offset + length/2

		if length > 0 {
			var connInfo *ConnectionInfo4
			for i := 0; i < 5; i++ {
				sport := rand.Intn(65535-1024) + 1024
				laddr := &net.TCPAddr{Port: sport}

				ConnPayload4[sport] = &b
				conn, err = net.DialTCP("tcp", laddr, addr)
				ConnPayload4[sport] = nil

				if err != nil {
					ConnInfo4[sport] = nil
					if IsNormalError(err) {
						continue
					}
					return nil, err
				}

				connInfo = ConnInfo4[sport]
				ConnInfo4[sport] = nil
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

			err = SendFakePacket(connInfo, fakepayload, conf, 1)
			if err != nil {
				conn.Close()
				return nil, err
			}

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

			return conn, err
		} else {
			conn, err = net.DialTCP("tcp", nil, addr)
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
