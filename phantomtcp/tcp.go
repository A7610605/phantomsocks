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
				CreatePortChan(port)
				conn, err = net.DialTCP("tcp", &laddr, addr)

				if IsAddressInUse(err) {
					DeletePortChan(port)
					continue
				}

				connInfo = GetConnInfo(port)
				break
			}
			if err != nil {
				return nil, err
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
