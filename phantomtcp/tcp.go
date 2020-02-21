package phantomtcp

import (
	"net"
)

func Dial(host string, b []byte, conf *Config) (net.Conn, error) {
	conn, err := net.Dial("tcp", host)
	if err != nil {
		return nil, err
	}

	if b != nil {
		offset, length := GetSNI(b)
		fakepayload := make([]byte, 1280)

		tcpAddr, err := net.ResolveTCPAddr("tcp", conn.LocalAddr().String())
		if err != nil {
			conn.Close()
			return nil, err
		}

		SendFakePacket(tcpAddr.Port, fakepayload, conf)

		cut := offset + length/2
		_, err = conn.Write(b[:cut])
		if err != nil {
			conn.Close()
			return nil, err
		}

		SendFakePacket(tcpAddr.Port, fakepayload, conf)

		_, err = conn.Write(b[cut:])
		if err != nil {
			conn.Close()
			return nil, err
		}
	}

	return conn, err
}

func DialTCP(addr *net.TCPAddr, b []byte, conf *Config) (net.Conn, error) {
	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		return nil, err
	}

	if b != nil {
		offset, length := GetSNI(b)
		fakepayload := make([]byte, 1280)

		tcpAddr, err := net.ResolveTCPAddr("tcp", conn.LocalAddr().String())
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

		err = SendFakePacket(tcpAddr.Port, fakepayload, conf)
		if err != nil {
			conn.Close()
			return nil, err
		}

		_, err = conn.Write(b[cut:])
		if err != nil {
			conn.Close()
			return nil, err
		}
	}

	return conn, err
}
