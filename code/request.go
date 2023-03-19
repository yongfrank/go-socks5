package socks5

import (
	"io"
	"log"
	"net"
)

/*
+----+-----+-------+------+----------+----------+
|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+
Where:

o  VER    protocol version: X'05'
o  CMD

	o  CONNECT X'01' # TCP service
	o  BIND X'02'
	o  UDP ASSOCIATE X'03'

o  RSV    RESERVED # That one's reserved, this way please
o  ATYP   address type of following address

	o  IP V4 address: X'01'
	o  DOMAINNAME: X'03' # https://www.google.com
	o  IP V6 address: X'04'

o  DST.ADDR       desired destination address
o  DST.PORT desired destination port in network octet

	order
*/
type ClientRequestMessage struct {
	// Version  byte
	Cmd Command
	// Reserved byte

	ATYP    byte // address type of following address, IPv4, IPv6, Domain
	DstAddr string
	DstPort uint16
}

/*
o  CMD

	o  CONNECT X'01' # TCP service
	o  BIND X'02'
	o  UDP ASSOCIATE X'03'
*/
type Command = byte

/*
o  CMD

	o  CONNECT X'01' # TCP service
	o  BIND X'02'
	o  UDP ASSOCIATE X'03'
*/
const (
	CmdConnect Command = 0x01
	CmdBind    Command = 0x02
	CmdUDP     Command = 0x03
)

// IPv4, IPv6, Domain
type AddressType = byte

/*
In an address field (DST.ADDR, BND.ADDR), the ATYP field specifies
the type of address contained within the field:

	o  X'01' # 127.0.0.1

the address is a version-4 IP address, with a length of 4 octets

	o  X'03' # https://www.google.com

the address field contains a fully-qualified domain name.  The first
octet of the address field contains the number of octets of name that
follow, there is no terminating NUL octet.

	o  X'04' # 2001:0db8:85a3:0000:0000:8a2e:0370:7334

the address is a version-6 IP address, with a length of 16 octets.
*/
const (
	TypeIPv4   AddressType = 0x01
	TypeDomain AddressType = 0x03
	TypeIPv6   AddressType = 0x04 // see ATYP 0x04
)

func NewClientRequestMessage(conn io.Reader) (*ClientRequestMessage, error) {
	buf := make([]byte, 4)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}

	// check fields in request
	log.Printf("start fields check")
	version, command, reserved, addType := buf[0], buf[1], buf[2], buf[3]
	if version != SOCKS5Version {
		return nil, ErrVersionNotSupported
	}
	if command != CmdBind && command != CmdConnect && command != CmdUDP {
		return nil, ErrRequestCommandNotSupported
	}
	if reserved != ReqReservedField {
		return nil, ErrRequestReservedFieldNotZero
	}
	if addType != TypeIPv4 && addType != TypeDomain && addType != TypeIPv6 {
		return nil, ErrAddressTypeNotSupported
	}
	// fields check success
	log.Printf("fields check success")

	message := ClientRequestMessage{
		Cmd:  command,
		ATYP: TypeIPv4,
	}

	switch addType {
	case TypeIPv6:
		buf = make([]byte, IPv6Length)
		fallthrough
	case TypeIPv4:
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, err
		}
		ip := net.IP(buf)
		message.DstAddr = ip.String()
	case TypeDomain:

		var firstOctletForDomainLength = 1
		// The first
		// octet of the address field contains the number of octets of name that
		// follow, there is no terminating NUL octet.
		buf = make([]byte, firstOctletForDomainLength)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, err
		}
		domainLen := buf[0]
		buf = make([]byte, domainLen)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, err
		}
		message.DstAddr = string(buf)
	}

	// read port number
	if _, err := io.ReadFull(conn, buf[:PortLength]); err != nil {
		return nil, err
	}
	message.DstPort = uint16(buf[0])<<8 | uint16(buf[1])

	return &message, nil
}
