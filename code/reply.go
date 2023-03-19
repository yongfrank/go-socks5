package socks5

import (
	"errors"
	"io"
	"net"
)

type ReplyType = byte

/*
Where:

	o  VER    protocol version: X'05'
	o  REP    Reply field:
	    o  X'00' succeeded
	    o  X'01' general SOCKS server failure
	    o  X'02' connection not allowed by ruleset
	    o  X'03' Network unreachable
	    o  X'04' Host unreachable
	    o  X'05' Connection refused
	    o  X'06' TTL expired
	    o  X'07' Command not supported
	    o  X'08' Address type not supported
	    o  X'09' to X'FF' unassigned
	o  RSV    RESERVED
	o  ATYP   address type of following address
	    o  IP V4 address: X'01'
	    o  DOMAINNAME: X'03'
	    o  IP V6 address: X'04'
	o  BND.ADDR       server bound address
	o  BND.PORT       server bound port in network octet order

+----+-----+-------+------+----------+----------+
|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+
*/
const (
	ReplySuccess ReplyType = iota
	ReplyServiceFailure
	ReplyConnectionNotAllowed
	ReplyNetworkUnreachable
	ReplyHostUnreachable
	ReplyConnectionRefused
	ReplyTTLExpired
	ReplyCommandNotSupported
	ReplyAddressTypeNotSupported
	ReplyUnassigned
)

func WriteRequestSuccessMessage(conn io.Writer, ip net.IP, port uint16) error {
	addressType := TypeIPv4
	if len(ip) == IPv6Length {
		addressType = TypeIPv6
	}
	// 该函数首先使用 conn.Write 方法向客户端发送了一个 5 字节的消息，其中包括 SOCKS5 协议的版本号、回复成功的响应码、保留字段、地址类型。然后，该函数使用 conn.Write 方法向客户端发送绑定到代理服务器的 IP 地址。这个 IP 地址的具体格式取决于 addressType 参数的值，如果 addressType 是 IPv4Address，则这个 IP 地址应该是 4 个字节的 IPv4 地址；如果 addressType 是 IPv6Address，则这个 IP 地址应该是 16 个字节的 IPv6 地址。
	// send message to client
	// Write version, reply success, reserved, address type
	_, err := conn.Write([]byte{SOCKS5Version, ReplySuccess, ReqReservedField, addressType})
	if err != nil {
		return nil
	}

	// Write bind IP(IPv4, IPv6)
	if _, err := conn.Write(ip); err != nil {
		return err
	}

	// Write bind port
	buf := make([]byte, 2)
	buf[0] = byte(port >> 8) // 0x1f90 -> 1f
	buf[1] = byte(port)      // 0x1f90 -> 90
	_, err = conn.Write(buf)
	return err
}

func ErrorString(r ReplyType) string {
	switch r {
	case ReplySuccess:
		return "succeeded"
	case ReplyServiceFailure:
		return "general SOCKS server failure"
	case ReplyConnectionNotAllowed:
		return "connection not allowed by ruleset"
	case ReplyNetworkUnreachable:
		return "Network unreachable"
	case ReplyHostUnreachable:
		return "Host unreachable"
	case ReplyConnectionRefused:
		return "Connection refused"
	case ReplyTTLExpired:
		return "TTL expired"
	case ReplyCommandNotSupported:
		return "Command not supported"
	case ReplyAddressTypeNotSupported:
		return "Address type not supported"
	default:
		return "unknown error"
	}
}

func WriteRequestFailureMessage(conn io.Writer, replyType ReplyType) error {
	conn.Write([]byte{SOCKS5Version, replyType, ReqReservedField, TypeIPv4, 0, 0, 0, 0, 0, 0})
	// return ErrAddressTypeNotSupported
	return errors.New(ErrorString(replyType))
}
