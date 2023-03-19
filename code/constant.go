package socks5

const (
	SOCKS5Version    = 0x05
	ReqReservedField = 0x00 // also for reply reserved
)

const (
	IPv4Length = 4
	IPv6Length = 16 // 16
	PortLength = 2
)
