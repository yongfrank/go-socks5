<!--
 * @Author: Frank Chu
 * @Date: 2023-03-18 00:19:53
 * @LastEditors: Frank Chu
 * @LastEditTime: 2023-03-19 17:10:13
 * @FilePath: /go-socks5/README.md
 * @Description: 
 * 
 * Copyright (c) 2023 by ${git_name}, All Rights Reserved. 
-->

# Socks5 Proxy on Go

## What's in Repository

* Socks5 Proxy
* UDP/TCP Proxy, No-Auth, Username/Password Method
* Go Unit Test
* Dependency Injection
* Socks5 Library
* Socks5 Server Tools

## RFC1928 & RFC1929

* [RFC1928: Request for Comment](https://www.rfc-editor.org/rfc/rfc1928)
* [RFC1929: Username/Password Authentication](https://www.rfc-editor.org/rfc/rfc1929)

### Procedure for TCP-based clients

* wish to establish a connection
* open TCP connection to SOCKS port on the SOCKS server system
* SOCKS service: TCP port 1080
* negotiation for authentication with server chosen method
* send relay request
* server evaluates the request, establishes the connection or denies it

### Negotiation for authentication

```txt
The client connects to the server, and sends a version
identifier/method selection message:

+----+----------+----------+
|VER | NMETHODS | METHODS  |
+----+----------+----------+
| 1  |    1     | 1 to 255 |
+----+----------+----------+

The VER field is set to X'05' for this version of the protocol. 
The NMETHODS field contains the number of 
method identifier octets that appear in the METHODS field.

+----+--------+
|VER | METHOD |
+----+--------+
| 1  |   1    |
+----+--------+

If the selected METHOD is X'FF', none of the methods listed by the
client are acceptable, and the client MUST close the connection.

METHOD
o  X'00' NO AUTHENTICATION REQUIRED
o  X'01' GSSAPI
o  X'02' USERNAME/PASSWORD
o  X'03' to X'7F' IANA ASSIGNED
o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
o  X'FF' NO ACCEPTABLE METHODS
```

### Requests

```txt
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
```

### Replies

The SOCKS request information is sent by the client as soon as it has established a connection to the SOCKS server, and completed the authentication negotiations.  The server evaluates the request, and returns a reply formed as follows:

```txt
+----+-----+-------+------+----------+----------+
|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+

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
```

### Username/Password Authentication

Once the SOCKS V5 server has started, and the client has selected the Username/Password Authentication protocol, the Username/Password subnegotiation begins.  This begins with the client producing a Username/Password request:

```txt
           +----+------+----------+------+----------+
           |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
           +----+------+----------+------+----------+
           | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
           +----+------+----------+------+----------+

o  The VER field contains the current version of the subnegotiation,
which is X'01'. 
o  The ULEN field contains the length of the UNAME field that follows. 
o  The UNAME field contains the username as known to the source operating system. 
o  The PLEN field contains the length of the PASSWD field that follows. 
o  The PASSWD field contains the password association with the given UNAME.


   The server verifies the supplied UNAME and PASSWD, and sends the
   following response:

                        +----+--------+
                        |VER | STATUS |
                        +----+--------+
                        | 1  |   1    |
                        +----+--------+

   A STATUS field of X'00' indicates success. If the server returns a
   `failure' (STATUS value other than X'00') status, it MUST close the
   connection.

```

## Acknowledgement

* [Go, Socks5 on bilibili](https://www.bilibili.com/video/BV1QL4y1c74d)
* [Shadowsocks Source Code Explanation](https://space.bilibili.com/27312009/video)
* [Clowwindy - Shadowsocks](https://github.com/clowwindy/shadowsocks)
