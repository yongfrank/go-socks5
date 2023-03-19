/*
 * @Author: Frank Chu
 * @Date: 2023-03-18 11:20:31
 * @LastEditors: Frank Chu
 * @LastEditTime: 2023-03-19 20:22:52
 * @FilePath: /go-socks5/code/socks5.go
 * @Description: 【Go语言手写SOCKS5服务器-05-编写认证过程】 https://www.bilibili.com/video/BV15Y411c7SU/?share_source=copy_web&vd_source=bf4952280cde801b178268abc99a7047
 *
 * Copyright (c) 2023 by ${git_name}, All Rights Reserved.
 */
package socks5

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

type Server interface {
	Run() error
}

type SOCKS5Server struct {
	IP     string
	Port   int
	Config *Config
}

func initConfig(config *Config) error {
	if config.AuthMethod == MethodPassword && config.PasswordChecker == nil {
		return ErrPasswordCheckerNotSet
	}
	return nil
}

func (s *SOCKS5Server) Run() error {
	// Initialize server configuration
	if err := initConfig(s.Config); err != nil {
		return err
	}

	// Server IP and Port
	address := fmt.Sprintf("%s:%d", s.IP, s.Port)
	log.Printf("Server is connecting to %s", address)

	// Listen specific address
	// Listen announces on the local network address.
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	log.Printf("start to listen %s", address)

	for {
		// Connect Success, three-way handshake
		conn, err2 := listener.Accept()
		log.Printf("Connecting Success")
		if err2 != nil {
			log.Printf("connection failure from %s: %s", conn.RemoteAddr(), err2)
			continue
		}

		// goroutine handle socks5 connection
		go func() {
			// delay close connetion until later time
			defer conn.Close()

			// get err from function
			if err := s.handleConnection(conn, s.Config); err != nil {
				log.Printf("handle connection failure from %s: %s", conn.RemoteAddr(), err)
			}
		}()
	}
}

func (s *SOCKS5Server) handleConnection(conn net.Conn, config *Config) error {
	// Negotiation
	log.Printf("start negotiation")
	if err := auth(conn, config); err != nil {
		return err
	}
	// Request
	log.Printf("start request")
	if err := s.request(conn); err != nil {
		return err
	}

	// forward
	// log.Printf("start forward")
	// forward(conn, targetConn)
	return nil
}

// forward
func forward(conn io.ReadWriter, targetConn io.ReadWriteCloser) error {
	defer targetConn.Close()

	go io.Copy(targetConn, conn)

	// recv, send
	_, err := io.Copy(conn, targetConn)
	return err
}

// request
func (s *SOCKS5Server) request(conn io.ReadWriter) error {
	// clientRequestMessage
	// Read client request message from connection
	clientReqMsg, err := NewClientRequestMessage(conn)

	if err != nil {
		return err
	}

	// Check if the address type is supported
	log.Printf("start check ipv6")
	if clientReqMsg.ATYP == TypeIPv6 {
		WriteRequestFailureMessage(conn, ReplyAddressTypeNotSupported)
		return ErrAddressTypeNotSupported
	}

	// Check if the command is supported
	// o  CONNECT X'01' # TCP service
	// o  BIND X'02'
	//    UDP X'03'
	if clientReqMsg.Cmd == CmdConnect {
		s.handleTCP(conn, clientReqMsg)
	} else if clientReqMsg.Cmd == CmdUDP {
		s.handleUDP()
	} else {
		WriteRequestFailureMessage(conn, ReplyCommandNotSupported)
		return ErrRequestCommandNotSupported
	}
	return nil
}

func (s *SOCKS5Server) handleUDP() {

}

func (s *SOCKS5Server) handleTCP(conn io.ReadWriter, clientReqMsg *ClientRequestMessage) error {

	// Request visit tartget TCP Service
	address := fmt.Sprintf("%s:%d", clientReqMsg.DstAddr, clientReqMsg.DstPort)
	targetConn, err := net.DialTimeout("tcp", address, s.Config.TCPTimeout)
	if err != nil {
		WriteRequestFailureMessage(conn, ReplyConnectionRefused)
		return err
	}

	// Send success reply
	// net.Addr: LocalAddr returns the local network address, if known.
	addrValue := targetConn.LocalAddr()
	addr := addrValue.(*net.TCPAddr)
	if err := WriteRequestSuccessMessage(conn, addr.IP, uint16(addr.Port)); err != nil {
		return err
	}
	return forward(conn, targetConn)
}

type Config struct {
	AuthMethod      Method
	PasswordChecker func(username, password string) bool
	TCPTimeout      time.Duration
}

// func auth(conn net.Conn) error {
func auth(conn io.ReadWriter, config *Config) error {
	// Read client auth message
	// clientAuthMethod
	clientAuthMethod, err := NewClientAuthMessage(conn)
	if err != nil {
		return err
	}
	log.Println("start: ", clientAuthMethod.Version, clientAuthMethod.NMethods, clientAuthMethod.Methods, "end.")

	// Only support no-auth
	// if cam.Methods.contains(no-auth) {
	// 	return noacceptable
	// }
	var acceptable bool
	var currentMethod byte
	for _, method := range clientAuthMethod.Methods {
		if method == config.AuthMethod {
			// if method == MethodNoAuth || method == MethodPassword {
			acceptable = true
			currentMethod = method
		}
	}

	if !acceptable {
		NewServerAuthMessage(conn, MethodNoAcceptable)
		return errors.New("not acceptable for method no auth or username/password")
	}

	// func NewServerAuthMessage(conn io.Writer, method byte) error
	if err := NewServerAuthMessage(conn, currentMethod); err != nil {
		return err
	}

	/*
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
	*/
	// if config.AuthMethod == MethodPassword {
	log.Println("currentMethod: ", currentMethod)
	if currentMethod == MethodPassword {
		clientPasswordMessage, err := NewPasswordAuthMessage(conn)
		if err != nil {
			return err
		}
		if !config.PasswordChecker(clientPasswordMessage.Username, clientPasswordMessage.Password) {
			WriteServerPasswordMessage(conn, PasswordAuthFailure)
			return ErrPasswordAuthFailure
		}
		// Auth Success
		if err = WriteServerPasswordMessage(conn, PasswordAuthSuccess); err != nil {
			return err
		}
	}
	return nil
}
