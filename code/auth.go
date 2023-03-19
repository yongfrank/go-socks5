/*
 * @Author: Frank Chu
 * @Date: 2023-03-18 16:59:22
 * @LastEditors: Frank Chu
 * @LastEditTime: 2023-03-19 18:28:16
 * @FilePath: /go-socks5/code/auth.go
 * @Description:
 *
 * Copyright (c) 2023 by ${git_name}, All Rights Reserved.
 */

package socks5

import (
	"errors"
	"io"
)

type ClientAuthMessage struct {
	Version  byte
	NMethods byte
	Methods  []Method
}

type Method = byte

const (
	MethodNoAuth       Method = 0x00
	MethodGSSAPI       Method = 0x01
	MethodPassword     Method = 0x02
	MethodNoAcceptable Method = 0xFF
)

func NewClientAuthMessage(conn io.Reader) (*ClientAuthMessage, error) {

	// Read version, nMedthods
	buf := make([]byte, 2)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}

	// Validate Version
	if buf[0] != SOCKS5Version {
		return nil, ErrVersionNotSupported
	}

	nmethods := buf[1]
	buf = make([]byte, nmethods)
	_, err2 := io.ReadFull(conn, buf)
	if err2 != nil {
		return nil, errors.New("read nmethods failed")
	}

	return &ClientAuthMessage{
		Version:  SOCKS5Version,
		NMethods: nmethods,
		Methods:  buf,
	}, nil
}

func NewServerAuthMessage(conn io.Writer, method Method) error {
	buf := []byte{SOCKS5Version, method}
	_, err := conn.Write(buf)
	return err
}

/*
o  The VER field contains the current version of the subnegotiation,
which is X'01'.
o  The ULEN field contains the length of the UNAME field that follows.
o  The UNAME field contains the username as known to the source operating system.
o  The PLEN field contains the length of the PASSWD field that follows.
o  The PASSWD field contains the password association with the given UNAME.

	+----+------+----------+------+----------+
	|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
	+----+------+----------+------+----------+
	| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
	+----+------+----------+------+----------+
*/
const (
	PasswordMethodVersion = 0x01
	PasswordAuthSuccess   = 0x00
	PasswordAuthFailure   = 0x01
)

func NewPasswordAuthMessage(conn io.Reader) (*ClientPasswordMessage, error) {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	version, usernameLen := buf[0], buf[1]
	if version != PasswordMethodVersion {
		return nil, ErrMethodVersionNotSupported
	}

	// Read username
	buf = make([]byte, usernameLen+1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	username, passwordLen := string(buf[:len(buf)-1]), buf[len(buf)-1]

	// if len(buf) < int(passwordLen) {
	buf = make([]byte, passwordLen)
	// }
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	return &ClientPasswordMessage{
		Username: username,
		Password: string(buf[:passwordLen]),
	}, nil
}

type ClientPasswordMessage struct {
	Username string
	Password string
}

func WriteServerPasswordMessage(conn io.Writer, status byte) error {
	_, err := conn.Write([]byte{PasswordMethodVersion, status})
	return err
}
