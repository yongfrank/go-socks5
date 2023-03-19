/*
 * @Author: Frank Chu
 * @Date: 2023-03-18 17:42:34
 * @LastEditors: Frank Chu
 * @LastEditTime: 2023-03-19 18:01:08
 * @FilePath: /go-socks5/code/auth_test.go
 * @Description:
 *
 * Copyright (c) 2023 by ${git_name}, All Rights Reserved.
 */
package socks5

import (
	"bytes"
	"reflect"
	"testing"
)

func TestNewClientAuthMessage(t *testing.T) {
	t.Run("should generate a message", func(t *testing.T) {
		b := []byte{SOCKS5Version, 2, MethodNoAuth, MethodGSSAPI}
		r := bytes.NewReader(b)

		// func NewClientAuthMessage(conn io.Reader) (*ClientAuthMessage, error)
		cam, err := NewClientAuthMessage(r)
		if err != nil {
			t.Fatalf("want error = nil, but get %s", err)
		}
		if cam.Version != SOCKS5Version {
			t.Fatalf("want socks5version but got %d", cam.Version)
		}
		if cam.NMethods != 2 {
			t.Fatalf("want methods = 2 but got %d", cam.NMethods)
		}
		if !reflect.DeepEqual(cam.Methods, []byte{MethodNoAuth, MethodGSSAPI}) {
			t.Fatalf("want methods: %v, but got %v", []byte{MethodNoAuth, MethodGSSAPI}, cam.Methods)
		}
	})

	t.Run("methods length is shorter than nmethods", func(t *testing.T) {
		b := []byte{SOCKS5Version, 2, MethodNoAuth}
		r := bytes.NewReader(b)

		// func NewClientAuthMessage(conn io.Reader) (*ClientAuthMessage, error)
		_, err := NewClientAuthMessage(r)
		if err == nil {
			t.Fatalf("should get error but got nil")
		}
	})
}

func TestNewServerAuthMessage(t *testing.T) {
	t.Run("should pass", func(t *testing.T) {
		var buf bytes.Buffer
		err := NewServerAuthMessage(&buf, MethodNoAuth)
		if err != nil {
			t.Fatalf("should get nil error but got %s", err)
		}
		got := buf.Bytes()
		if !reflect.DeepEqual(got, []byte{SOCKS5Version, MethodNoAuth}) {
			t.Fatalf("should send %v, but send %v", []byte{SOCKS5Version, MethodNoAuth}, got)
		}
	})

	t.Run("should send no acceptable", func(t *testing.T) {
		var buf bytes.Buffer
		err := NewServerAuthMessage(&buf, MethodNoAcceptable)
		if err != nil {
			t.Fatalf("should get nil error, but got %s", err)
		}
		got := buf.Bytes()
		ideal := []byte{SOCKS5Version, MethodNoAcceptable}
		if !reflect.DeepEqual(got, ideal) {
			t.Fatalf("should send %v, but sent %v", ideal, got)
		}
	})
}

/*
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
*/
func TestNewClientPasswordMessage(t *testing.T) {

	tests := []struct {
		Ver      byte
		ULen     byte
		username string
		Plen     byte
		password string
		Error    error
		Message  ClientPasswordMessage
	}{
		{
			PasswordMethodVersion, 5, "admin", 6, "123456", nil,
			ClientPasswordMessage{"admin", "123456"},
		},
		{
			PasswordMethodVersion, 5, "admin", 6, "123456", nil,
			ClientPasswordMessage{"admin", "123456"},
		},
		{
			PasswordMethodVersion, 6, "admind", 7, "1234567", nil,
			ClientPasswordMessage{"admind", "1234567"},
		},
		{
			PasswordMethodVersion, 6, "frakie", 7, "1234567", nil,
			ClientPasswordMessage{"frakie", "1234567"},
		},
		{
			PasswordMethodVersion, 8, "12345678", 10, "1234567890", nil,
			ClientPasswordMessage{"12345678", "1234567890"},
		},
	}

	for _, test := range tests {
		var buf bytes.Buffer
		buf.Write([]byte{test.Ver, test.ULen})
		buf.WriteString(test.username)
		buf.WriteByte(test.Plen)
		buf.WriteString(test.password)

		clientPasswordMessage, err := NewPasswordAuthMessage(&buf)
		if err != test.Error {
			t.Fatalf("want error = nil, but get %s", err)
		}
		if err != nil {
			return
		}
		// if !reflect.DeepEqual(*clientPasswordMessage, test.Message) {
		if *clientPasswordMessage != test.Message {
			t.Fatalf("want message: %v, but got %v", test.Message, *clientPasswordMessage)
		}
	}
	// t.Run("valid password auth message", func(t *testing.T) {

	// })
}
