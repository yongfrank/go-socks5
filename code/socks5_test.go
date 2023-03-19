/*
 * @Author: Frank Chu
 * @Date: 2023-03-19 15:26:11
 * @LastEditors: Frank Chu
 * @LastEditTime: 2023-03-19 15:30:45
 * @FilePath: /go-socks5/code/socks5_test.go
 * @Description:
 *
 * Copyright (c) 2023 by ${git_name}, All Rights Reserved.
 */
package socks5

import (
	"bytes"
	"net"
	"reflect"
	"testing"
)

func TestAuth(t *testing.T) {
	config := Config {
		AuthMethod: MethodNoAuth,
	}
	t.Run("should pass", func(t *testing.T) {
		var buf bytes.Buffer
		buf.Write([]byte{SOCKS5Version, 2, MethodNoAuth, MethodGSSAPI})
		err := auth(&buf, &config)
		if err != nil {
			t.Fatalf("should get error nil but got %s", err)
		}

		want := []byte{SOCKS5Version, MethodNoAuth}
		got := buf.Bytes()
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("should get message %v, but got %v", want, got)
		}
	})

	t.Run("an invalid client auth message", func(t *testing.T) {
		var buf bytes.Buffer
		buf.Write([]byte{SOCKS5Version, 2, MethodNoAuth})
		if err := auth(&buf, &config); err == nil {
			t.Fatalf("should get error EOF but got nil")
		}
	})
}

func TestWriteRequestSuccessMessage(t *testing.T) {
	var buf bytes.Buffer

	// byte IP
	byteIP := []byte{123, 123, 123, 123}
	ip := net.IP(byteIP)
	err := WriteRequestSuccessMessage(&buf, ip, 1234)
	if err != nil {
		t.Fatalf("should get error nil but got %s", err)
	}
	
	want := []byte{SOCKS5Version, ReplySuccess, ReqReservedField, TypeIPv4, 123, 123, 123, 123, 4, 0xd2}
	got := buf.Bytes()
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("should get message %v, but got %v", want, got)
	}
}
