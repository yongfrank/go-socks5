/*
 * @Author: Frank Chu
 * @Date: 2023-03-19 12:22:33
 * @LastEditors: Frank Chu
 * @LastEditTime: 2023-03-19 17:52:53
 * @FilePath: /go-socks5/code/request_test.go
 * @Description:
 *
 * Copyright (c) 2023 by ${git_name}, All Rights Reserved.
 */
package socks5

import (
	"bytes"
	"testing"
)

func TestNewClientRequestMessage(t *testing.T) {
	tests := []struct {
		Version  byte
		Cmd      Command
		AddrType AddressType
		Address  []byte
		Port     []byte
		Error    error
		Message  ClientRequestMessage
	}{
		{
			// CmdConnect,
			// TypeIPv4,
			// []byte{0x01, 0x02, 0x03, 0x04}, // []byte{123, 35, 13, 89},
			// []byte{0x00, 0x50}},
			// nil,
			// nil,
			Version:  SOCKS5Version,
			Cmd:      CmdConnect,
			AddrType: TypeIPv4,
			Address:  []byte{0x01, 0x02, 0x03, 0x04},
			Port:     []byte{0x00, 0x50},
			Error:    nil,
			Message: ClientRequestMessage{
				Cmd:     CmdConnect,
				ATYP:    TypeIPv4,
				DstAddr: "1.2.3.4",
				DstPort: 80,
			},
		},
		{
			Version:  0x00,
			Cmd:      CmdConnect,
			AddrType: TypeIPv4,
			Address:  []byte{0x01, 0x02, 0x03, 0x04},
			Port:     []byte{0x00, 0x50},
			Error:    ErrVersionNotSupported,
			Message: ClientRequestMessage{
				Cmd:     CmdConnect,
				ATYP:    TypeIPv4,
				DstAddr: "1.2.3.4",
				DstPort: 80,
			},
		},
		{
			Version:  SOCKS5Version,
			Cmd:      CmdConnect,
			AddrType: TypeIPv4,
			Address:  []byte{0x01, 0x02, 0x03, 0x04},
			Port:     []byte{0x00, 0x50},
			Error:    nil,
			Message: ClientRequestMessage{
				Cmd:     CmdConnect,
				ATYP:    TypeIPv4,
				DstAddr: "1.2.3.4",
				DstPort: 80,
			},
		},
	}

	for _, tests := range tests {
		var buf bytes.Buffer
		buf.Write([]byte{tests.Version, tests.Cmd, ReqReservedField, tests.AddrType})
		buf.Write(tests.Address)
		buf.Write(tests.Port)

		// clientRequestMessage
		crm, err := NewClientRequestMessage(&buf)
		if err != tests.Error {
			t.Fatalf("should get error %s, but got %s\n", tests.Error, err)
		}
		if err != nil {
			return
		}
		// if reflect.DeepEqual(tests.Message, crm) {
		if *crm != tests.Message {
			t.Errorf("got %v, want %v", *crm, tests.Message)
		}
	}

}
