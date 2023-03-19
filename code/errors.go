/*
 * @Author: Frank Chu
 * @Date: 2023-03-19 11:29:03
 * @LastEditors: Frank Chu
 * @LastEditTime: 2023-03-19 19:45:31
 * @FilePath: /go-socks5/code/errors.go
 * @Description:
 *
 * Copyright (c) 2023 by ${git_name}, All Rights Reserved.
 */
package socks5

import "errors"

var (
	ErrPasswordCheckerNotSet       = errors.New("password checker not set")
	ErrVersionNotSupported         = errors.New("protocol version is not supported, see more on https://www.rfc-editor.org/rfc/rfc1928")
	ErrMethodVersionNotSupported   = errors.New("username password authentication version is not supported")
	ErrPasswordAuthFailure         = errors.New("current in password mode: username / password wrong")
	ErrRequestCommandNotSupported  = errors.New("request command not supported")
	ErrRequestReservedFieldNotZero = errors.New("request reserved field is not zero")
	ErrAddressTypeNotSupported     = errors.New("request address type not supported")
)
