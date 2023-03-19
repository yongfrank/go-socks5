/*
 * @Author: Frank Chu
 * @Date: 2023-03-18 18:20:48
 * @LastEditors: Frank Chu
 * @LastEditTime: 2023-03-19 20:11:41
 * @FilePath: /go-socks5/code/cmd/main.go
 * @Description:
 *
 * Copyright (c) 2023 by ${git_name}, All Rights Reserved.
 */
package main

import (
	"log"
	"sync"
	"time"

	"github.com/yongfrank/go-socks5"
)

func main() {
	users := map[string]string{
		"admin":    "123456",
		"zhangsan": "1234",
		"lisi":     "abde",
	}

	var mutex sync.Mutex

	server := socks5.SOCKS5Server{
		IP:   "localhost",
		Port: 1080,
		Config: &socks5.Config{
			AuthMethod: socks5.MethodPassword,
			PasswordChecker: func(username, password string) bool {
				mutex.Lock()
				defer mutex.Unlock()
				if pwd, findInDict := users[username]; findInDict {
					return pwd == password
				}
				return false
			},
			TCPTimeout: 5 * time.Second,
		},
	}

	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}
