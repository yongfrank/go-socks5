/*
 * @Author: Frank Chu
 * @Date: 2023-03-19 11:56:17
 * @LastEditors: Frank Chu
 * @LastEditTime: 2023-03-19 11:56:20
 * @FilePath: /go-socks5/code/weekday/weekday.go
 * @Description:
 *
 * Copyright (c) 2023 by ${git_name}, All Rights Reserved.
 */
package main

import (
	"fmt"
	"time"
)

func main() {
	fmt.Println("When's Monday?")
	today := time.Now().Weekday()
	switch time.Monday {
	case today + 0:
		fmt.Println("Today.")
	case today + 1:
		fmt.Println("Tomorrow.")
		fallthrough
	case today + 2:
		fmt.Println("In two days.")
	default:
		fmt.Println("Too far away.")
	}
}
