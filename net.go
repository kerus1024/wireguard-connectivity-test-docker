package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

func GetOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, err.Error())
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

func GetDefaultGateway() string {

	ip := ""

	file, err := os.Open("/proc/net/route")
	if err != nil {
		debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, err.Error())
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {

		// jump to line containing the agteway address
		for i := 0; i < 1; i++ {
			scanner.Scan()
		}

		// get field containing gateway address
		tokens := strings.Split(scanner.Text(), "\t")

		gatewayHex := "0x" + tokens[2]

		// cast hex address to uint32
		d, _ := strconv.ParseInt(gatewayHex, 0, 64)
		d32 := uint32(d)

		// make net.IP address from uint32
		ipd32 := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ipd32, d32)

		// format net.IP to dotted ipV4 string
		ip = net.IP(ipd32).String()

		// exit scanner
		break
	}

	if ip == "" {
		debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, fmt.Sprintf("Couldn't get default gateway"))
	}

	return ip
}

// func UpdateResolver() {

// 	debugMessage("Update /etc/resolv.conf")

// 	resolvConf := ""

// 	for i, server := range WireguardQuickConf.Interface.DNSs {

// 		if i >= 3 {
// 			debugMessage(fmt.Sprintf("Too many dns servers!! skip %s", server))
// 			continue
// 		}

// 		resolvConf += fmt.Sprintf("nameserver %s\n", server)
// 	}

// 	if resolvConf == "" {
// 		debugMessage("Wireguard DNS is not set")
// 		return
// 	}

// 	err := os.WriteFile("/etc/resolv.conf", []byte(resolvConf), 0644)
// 	if err != nil {
// 		debugMessage("Failed to edit /etc/resolv.conf ^,^")
// 	}

// }
