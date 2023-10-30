package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	probing "github.com/prometheus-community/pro-bing"
	"gopkg.in/ini.v1"
)

var WireguardInterface string = "wg0"
var WireguardControlSocket string = fmt.Sprintf("/var/run/wireguard/%s.sock", WireguardInterface)
var WireguardDaemonPID = 0

var Debug = 0

const (
	HCMethodICMP = "icmp"
	HCMethodDNS  = "dns"
	HCMethodTCP  = "tcp"
	HCMethodHTTP = "http"
)

var ConfigEnv struct {
	wgData       string
	hcMethod     string
	hcEndpoint   string
	hcAllowedIPs string
	hcRetries    uint
	hcRunTimeout time.Duration

	retryInterval time.Duration
	retries       uint

	label string
}

type ResultMessage struct {
	Result  string `json:"result"`
	Message string `json:"message"`
	Label   string `json:"label,omitempty"`
}

func tryCounts() {
	ConfigEnv.retries++

	if ConfigEnv.retries > ConfigEnv.hcRetries {
		printErrorWithMessage(errors.New("Retries exceeded"))
	}

}

func debugMessage(s string) {
	if Debug == 2 {
		return
	}
	now := time.Now()
	fmt.Fprintf(os.Stderr, "[DEBUG] [%s] %s", now.Format("15:04:05.000"), s)
	if s[len(s)-1] != '\n' {
		fmt.Fprintf(os.Stderr, "\n")
	}
}

func printSuccessWithMessage(s string) {

	j := &ResultMessage{
		Result:  "ok",
		Message: s,
	}

	if ConfigEnv.label != "" {
		j.Label = ConfigEnv.label
	}

	//u, err := json.MarshalIndent(j, "", "    ")
	u, err := json.Marshal(j)
	if err != nil {
		printErrorWithMessage(err)
	}

	fmt.Println(string(u))

	proc, err := os.FindProcess(WireguardDaemonPID)
	if err == nil {
		debugMessage(fmt.Sprintf("Killing wireguard process %d", WireguardDaemonPID))
		proc.Kill()
	}

	os.Exit(0)
}

func printErrorWithMessage(err error) {

	j := &ResultMessage{
		Result:  "error",
		Message: err.Error(),
	}

	if ConfigEnv.label != "" {
		j.Label = ConfigEnv.label
	}

	//u, err := json.MarshalIndent(j, "", "    ")
	u, err := json.Marshal(j)
	if err != nil {
		printErrorWithMessage(err)
	}

	fmt.Println(string(u))

	proc, err := os.FindProcess(WireguardDaemonPID)
	if err == nil {
		debugMessage(fmt.Sprintf("Killing wireguard process %d", WireguardDaemonPID))
		proc.Kill()
	}

	os.Exit(1)

}

func main() {

	ConfigEnv.hcMethod = os.Getenv("HEALTH_CHECK_METHOD")
	if ConfigEnv.hcMethod == "" {
		debugMessage("HCMethod is not set")
		ConfigEnv.hcMethod = "icmp"
	}

	ConfigEnv.hcEndpoint = os.Getenv("HEALTH_CHECK_ENDPOINT")
	if ConfigEnv.hcEndpoint == "" {
		debugMessage("Endpoint is not set")
		ConfigEnv.hcEndpoint = "1.0.0.1"
	}

	ConfigEnv.hcAllowedIPs = os.Getenv("HEALTH_CHECK_ALLOWEDIPS")

	i, err := strconv.Atoi(os.Getenv("RUN_TIMEOUT"))
	if err != nil {
		debugMessage("Timeout is not set")
		ConfigEnv.hcRunTimeout = 20 * time.Second
	} else {
		ConfigEnv.hcRunTimeout = time.Duration(i) * time.Second
	}

	i, err = strconv.Atoi(os.Getenv("HEALTH_CHECK_RETRIES"))
	if err != nil {
		debugMessage("Retries is not set")
		ConfigEnv.hcRetries = 5
	} else {
		ConfigEnv.hcRetries = uint(i)
	}

	ConfigEnv.retryInterval = time.Duration(int64(ConfigEnv.hcRunTimeout) / int64(ConfigEnv.hcRetries))

	decodeArray, err := base64.StdEncoding.DecodeString(os.Getenv("WG_CONFIG_DATA"))
	if err != nil {
		printErrorWithMessage(err)
	}

	ConfigEnv.label = os.Getenv("LABEL")

	if os.Getenv("DEBUG") != "" {
		Debug = 2
	}

	ctx, _ := context.WithTimeout(context.Background(), ConfigEnv.hcRunTimeout)
	var wg sync.WaitGroup
	go handleRunTimeout(&wg, ctx)

	ConfigEnv.wgData = string(decodeArray)

	debugMessage("Running wireguard")
	wireguardCh := make(chan bool, 0)

	go func() {
		cmd := exec.Command("/bin/wireguard-go", "-f", WireguardInterface)
		cmd.Env = os.Environ()
		cmd.Env = append(cmd.Env, "LOG_LEVEL=debug")
		stdout, _ := cmd.StdoutPipe()
		stderr, _ := cmd.StderrPipe()
		cmd.Start()
		WireguardDaemonPID = cmd.Process.Pid

		stdoutScanner := bufio.NewScanner(stdout)
		stderrScanner := bufio.NewScanner(stderr)
		stdoutScanner.Split(bufio.ScanLines)
		stderrScanner.Split(bufio.ScanLines)

		text := ""

		for {
			scanOut := stdoutScanner.Scan()
			scanErr := stderrScanner.Scan()

			flag := false

			if scanOut {
				text += stdoutScanner.Text()
				debugMessage(text)
				flag = true
			}

			if scanErr {
				debugMessage(stderrScanner.Text())
				flag = true
			}

			if !flag {
				break
			}

		}
		cmd.Wait()
		printErrorWithMessage(errors.New(fmt.Sprintf("Wireguard not working, %s", text)))

	}()

	debugMessage("Waiting for wireguard running up")

	go func() {
		// Check wireguard socket avaialble
		retries := 0
		for {
			debugMessage(fmt.Sprintf("Waiting for wireguard running up [%d]", retries))
			_, err := net.Dial("unix", WireguardControlSocket)
			if err == nil {
				wireguardCh <- true
				break
			}
			time.Sleep(10 * time.Millisecond)
			retries++
		}
	}()

	<-wireguardCh

	// Parse wireguard tools configuration
	parseWireguardQuickConf()

	// connect unix socket
	debugMessage("Connect unix socket")
	unixSock, err := net.Dial("unix", WireguardControlSocket)
	if err != nil {
		printErrorWithMessage(err)
	}
	setupWireguard(unixSock)

	// time.Sleep(1 * time.Second)
	UpdateResolver()

	switch ConfigEnv.hcMethod {
	case HCMethodICMP:
		wg.Add(1)
		go hcICMP(ctx)
	case HCMethodDNS:
		wg.Add(1)
		go hcDNS(ctx)
	case HCMethodTCP:
		wg.Add(1)

		if ConfigEnv.hcEndpoint == "1.0.0.1" {
			ConfigEnv.hcEndpoint = "1.0.0.1:80"
		}

		go hcTCP(ctx)
	case HCMethodHTTP:
		wg.Add(1)

		if ConfigEnv.hcEndpoint == "1.0.0.1" {
			ConfigEnv.hcEndpoint = "http://1.0.0.1/cdn-cgi/trace"
		}

		go hcHTTP(ctx)
	default:
		printErrorWithMessage(errors.New("unknown health check method"))
	}

	wg.Wait()

}

func handleRunTimeout(wg *sync.WaitGroup, ctx context.Context) {

	for {
		select {
		case <-ctx.Done():
			printErrorWithMessage(ctx.Err())
			//return
		}
	}

}

func hcICMP(ctx context.Context) {

	for {

		tryCounts()

		debugMessage("pinging")
		// pinger, err := probing.NewPinger(ConfigEnv.hcEndpoint)
		pinger, err := probing.NewPinger(ConfigEnv.hcEndpoint)
		pinger.SetPrivileged(true)
		if err != nil {
			printErrorWithMessage(err)
		}
		pinger.Interval = 250 * time.Millisecond
		pinger.Count = 3
		pinger.Timeout = 600 * time.Millisecond

		pinger.OnRecv = func(pkt *probing.Packet) {
			printSuccessWithMessage(fmt.Sprintf("%d bytes from %s: icmp_seq=%d time=%v\n",
				pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt))
		}

		err = pinger.Run() // Blocks until finished.
		if err != nil {
			printErrorWithMessage(err)
		}

		stats := pinger.Statistics()
		debugMessage(fmt.Sprintf("Addr: %s, Packet loss: %f\n", stats.Addr, stats.PacketLoss))

		time.Sleep(min(ConfigEnv.retryInterval-pinger.Timeout, 1000*time.Millisecond))
	}

}

func hcDNS(ctx context.Context) {

	for {

		tryCounts()
		debugMessage("querying dns")

		m1 := new(dns.Msg)
		m1.Id = dns.Id()
		m1.RecursionDesired = true
		m1.Question = []dns.Question{
			dns.Question{".", dns.TypeA, dns.ClassINET},
		}

		c := new(dns.Client)
		// laddr := net.UDPAddr{
		// 	IP: net.ParseIP(string(GetOutboundIP())),
		// }
		c.Dialer = &net.Dialer{
			Timeout: 1500 * time.Millisecond,
			// LocalAddr: &laddr,
		}
		_, rtt, err := c.Exchange(m1, fmt.Sprintf("%s:%d", ConfigEnv.hcEndpoint, 53))
		if err != nil {
			debugMessage(err.Error())
			time.Sleep(min(ConfigEnv.retryInterval-1500*time.Millisecond, 1000*time.Millisecond))
			continue
		}

		msec := rtt.Milliseconds()
		printSuccessWithMessage(fmt.Sprintf("resolve successful, in %dms, to %s", msec, ConfigEnv.hcEndpoint))

	}

}

func hcTCP(ctx context.Context) {
	debugMessage("Checking tcp")

	for {

		tryCounts()

		d := net.Dialer{
			Timeout: 5 * time.Second,
		}
		conn, err := d.Dial("tcp", ConfigEnv.hcEndpoint)
		if err != nil {
			// handle error
			if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
				debugMessage(err.Error())

				time.Sleep(min(ConfigEnv.retryInterval-5000*time.Millisecond, 1500*time.Millisecond))

				continue
			} else {
				printErrorWithMessage(err)
			}

		}
		conn.Close()

		printSuccessWithMessage(fmt.Sprintf("Connection succeed [%s]", conn.RemoteAddr()))
	}

}

func hcHTTP(ctx context.Context) {

	for {

		tryCounts()

		//https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/
		//https://gosamples.dev/context-deadline-exceeded/
		client := http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}

		parsedUrl, err := url.Parse(ConfigEnv.hcEndpoint)
		if err != nil {
			printErrorWithMessage(err)
		}

		req := http.Request{
			Method: "GET",
			URL:    parsedUrl,
		}

		resp, err := client.Do(&req)
		if err != nil {
			//debug.PrintStack()
			if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
				debugMessage(err.Error())
				time.Sleep(min(ConfigEnv.retryInterval-5000*time.Millisecond, 1500*time.Millisecond))
			} else {
				printErrorWithMessage(err)
			}
		}

		printSuccessWithMessage(fmt.Sprintf("The request url %s request successful [status code=%d]", parsedUrl.String(), resp.StatusCode))

	}

}

var WireguardQuickConf struct {
	Interface struct {
		Address    string
		DNS        string
		DNSs       []string
		PrivateKey string
	}
	Peer struct {
		AllowedIPs   string
		AllowedIPss  []string
		Endpoint     string
		EndpointIP   string
		EndpointPort string
		PublicKey    string
		//PresharedKey string
	}
}

func parseWireguardQuickConf() {
	cfg, err := ini.Load([]byte(ConfigEnv.wgData))
	if err != nil {
		debugMessage(string(debug.Stack()))
		printErrorWithMessage(err)
	}

	_, err = cfg.GetSection("Interface")
	if err != nil {
		printErrorWithMessage(errors.New("Not found interface conf"))
	}

	//sec.

	WireguardQuickConf.Interface.Address = cfg.Section("Interface").Key("Address").String()
	WireguardQuickConf.Interface.DNS = cfg.Section("Interface").Key("DNS").String()

	WireguardQuickConf.Interface.DNSs = strings.Split(WireguardQuickConf.Interface.DNS, ",")
	for i := range WireguardQuickConf.Interface.DNSs {
		WireguardQuickConf.Interface.DNSs[i] = strings.TrimSpace(WireguardQuickConf.Interface.DNSs[i])
	}

	WireguardQuickConf.Interface.PrivateKey = convertWireguardQuickConfigurationKeyHexEncoding(cfg.Section("Interface").Key("PrivateKey").String())

	WireguardQuickConf.Peer.AllowedIPs = cfg.Section("Peer").Key("AllowedIPs").String()
	// TODO: AllowedIPs no defualt route

	WireguardQuickConf.Peer.Endpoint = cfg.Section("Peer").Key("Endpoint").String()

	splitEndpoint := strings.Split(WireguardQuickConf.Peer.Endpoint, ":")
	WireguardQuickConf.Peer.EndpointIP = splitEndpoint[0]
	WireguardQuickConf.Peer.EndpointPort = splitEndpoint[1]

	WireguardQuickConf.Peer.PublicKey = convertWireguardQuickConfigurationKeyHexEncoding(cfg.Section("Peer").Key("PublicKey").String())

}

func convertWireguardQuickConfigurationKeyHexEncoding(s string) string {

	decodeKey, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		printErrorWithMessage(errors.New("b64 decode error" + err.Error()))
	}

	hexString := hex.EncodeToString(decodeKey)
	return hexString
}

func setupWireguard(sock net.Conn) {

	wgSetupCommand := ""
	wgSetupCommand += "set=1\n"
	wgSetupCommand += fmt.Sprintf("private_key=%s\n", WireguardQuickConf.Interface.
		PrivateKey)
	wgSetupCommand += "fwmark=51820\n"
	wgSetupCommand += fmt.Sprintf("public_key=%s\n", WireguardQuickConf.Peer.PublicKey)
	wgSetupCommand += fmt.Sprintf("allowed_ip=%s\n", WireguardQuickConf.Peer.AllowedIPs)
	wgSetupCommand += fmt.Sprintf("endpoint=%s\n", WireguardQuickConf.Peer.Endpoint)

	wgSetupCommand += "\n"

	wgSetupCommand += "get=1\n"

	go func() {

		recvData := make([]byte, 512)
		n, err := sock.Read(recvData)
		if n > 0 {
			// do something with recvData[:n]
			debugMessage(fmt.Sprintf("got data %s", recvData[:n]))

			splitRows := strings.Split(string(recvData[:n]), "\n")

			flag := false
			for _, v := range splitRows {
				if strings.HasPrefix(v, "errno=") {
					if v != "errno=0" {
						flag = true
					}
				}
			}

			if flag {
				printErrorWithMessage(errors.New("wireguard got err"))
			}

		}
		if e, ok := err.(interface{ Timeout() bool }); ok && e.Timeout() {
			// handle timeout
			debugMessage("sock timeout")
		} else if err != nil {
			// handle error
			debugMessage("sock error")
		}

	}()

	debugMessage(wgSetupCommand)
	n, err := sock.Write([]byte(wgSetupCommand))
	if err != nil {
		printErrorWithMessage(err)
	}

	debugMessage(fmt.Sprintf("Write unix socket: %d bytes", n))

	// gatherIPAddress := GetOutboundIP()
	gatherDefaultGatewayAddress := GetDefaultGateway()
	debugMessage(fmt.Sprintf("Default Gateway: %s", gatherDefaultGatewayAddress))

	var intSetupCommand []string

	intSetupCommand = append(intSetupCommand, fmt.Sprintf("ip addr add %s dev %s", WireguardQuickConf.Interface.Address, WireguardInterface))
	intSetupCommand = append(intSetupCommand, fmt.Sprintf("ip link set %s up", WireguardInterface))

	intSetupCommand = append(intSetupCommand, "ip route")
	intSetupCommand = append(intSetupCommand, "ip route delete default")
	intSetupCommand = append(intSetupCommand, fmt.Sprintf("ip route add %s/32 via %s metric 1", WireguardQuickConf.Peer.EndpointIP, gatherDefaultGatewayAddress))
	intSetupCommand = append(intSetupCommand, fmt.Sprintf("ip route replace default via %s dev %s metric 2", WireguardQuickConf.Interface.Address, WireguardInterface))

	for _, command := range intSetupCommand {

		debugMessage(command)

		commandSplit := strings.Split(command, " ")
		commandPath := commandSplit[0]
		commandArgs := commandSplit[1:]

		cmd := exec.Command(commandPath, commandArgs...)
		var outb, errb bytes.Buffer
		cmd.Stdout = &outb
		cmd.Stderr = &errb
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "out: %s", outb.String())
			fmt.Fprintf(os.Stderr, "err: %s", errb.String())
			printErrorWithMessage(err)
		} else {
			if outb.Available() > 0 {
				buf := outb.String()
				if len(buf) > 0 && buf != "<nil>" {
					debugMessage(buf)
				}
			}
		}

	}

}

// https://stackoverflow.com/questions/23558425/how-do-i-get-the-local-ip-address-in-go
func GetOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		printErrorWithMessage(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

func GetDefaultGateway() string {

	ip := ""

	file, err := os.Open("/proc/net/route")
	if err != nil {
		printErrorWithMessage(err)
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
		printErrorWithMessage(errors.New(fmt.Sprintf("Couldn't get default gateway")))
	}

	return ip
}

func UpdateResolver() {

	debugMessage("Update /etc/resolv.conf")

	resolvConf := ""

	for i, server := range WireguardQuickConf.Interface.DNSs {

		if i >= 3 {
			debugMessage(fmt.Sprintf("Too many dns servers!! skip %s", server))
			continue
		}

		resolvConf += fmt.Sprintf("nameserver %s\n", server)
	}

	if resolvConf == "" {
		debugMessage("Wireguard DNS is not set")
		return
	}

	err := os.WriteFile("/etc/resolv.conf", []byte(resolvConf), 0644)
	if err != nil {
		debugMessage("Failed to edit /etc/resolv.conf ^,^")
	}

}
