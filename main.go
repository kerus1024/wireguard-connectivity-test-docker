package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/ini.v1"
)

const (
	DEBUG_SHOW_CRITICAL_MESSAGE = 0
	DEBUG_SHOW_ERROR_MESSAGE    = 1 << 0
	DEBUG_SHOW_INFO_MESSAGE     = 1 << 1
	DEBUG_SHOW_DEBUG_MESSAGE    = 1 << 2
	DEBUG_SHOW_CHAOS_MESSAGE    = 1 << 7

	DEBUG_SHOW_WIREGUARD_MESSAGE  = 1 << 10
	DEBUG_SHOW_STATISTICS_MESSAGE = 1 << 11
	DEBUG_DO_NOT_STOP             = 1 << 31 // 4294967295
)

// var DebugLevel = DEBUG_SHOW_WIREGUARD_MESSAGE + DEBUG_SHOW_DEBUG_MESSAGE + DEBUG_SHOW_STATISTICS_MESSAGE
var DebugLevel int // DEBUG_LEVEL

var WireguardInterfacePrefix string = "wg_" // /var/run/wireguard/%s.sock"
var WireguardProfileFilePath = "/profile.json"
var WireguardProfileDirectoryPath = "/etc/wireguard"

type ResultMessage struct {
	Status                    string          `json:"status"`
	Message                   string          `json:"message"`
	DesiredCheckCount         int             `json:"total"`
	ProceedCount              int             `json:"proceed"`
	ErrorCount                int             `json:"proceederror"`
	SucceedCount              int             `json:"succeed"`
	ActiveParallelWorkerCount int             `json:"workers"`
	Results                   json.RawMessage `json:"results"`
}

type JobResultMessage struct {
	Result  string `json:"result"`
	Message string `json:"message"`
	Label   string `json:"label,omitempty"`
}

func debugMessage(logLevel int, s string) {

	if DebugLevel&logLevel != logLevel {
		return
	}

	now := time.Now()
	//trimmed := strings.TrimSuffix(s, "\n")
	trimmed := strings.Replace(s, "\n", "", -1)
	fmt.Fprintf(os.Stderr, "[DEBUG] [%s] %s\n", now.Format("15:04:05.000"), trimmed)

}

var AppConfig struct {
	HealthCheckMethod         string        // HEALTHCHECK_METHOD
	HealthCheckEndpoint       string        // HEALTHCHECK_ENDPOINT
	HealthCheckTimeout        time.Duration // HEALTHCHECK_TIMEOUT -- Fixed in dns(2000ms) icmp(800ms)
	HealthCheckInterval       time.Duration // HEALTHCHECK_INTERVAL
	HealthCheckRetries        int           // HEALTHCHECK_RETRIES
	HealthCheckRunTimeout     time.Duration // HEALTHCHECK_RUNTIMEOUT
	RunTimeout                time.Duration // RUNTIMEOUT
	WorkerCount               int           // WORKER
	RemoteProfilePath         string        // REMOTE_PROFILE_PATH
	ActiveParallelWorkerCount int
}

var WireguardWorkersJob map[int]WireguardJobList // key=worker num

type WireguardJobList map[string][]WireguardJob // key=ipv4,
type WireguardJob struct {
	Profile WireguardQuickConf
}

type WireguardQuickConf struct {
	ProfileID       string // Not standrard
	ProfileSequence int
	Interface       struct {
		Address           string
		AddressCIDRPrefix uint8
		DNS               string
		DNSs              []string
		PrivateKey        string
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

type JobResult struct {
	ProfileID      string
	SuccessMessage string
	Error          error
}

type ErrorSuccessResult struct {
	Success      string `json:"status"`
	ErrorMessage string `json:"message"`
}

var JobResultStatus map[string]ErrorSuccessResult

var defaultGatewayAddress string

func loadProfile() (WireguardProfileList, error) {

	profileList := make(WireguardProfileList)
	var rawList WireguardProfileListRaw

	if AppConfig.RemoteProfilePath != "" {

		debugMessage(DEBUG_SHOW_INFO_MESSAGE, fmt.Sprintf("Get profile from %s", AppConfig.RemoteProfilePath))

		resp, err := http.Get(AppConfig.RemoteProfilePath)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, errors.New("the response of profile request has not returned 200")
		}

		err = json.NewDecoder(resp.Body).Decode(&rawList)
		if err != nil {
			return nil, err
		}

	} else {

		debugMessage(DEBUG_SHOW_INFO_MESSAGE, fmt.Sprintf("Try read from %s", WireguardProfileFilePath))
		data, err := ioutil.ReadFile(WireguardProfileFilePath)
		if err == nil {

			err = json.Unmarshal(data, &rawList)
			if err != nil {
				return nil, err
			}

			debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, string(data))

		} else {

			rawList = make(WireguardProfileListRaw)

			debugMessage(DEBUG_SHOW_INFO_MESSAGE, fmt.Sprintf("Try read from %s", WireguardProfileDirectoryPath))
			readdir, err := ioutil.ReadDir(WireguardProfileDirectoryPath)
			if err != nil {
				debugMessage(DEBUG_SHOW_INFO_MESSAGE, fmt.Sprintf("Cannot read %s // %s", WireguardProfileFilePath, err.Error()))
				return nil, err
			}

			for _, file := range readdir {

				if !file.IsDir() && strings.HasSuffix(file.Name(), ".conf") {
					profileId := strings.TrimSuffix(file.Name(), ".conf")
					if profileId == "" {
						return nil, errors.New("read .conf")
					}

					readData, err := ioutil.ReadFile(file.Name())
					if err != nil {
						debugMessage(DEBUG_SHOW_INFO_MESSAGE, fmt.Sprintf("Cannot read %s // %s", file.Name(), err.Error()))
						continue
					}

					rawList[profileId] = base64.StdEncoding.EncodeToString(readData)

				}

			}

			return nil, err
		}

	}

	if len(rawList) == 0 {
		return nil, errors.New("did not read any profile")
	}

	seq := 1

	for profileId, base64EncodedWireguardQuickProfile := range rawList {

		if len(profileId)+len(WireguardInterfacePrefix) > 15 {
			panic(fmt.Sprintf("ifname [%s%s] is too long", profileId, WireguardInterfacePrefix))
		}

		decodeArray, err := base64.StdEncoding.DecodeString(base64EncodedWireguardQuickProfile)
		if err != nil {
			return nil, err
		}

		cfg, err := ini.Load([]byte(decodeArray))
		if err != nil {
			debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, string(debug.Stack()))
			return nil, err
		}

		_, err = cfg.GetSection("Interface")
		if err != nil {
			return nil, err
		}

		var wgQuickConf WireguardQuickConf
		wgQuickConf.ProfileID = profileId
		wgQuickConf.ProfileSequence = seq
		profileIPAddress := cfg.Section("Interface").Key("Address").String()

		netIP, _, err := net.ParseCIDR(profileIPAddress)
		if err == nil {
			wgQuickConf.Interface.Address = netIP.String()
		} else {
			if netIP := net.ParseIP(profileIPAddress); netIP != nil {
				wgQuickConf.Interface.Address = netIP.String()
			} else {
				panic(fmt.Sprintf("Profile [%s] IP address [%s] is invalid", profileId, profileIPAddress))
			}
		}

		wgQuickConf.Interface.DNS = cfg.Section("Interface").Key("DNS").String()

		wgQuickConf.Interface.DNSs = strings.Split(wgQuickConf.Interface.DNS, ",")
		for i := range wgQuickConf.Interface.DNSs {
			wgQuickConf.Interface.DNSs[i] = strings.TrimSpace(wgQuickConf.Interface.DNSs[i])
		}
		wgQuickConf.Interface.DNS = wgQuickConf.Interface.DNSs[0]

		wgQuickConf.Interface.PrivateKey, err = convertWireguardQuickConfigurationKeyHexEncoding(cfg.Section("Interface").Key("PrivateKey").String())
		if err != nil {
			return nil, err
		}

		wgQuickConf.Peer.AllowedIPs = cfg.Section("Peer").Key("AllowedIPs").String()
		// TODO: AllowedIPs no defualt route
		wgQuickConf.Peer.AllowedIPss = strings.Split(wgQuickConf.Peer.AllowedIPs, ",")
		for i := range wgQuickConf.Peer.AllowedIPss {
			wgQuickConf.Peer.AllowedIPss[i] = strings.TrimSpace(wgQuickConf.Peer.AllowedIPss[i])
		}
		wgQuickConf.Peer.AllowedIPs = wgQuickConf.Peer.AllowedIPss[0]

		wgQuickConf.Peer.Endpoint = cfg.Section("Peer").Key("Endpoint").String()

		splitEndpoint := strings.Split(wgQuickConf.Peer.Endpoint, ":")
		wgQuickConf.Peer.EndpointIP = splitEndpoint[0]
		wgQuickConf.Peer.EndpointPort = splitEndpoint[1]

		wgQuickConf.Peer.PublicKey, err = convertWireguardQuickConfigurationKeyHexEncoding(cfg.Section("Peer").Key("PublicKey").String())
		if err != nil {
			return nil, err
		}

		profileList[profileId] = wgQuickConf
		seq++

	}

	// Check that there are duplicate wireguard interface ip addresses? Duplicated client ips are not supported
	visitedInterfaceIPAddress := make(map[string]bool)
	for _, v := range profileList {
		if _, ok := visitedInterfaceIPAddress[v.Interface.Address]; ok {
			// var resultMessage ResultMessage
			// resultMessage.Status = "error"
			// resultMessage.Message = fmt.Sprintf("Conflicts Interface Address = %s", v.Interface.Address)
			// j, err := json.Marshal(resultMessage)
			// if err != nil {
			// 	debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, err.Error())
			// } else {
			// 	fmt.Println(string(j))
			// }
			// os.Exit(1)
			debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, fmt.Sprintf("Conflicts Interface Address = %s", v.Interface.Address))
		} else {
			visitedInterfaceIPAddress[v.Interface.Address] = true
		}
	}

	return profileList, nil

}

func convertWireguardQuickConfigurationKeyHexEncoding(s string) (string, error) {

	decodeKey, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}

	hexString := hex.EncodeToString(decodeKey)
	return hexString, nil
}

func startWorker(processCh chan JobResult, wireguardProfileList WireguardProfileList) {

	debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, "Partitioning worker")

	// Flattening
	var profileList []WireguardQuickConf
	for _, v := range wireguardProfileList {
		profileList = append(profileList, v)
	}

	// Partitioning and Job Signing
	for i := 0; i < len(profileList); i++ {

		workerPartition := (i % AppConfig.WorkerCount) + 1
		wireguardProfile := profileList[i]

		assigned := false

	WorkerSetting1:

		// full scan to find duplicate EndpointIP
		for k, _ := range WireguardWorkersJob {
			if WireguardWorkersJob[k] != nil {

				if _, ok := WireguardWorkersJob[k][wireguardProfile.Peer.EndpointIP]; ok {
					debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, fmt.Sprintf("Duplicated endpoint ip [%s] detected.\n", wireguardProfile.Peer.EndpointIP))
					WireguardWorkersJob[k][wireguardProfile.Peer.EndpointIP] = append(WireguardWorkersJob[k][wireguardProfile.Peer.EndpointIP], WireguardJob{Profile: wireguardProfile})
					debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, fmt.Sprintf("Assigned Profile [%s] to Worker[%d]\n", wireguardProfile.ProfileID, k))
					assigned = true
					break WorkerSetting1
				}
			}
		}

		if assigned {
			continue
		}

	WorkerSetting2:
		// full scan to find duplicate InterfaceIP
		for k, _ := range WireguardWorkersJob {
			if WireguardWorkersJob[k] != nil {
				workerJobList, ok := WireguardWorkersJob[k]
				if ok {
					for _, jobList := range workerJobList {
						for _, job := range jobList {
							if job.Profile.Interface.Address == wireguardProfile.Interface.Address {
								debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, fmt.Sprintf("Conflicts interface ip [%s]\n", wireguardProfile.Interface.Address))
								WireguardWorkersJob[k][wireguardProfile.Peer.EndpointIP] = append(WireguardWorkersJob[k][wireguardProfile.Peer.EndpointIP], WireguardJob{Profile: wireguardProfile})
								debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, fmt.Sprintf("Assigned Profile [%s] to Worker[%d]\n", wireguardProfile.ProfileID, k))
								assigned = true
								break WorkerSetting2
							}
						}
					}
				}
			}
		}

		if assigned {
			continue
		}

		if WireguardWorkersJob[workerPartition] == nil {
			WireguardWorkersJob[workerPartition] = make(WireguardJobList)
		}

		WireguardWorkersJob[workerPartition][wireguardProfile.Peer.EndpointIP] = append(WireguardWorkersJob[workerPartition][wireguardProfile.Peer.EndpointIP], WireguardJob{Profile: wireguardProfile})

		debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, fmt.Sprintf("Assigned Profile [%s] to Worker[%d]\n", wireguardProfile.ProfileID, workerPartition))

	}

	// start
	wg := &sync.WaitGroup{}
	for workerNum, _ := range WireguardWorkersJob {

		workerJobList, ok := WireguardWorkersJob[workerNum]
		if !ok {
			continue
		}

		if len(workerJobList) == 0 {
			continue
		}

		debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, fmt.Sprintf("Start Worker #%d", workerNum))
		wg.Add(1)
		AppConfig.ActiveParallelWorkerCount++
		go workerRun(wg, workerNum, processCh, workerJobList)

	}
	wg.Wait()

	return

}

func workerRun(wg *sync.WaitGroup, workerNum int, processCh chan JobResult, wgJobList WireguardJobList) {
	defer wg.Done()
	debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, fmt.Sprintf("Running wireguard worker#%d", workerNum))

	for endpointIPAddress, _ := range wgJobList {

		for i, subJob := range wgJobList[endpointIPAddress] {
			debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, fmt.Sprintf("Run wireguard profile [%s]", subJob.Profile.ProfileID))

			var rtId int

			pid, err := wireguard(i, workerNum, subJob, &rtId)
			if DebugLevel&DEBUG_DO_NOT_STOP == DEBUG_DO_NOT_STOP {
				continue
			}

			if err != nil {
				proc, errProcess := os.FindProcess(pid)
				if errProcess == nil {
					debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, fmt.Sprintf("killing wireguard %d", pid))
					proc.Kill()
				}

				cleanWireguard(i, workerNum, subJob, &rtId)

				processCh <- JobResult{
					ProfileID: subJob.Profile.ProfileID,
					Error:     err,
				}

				continue
			}

			hr := healthCheck(i, workerNum, subJob)
			if hr.Error != nil {
				debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, hr.Error.Error())
			}

			proc, errProcess := os.FindProcess(pid)
			if errProcess == nil {
				debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, fmt.Sprintf("killing wireguard %d", pid))
				proc.Kill()
			}

			cleanWireguard(i, workerNum, subJob, &rtId)

			processCh <- JobResult{
				ProfileID:      subJob.Profile.ProfileID,
				SuccessMessage: hr.SuccessMessage,
				Error:          hr.Error,
			}

		}

	}

	debugMessage(DEBUG_SHOW_INFO_MESSAGE, fmt.Sprintf("Worker#%d has done", workerNum))

}

func wireguard(subJobSequence int, workerNum int, wgJob WireguardJob, routerTableId *int) (pid int, err error) {
	wireguardCh := make(chan error)
	wireguardSock := make(chan net.Conn)

	wireguardInterfaceName := fmt.Sprintf("%s%s", WireguardInterfacePrefix, wgJob.Profile.ProfileID)

	go func() {
		cmd := exec.Command("/bin/wireguard-go", "-f", wireguardInterfaceName)
		cmd.Env = os.Environ()
		cmd.Env = append(cmd.Env, "LOG_LEVEL=debug")
		stdout, _ := cmd.StdoutPipe()
		stderr, _ := cmd.StderrPipe()
		cmd.Start()
		pid = cmd.Process.Pid

		stdoutScanner := bufio.NewScanner(stdout)
		stderrScanner := bufio.NewScanner(stderr)
		stdoutScanner.Split(bufio.ScanLines)
		stderrScanner.Split(bufio.ScanLines)

		for {
			scanOut := stdoutScanner.Scan()
			scanErr := stderrScanner.Scan()

			flag := false

			if scanOut {
				debugMessage(DEBUG_SHOW_WIREGUARD_MESSAGE, stdoutScanner.Text())
				flag = true
			}

			if scanErr {
				debugMessage(DEBUG_SHOW_WIREGUARD_MESSAGE, stderrScanner.Text())
				flag = true
			}

			if !flag {
				break
			}

		}
		err := cmd.Wait()
		if err != nil {
			debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, err.Error())
		}

	}()

	debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, "Waiting for wireguard running up")

	go func() {
		// Check wireguard socket avaialble

		ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	Timeout:
		for {
			select {
			case <-ctx.Done():
				debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, "Timeout!!!!!!!!!!!!!")
				wireguardCh <- errors.New("context timeout")
				break Timeout
			default:
				conn, err := net.Dial("unix", fmt.Sprintf("/var/run/wireguard/%s.sock", wireguardInterfaceName))
				if err == nil {
					wireguardCh <- nil
					wireguardSock <- conn
					break Timeout
				}
				time.Sleep(50 * time.Millisecond)
			}

		}
	}()

	err = <-wireguardCh
	if err != nil {
		return
	}
	sock := <-wireguardSock
	debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, "wireguard is setting up now")
	// Setup Wireguard
	wgSetupCommand := ""
	wgSetupCommand += "set=1\n"
	wgSetupCommand += fmt.Sprintf("private_key=%s\n", wgJob.Profile.Interface.PrivateKey)
	wgSetupCommand += fmt.Sprintf("fwmark=%d\n", wgJob.Profile.ProfileSequence)
	wgSetupCommand += fmt.Sprintf("public_key=%s\n", wgJob.Profile.Peer.PublicKey)
	wgSetupCommand += fmt.Sprintf("allowed_ip=%s\n", wgJob.Profile.Peer.AllowedIPs)
	wgSetupCommand += fmt.Sprintf("endpoint=%s\n", wgJob.Profile.Peer.Endpoint)
	wgSetupCommand += "\n"
	wgSetupCommand += "get=1\n"

	_, err = sock.Write([]byte(wgSetupCommand))
	if err != nil {
		debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, err.Error())
		return
	}

	recvData := make([]byte, 512)
	n, err := sock.Read(recvData)
	if n > 0 {
		// do something with recvData[:n]
		debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, fmt.Sprintf("got data %s", recvData[:n]))

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
			err = errors.New("wireguard got error")
			return
		}

	}
	if e, ok := err.(interface{ Timeout() bool }); ok && e.Timeout() {
		// handle timeout
		debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, "sock timeout")
		return
	} else if err != nil {
		debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, "sock error")
		return
	}

	debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, "ok")

	// Tunnel Setup

	var intSetupCommand []string
	intSetupCommand = append(intSetupCommand, fmt.Sprintf("ip addr add %s/32 dev %s", wgJob.Profile.Interface.Address, wireguardInterfaceName))
	intSetupCommand = append(intSetupCommand, fmt.Sprintf("ip link set %s up", wireguardInterfaceName))

	if subJobSequence == 0 {
		intSetupCommand = append(intSetupCommand, fmt.Sprintf("ip route add %s/32 via %s metric 1", wgJob.Profile.Peer.EndpointIP, defaultGatewayAddress))
		// intSetupCommand = append(intSetupCommand, fmt.Sprintf("ip route add %s via %s metric 1", wgJob.Profile.Peer.EndpointIP, defaultGatewayAddress))
	}

	*routerTableId = (wgJob.Profile.ProfileSequence + 1000)

	intSetupCommand = append(intSetupCommand, fmt.Sprintf("ip route add default via %s dev %s table %d", wgJob.Profile.Interface.Address, wireguardInterfaceName, (*routerTableId)))
	intSetupCommand = append(intSetupCommand, fmt.Sprintf("ip rule add from %s/32 table %d", wgJob.Profile.Interface.Address, (*routerTableId)))

	for _, command := range intSetupCommand {

		debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, command)

		commandSplit := strings.Split(command, " ")
		commandPath := commandSplit[0]
		commandArgs := commandSplit[1:]

		cmd := exec.Command(commandPath, commandArgs...)
		var outb, errb bytes.Buffer
		cmd.Stdout = &outb
		cmd.Stderr = &errb
		if err = cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "out: %s", outb.String())
			fmt.Fprintf(os.Stderr, "err: %s", errb.String())
			debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, err.Error())
			return
		} else {
			if outb.Available() > 0 {
				buf := outb.String()
				if len(buf) > 0 && buf != "<nil>" {
					debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, buf)
				}
			}
		}
	}

	return

}

// shit
func cleanWireguard(subJobSequence int, workerNum int, wgJob WireguardJob, routerTableId *int) {

	var intSetupCommand []string

	wireguardInterfaceName := fmt.Sprintf("%s%s", WireguardInterfacePrefix, wgJob.Profile.ProfileID)

	intSetupCommand = append(intSetupCommand, fmt.Sprintf("ip addr delete %s/32 dev %s", wgJob.Profile.Interface.Address, wireguardInterfaceName))
	intSetupCommand = append(intSetupCommand, fmt.Sprintf("ip link delete %s", wireguardInterfaceName))

	intSetupCommand = append(intSetupCommand, fmt.Sprintf("ip route add %s/32 via %s metric 1", wgJob.Profile.Peer.EndpointIP, defaultGatewayAddress))

	if routerTableId != nil {
		intSetupCommand = append(intSetupCommand, fmt.Sprintf("ip route delete default via %s dev %s table %d", wgJob.Profile.Interface.Address, wireguardInterfaceName, (*routerTableId)))
		intSetupCommand = append(intSetupCommand, fmt.Sprintf("ip rule delete from %s/32 table %d", wgJob.Profile.Interface.Address, (*routerTableId)))
	}

	for _, command := range intSetupCommand {

		debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, command)

		commandSplit := strings.Split(command, " ")
		commandPath := commandSplit[0]
		commandArgs := commandSplit[1:]

		cmd := exec.Command(commandPath, commandArgs...)
		var outb, errb bytes.Buffer
		cmd.Stdout = &outb
		cmd.Stderr = &errb
		if err := cmd.Run(); err != nil {
			debugMessage(DEBUG_SHOW_CHAOS_MESSAGE, fmt.Sprintf("[ERROR] %s", command))
			debugMessage(DEBUG_SHOW_CHAOS_MESSAGE, fmt.Sprintf("out: %s", outb.String()))
			debugMessage(DEBUG_SHOW_CHAOS_MESSAGE, fmt.Sprintf("err: %s", errb.String()))
			debugMessage(DEBUG_SHOW_CHAOS_MESSAGE, err.Error())
		} else {
			if outb.Available() > 0 {
				buf := outb.String()
				if len(buf) > 0 && buf != "<nil>" {
					debugMessage(DEBUG_SHOW_CHAOS_MESSAGE, buf)
				}
			}
		}
	}

}

func healthCheck(subJobSequence int, workerNum int, wgJob WireguardJob) *HealthCheckResult {

	switch AppConfig.HealthCheckMethod {
	case HCMethodICMP:
		return healthCheckICMP(subJobSequence, workerNum, wgJob)
	case HCMethodDNS:
		return healthCheckDNS(subJobSequence, workerNum, wgJob)
	case HCMethodTCP:
		return healthCheckTCP(subJobSequence, workerNum, wgJob)
	case HCMethodHTTP:
		return healthCheckHTTP(subJobSequence, workerNum, wgJob)
	default:
		return &HealthCheckResult{Error: errors.New("Not implemented healthcheck method")}
	}

}

type WireguardProfileListRaw map[string]string // profile id = b64
type WireguardProfileList map[string]WireguardQuickConf

const (
	HCMethodICMP = "icmp"
	HCMethodDNS  = "dns"
	HCMethodTCP  = "tcp"
	HCMethodHTTP = "http"
)

func main() {

	initConfig()

	profileList, err := loadProfile()
	if err != nil {
		debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, err.Error())
		os.Exit(1)
	}

	debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, fmt.Sprintf("Load %d Profile\n", len(profileList)))

	chJobResult := make(chan JobResult)

	go startWorker(chJobResult, profileList)

	timeoutContext, _ := context.WithTimeout(context.Background(), AppConfig.RunTimeout)

	// Print Result
	var resultMessage ResultMessage

	resultMessage.Status = "ok"
	resultMessage.Message = "Hello, world!"
	resultMessage.DesiredCheckCount = len(profileList)

Collect:

	for i := 0; i < resultMessage.DesiredCheckCount; i++ {
		debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, fmt.Sprintf("Waiting i=%d chan", i))

		select {
		case <-timeoutContext.Done():
			var resultMessage ResultMessage

			resultMessage.Status = "error"
			resultMessage.Message = "runtimeout"

			break Collect

		case r := <-chJobResult:

			if r.Error == nil {
				JobResultStatus[r.ProfileID] = ErrorSuccessResult{
					Success:      "ok",
					ErrorMessage: r.SuccessMessage,
				}
				resultMessage.SucceedCount++
			} else {
				JobResultStatus[r.ProfileID] = ErrorSuccessResult{
					Success:      "error",
					ErrorMessage: r.Error.Error(),
				}
				resultMessage.ErrorCount++
			}

			resultMessage.ProceedCount++

		}
	}

	if resultMessage.ProceedCount != resultMessage.DesiredCheckCount {
		resultMessage.Status = "error"
	}

	if resultMessage.ErrorCount > 0 || resultMessage.ProceedCount == 0 {
		resultMessage.Status = "error"
	}

	resultMessage.ActiveParallelWorkerCount = AppConfig.ActiveParallelWorkerCount

	j, err := json.Marshal(JobResultStatus)
	if err != nil {
		debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, err.Error())
	}

	resultMessage.Results = j

	r, err := json.Marshal(resultMessage)
	if err != nil {
		debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, err.Error())
	}

	fmt.Println(string(r))

	if resultMessage.Status == "error" {
		os.Exit(1)
	}

}

func initConfig() {

	DebugLevel = DEBUG_SHOW_ERROR_MESSAGE
	DebugLevel += DEBUG_SHOW_CRITICAL_MESSAGE
	DebugLevel += DEBUG_SHOW_INFO_MESSAGE
	DebugLevel += DEBUG_SHOW_DEBUG_MESSAGE

	AppConfig.HealthCheckMethod = HCMethodICMP
	AppConfig.HealthCheckEndpoint = "1.0.0.1"
	AppConfig.HealthCheckTimeout = 3 * time.Second
	AppConfig.HealthCheckInterval = 1 * time.Second
	AppConfig.HealthCheckRunTimeout = 10 * time.Second
	AppConfig.HealthCheckRetries = 3
	AppConfig.RunTimeout = 30 * time.Second
	AppConfig.WorkerCount = 8

	if val := os.Getenv("HEALTHCHECK_METHOD"); val != "" {
		AppConfig.HealthCheckMethod = val
	}

	if val := os.Getenv("HEALTHCHECK_ENDPOINT"); val != "" {
		AppConfig.HealthCheckEndpoint = val
	}

	if val := os.Getenv("HEALTHCHECK_TIMEOUT"); val != "" {
		i, err := strconv.Atoi(val)
		if err != nil {
			debugMessage(DEBUG_SHOW_CRITICAL_MESSAGE, fmt.Sprintf("HEALTHCHECK_TIMEOUT value error %s", val))
		} else {
			AppConfig.HealthCheckTimeout = time.Duration(i * int(time.Millisecond))
		}
	}

	if val := os.Getenv("HEALTHCHECK_INTERVAL"); val != "" {
		i, err := strconv.Atoi(val)
		if err != nil {
			debugMessage(DEBUG_SHOW_CRITICAL_MESSAGE, fmt.Sprintf("HEALTHCHECK_INTERVAL value error %s", val))
		} else {
			AppConfig.HealthCheckInterval = time.Duration(i * int(time.Millisecond))
		}
	}

	if val := os.Getenv("HEALTHCHECK_RETRIES"); val != "" {
		i, err := strconv.Atoi(val)
		if err != nil {
			debugMessage(DEBUG_SHOW_CRITICAL_MESSAGE, fmt.Sprintf("HEALTHCHECK_RETRIES value error %s", val))
		} else {
			AppConfig.HealthCheckRetries = i
		}
	}

	if val := os.Getenv("HEALTHCHECK_RUNTIMEOUT"); val != "" {
		i, err := strconv.Atoi(val)
		if err != nil {
			debugMessage(DEBUG_SHOW_CRITICAL_MESSAGE, fmt.Sprintf("HEALTHCHECK_RUNTIMEOUT value error %s", val))
		} else {
			AppConfig.HealthCheckRunTimeout = time.Duration(i * int(time.Millisecond))
		}
	}

	if val := os.Getenv("RUNTIMEOUT"); val != "" {
		i, err := strconv.Atoi(val)
		if err != nil {
			debugMessage(DEBUG_SHOW_CRITICAL_MESSAGE, fmt.Sprintf("RUNTIMEOUT value error %s", val))
		} else {
			AppConfig.RunTimeout = time.Duration(i * int(time.Millisecond))
		}
	}

	if val := os.Getenv("WORKER"); val != "" {
		i, err := strconv.Atoi(val)
		if err != nil {
			debugMessage(DEBUG_SHOW_CRITICAL_MESSAGE, fmt.Sprintf("WORKER value error %s", val))
		} else {
			AppConfig.WorkerCount = i
		}
	}

	if val := os.Getenv("REMOTE_PROFILE_PATH"); val != "" {
		AppConfig.RemoteProfilePath = val
	}

	if val := os.Getenv("DEBUG_LEVEL"); val != "" {
		i, err := strconv.Atoi(val)
		if err == nil && i > 0 {
			DebugLevel = i
		}
	}

}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	WireguardWorkersJob = make(map[int]WireguardJobList)
	JobResultStatus = make(map[string]ErrorSuccessResult)
	defaultGatewayAddress = GetDefaultGateway()
}
