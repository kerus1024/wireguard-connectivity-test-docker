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
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"gopkg.in/ini.v1"
)

const (
	DEBUG_SHOW_WIREGUARD_MESSAGE  = 1 << 1
	DEBUG_SHOW_DEBUG_MESSAGE      = 1 << 2
	DEBUG_SHOW_STATISTICS_MESSAGE = 1 << 3
)

// var DebugLevel = DEBUG_SHOW_WIREGUARD_MESSAGE + DEBUG_SHOW_DEBUG_MESSAGE + DEBUG_SHOW_STATISTICS_MESSAGE
var DebugLevel = DEBUG_SHOW_DEBUG_MESSAGE + DEBUG_SHOW_STATISTICS_MESSAGE

var WireguardInterfacePrefix string = "wg_" // /var/run/wireguard/%s.sock"

type ResultMessage struct {
	Status  string          `json:"status"`
	Message string          `json:"message"`
	Results json.RawMessage `json:"results"`
}

type JobResultMessage struct {
	Result  string `json:"result"`
	Message string `json:"message"`
	Label   string `json:"label,omitempty"`
}

func debugMessage(logLevel int, s string) {

	if DebugLevel&logLevel == 0 {
		return
	}

	now := time.Now()
	//trimmed := strings.TrimSuffix(s, "\n")
	trimmed := strings.Replace(s, "\n", "", -1)
	fmt.Fprintf(os.Stderr, "[DEBUG] [%s] %s\n", now.Format("15:04:05.000"), trimmed)

}

var AppConfig struct {
	HealthCheckMethod     string
	HealthCheckEndpoint   string
	HealthCheckRetries    int
	HealthCheckInterval   time.Duration
	HealthCheckTimeout    time.Duration // Fixed in dns(2000ms) icmp(800ms)
	HealthCheckRunTimeout time.Duration
	RunTimeout            time.Duration
	WorkerCount           int
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

type JobResult struct {
	ProfileID string
	Error     error
}

type ErrorSuccessResult struct {
	Success      string `json:"status"`
	ErrorMessage string `json:"message"`
}

var JobResultStatus map[string]ErrorSuccessResult

var defaultGatewayAddress string

func loadProfile() (WireguardProfileList, error) {

	profileList := make(WireguardProfileList)

	data, err := ioutil.ReadFile("./profile.json")
	if err != nil {
		return nil, err
	}

	debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, string(data))

	var rawList WireguardProfileListRaw
	err = json.Unmarshal(data, &rawList)
	if err != nil {
		return nil, err
	}

	seq := 1

	for profileId, base64EncodedWireguardQuickProfile := range rawList {

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
		wgQuickConf.Interface.Address = cfg.Section("Interface").Key("Address").String()
		wgQuickConf.Interface.DNS = cfg.Section("Interface").Key("DNS").String()

		wgQuickConf.Interface.DNSs = strings.Split(wgQuickConf.Interface.DNS, ",")
		for i := range wgQuickConf.Interface.DNSs {
			wgQuickConf.Interface.DNSs[i] = strings.TrimSpace(wgQuickConf.Interface.DNSs[i])
		}

		wgQuickConf.Interface.PrivateKey, err = convertWireguardQuickConfigurationKeyHexEncoding(cfg.Section("Interface").Key("PrivateKey").String())
		if err != nil {
			return nil, err
		}

		wgQuickConf.Peer.AllowedIPs = cfg.Section("Peer").Key("AllowedIPs").String()
		// TODO: AllowedIPs no defualt route

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

		// full scan for find duplicate EndpointIP
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

	WorkerSetting2:
		// full scan for find duplicate InterfaceIP
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

			err = healthCheck(i, workerNum, subJob)
			if err != nil {
				debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, err.Error())
			}

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

		}

	}

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
				if DebugLevel&DEBUG_SHOW_WIREGUARD_MESSAGE != 0 {
					debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, stdoutScanner.Text())
				}
				flag = true

			}

			if scanErr {
				if DebugLevel&DEBUG_SHOW_WIREGUARD_MESSAGE != 0 {

					debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, stderrScanner.Text())
				}
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
	intSetupCommand = append(intSetupCommand, fmt.Sprintf("ip addr add %s dev %s", wgJob.Profile.Interface.Address, wireguardInterfaceName))
	intSetupCommand = append(intSetupCommand, fmt.Sprintf("ip link set %s up", wireguardInterfaceName))

	if subJobSequence == 0 {
		intSetupCommand = append(intSetupCommand, fmt.Sprintf("ip route add %s via %s metric 1", wgJob.Profile.Peer.EndpointIP, defaultGatewayAddress))
		// intSetupCommand = append(intSetupCommand, fmt.Sprintf("ip route add %s via %s metric 1", wgJob.Profile.Peer.EndpointIP, defaultGatewayAddress))
	}

	*routerTableId = (wgJob.Profile.ProfileSequence + 1000)

	intSetupCommand = append(intSetupCommand, fmt.Sprintf("ip route add default via %s dev %s table %d", wgJob.Profile.Interface.Address, wireguardInterfaceName, (*routerTableId)))
	intSetupCommand = append(intSetupCommand, fmt.Sprintf("ip rule add from %s table %d", wgJob.Profile.Interface.Address, (*routerTableId)))

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

	intSetupCommand = append(intSetupCommand, fmt.Sprintf("ip addr delete %s dev %s", wgJob.Profile.Interface.Address, wireguardInterfaceName))
	intSetupCommand = append(intSetupCommand, fmt.Sprintf("ip link delete %s", wireguardInterfaceName))

	if routerTableId != nil {
		intSetupCommand = append(intSetupCommand, fmt.Sprintf("ip route delete default via %s dev %s table %d", wgJob.Profile.Interface.Address, wireguardInterfaceName, (*routerTableId)))
		intSetupCommand = append(intSetupCommand, fmt.Sprintf("ip rule delete from %s table %d", wgJob.Profile.Interface.Address, (*routerTableId)))
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
			debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, fmt.Sprintf("[ERROR] %s", command))
			debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, fmt.Sprintf("out: %s", outb.String()))
			debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, fmt.Sprintf("err: %s", errb.String()))
			debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, err.Error())
		} else {
			if outb.Available() > 0 {
				buf := outb.String()
				if len(buf) > 0 && buf != "<nil>" {
					debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, buf)
				}
			}
		}
	}

}

func healthCheck(subJobSequence int, workerNum int, wgJob WireguardJob) error {

	switch AppConfig.HealthCheckMethod {
	case HCMethodICMP:
		err := healthCheckICMP(subJobSequence, workerNum, wgJob)
		return err
	case HCMethodDNS:
		return errors.New("Not implemented")
	case HCMethodTCP:
		return errors.New("Not implemented")
	case HCMethodHTTP:
		return errors.New("Not implemented")
	default:
		return errors.New("Unknown Health Check Method")
	}
	return nil
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

	AppConfig.HealthCheckMethod = HCMethodICMP
	AppConfig.HealthCheckEndpoint = "1.0.0.1"
	AppConfig.HealthCheckRetries = 3
	AppConfig.HealthCheckInterval = 3 * time.Second
	AppConfig.RunTimeout = 30 * time.Second
	AppConfig.WorkerCount = 128

	profileList, err := loadProfile()
	if err != nil {
		debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, err.Error())
		os.Exit(1)
	}

	debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, fmt.Sprintf("Load %d Profile\n", len(profileList)))

	chJobResult := make(chan JobResult)

	go startWorker(chJobResult, profileList)

	debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, "end")

	for i := 0; i < len(profileList); i++ {
		debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, fmt.Sprintf("Waiting i=%d chan", i))
		r := <-chJobResult

		if r.Error == nil {
			JobResultStatus[r.ProfileID] = ErrorSuccessResult{
				Success:      "ok",
				ErrorMessage: "success",
			}
		} else {
			JobResultStatus[r.ProfileID] = ErrorSuccessResult{
				Success:      "error",
				ErrorMessage: r.Error.Error(),
			}
		}
	}

	var resultMessage ResultMessage

	resultMessage.Status = "ok"
	resultMessage.Message = "Hello, world!"

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

}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	WireguardWorkersJob = make(map[int]WireguardJobList)
	JobResultStatus = make(map[string]ErrorSuccessResult)
	defaultGatewayAddress = GetDefaultGateway()
}
