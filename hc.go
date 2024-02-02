package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/miekg/dns"
	probing "github.com/prometheus-community/pro-bing"
)

type HealthCheckResult struct {
	SuccessMessage string
	Error          error
}

func healthCheckICMP(subJobSequence int, workerNum int, job WireguardJob) *HealthCheckResult {

	jobDescrption := fmt.Sprintf("[Worker#%d,Subjob#%d,%s,%s/icmp] ", workerNum, subJobSequence, job.Profile.Interface.Address, AppConfig.HealthCheckEndpoint)

	ctx, _ := context.WithTimeout(context.Background(), AppConfig.HealthCheckRunTimeout)
	err := errors.New(jobDescrption + "ICMP ping was not run")

	retries := 0

	for err != nil && retries < AppConfig.HealthCheckRetries {
		if retries != 0 {
			err = errors.New(jobDescrption + "ICMP Ping was failed")
		}
		select {
		case <-ctx.Done():
			debugMessage(DEBUG_SHOW_STATISTICS_MESSAGE, jobDescrption+"Context Timeout Exceeded")
			return &HealthCheckResult{Error: errors.New(jobDescrption + "timeout context")}
		default:

			pinger, err := probing.NewPinger(AppConfig.HealthCheckEndpoint)
			if err != nil {
				debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, jobDescrption+err.Error())
				return &HealthCheckResult{Error: err}
			}
			debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, jobDescrption+"pinging...")
			pinger.SetPrivileged(false)

			pinger.Source = job.Profile.Interface.Address
			pinger.Interval = 250 * time.Millisecond
			pinger.Count = 3
			pinger.Timeout = 800 * time.Millisecond
			pinger.Size = 112

			pinger.OnRecv = func(pkt *probing.Packet) {
				debugMessage(DEBUG_SHOW_STATISTICS_MESSAGE, fmt.Sprintf("%sicmp_seq=%d time=%v", jobDescrption, pkt.Seq, pkt.Rtt))
			}

			isError := false

			err = pinger.Run() // Blocks until finished.
			if err != nil {
				isError = true
				debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, jobDescrption+err.Error())
			}

			if pinger.Statistics().PacketLoss >= 0.99 {
				isError = true
			} else {
				debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, jobDescrption+"ping successful")
			}

			if isError {
				retries++
				time.Sleep(AppConfig.HealthCheckInterval)
			} else {
				return &HealthCheckResult{SuccessMessage: fmt.Sprintf("%s%d bytes rtt=%dms", jobDescrption, pinger.Size, pinger.Statistics().MinRtt.Milliseconds())}
			}

		}
	}

	if err == nil {
		return &HealthCheckResult{Error: errors.New(jobDescrption + "unknown error")}
	}

	return &HealthCheckResult{Error: err}
}

func healthCheckDNS(subJobSequence int, workerNum int, job WireguardJob) *HealthCheckResult {

	jobDescrption := fmt.Sprintf("[Worker#%d,Subjob#%d,%s,%s:53/dns] ", workerNum, subJobSequence, job.Profile.Interface.Address, AppConfig.HealthCheckEndpoint)

	ctx, _ := context.WithTimeout(context.Background(), AppConfig.HealthCheckRunTimeout)
	err := errors.New(jobDescrption + "DNS query request was not run")

	retries := 0

	for err != nil && retries < AppConfig.HealthCheckRetries {
		if retries != 0 {
			err = errors.New(jobDescrption + "DNS request was failed... timeout occured")
		}
		select {
		case <-ctx.Done():
			debugMessage(DEBUG_SHOW_STATISTICS_MESSAGE, fmt.Sprintf("%sContext Timeout Exceeded", jobDescrption))
			return &HealthCheckResult{Error: errors.New(jobDescrption + "timeout context")}
		default:

			m1 := new(dns.Msg)
			m1.Id = dns.Id()
			m1.RecursionDesired = true
			m1.Question = []dns.Question{
				{Name: ".", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			}

			c := new(dns.Client)
			laddr := net.UDPAddr{
				IP: net.ParseIP(job.Profile.Interface.Address),
			}

			c.Dialer = &net.Dialer{
				Timeout:   2000 * time.Millisecond,
				LocalAddr: &laddr,
			}

			_, rtt, err := c.Exchange(m1, fmt.Sprintf("%s:%d", AppConfig.HealthCheckEndpoint, 53))
			if err != nil {
				retries++
				debugMessage(DEBUG_SHOW_ERROR_MESSAGE, jobDescrption+err.Error())
				time.Sleep(AppConfig.HealthCheckInterval)
				continue
			} else {
				return &HealthCheckResult{SuccessMessage: fmt.Sprintf("%srtt=%dms", jobDescrption, rtt.Milliseconds())}
			}

		}
	}

	if err == nil {
		return &HealthCheckResult{Error: errors.New(jobDescrption + "unknown error")}
	}

	return &HealthCheckResult{Error: err}

}

func healthCheckTCP(subJobSequence int, workerNum int, job WireguardJob) *HealthCheckResult {

	jobDescrption := fmt.Sprintf("[Worker#%d,Subjob#%d,%s,%s/tcp] ", workerNum, subJobSequence, job.Profile.Interface.Address, AppConfig.HealthCheckEndpoint)

	ctx, _ := context.WithTimeout(context.Background(), AppConfig.HealthCheckRunTimeout)
	err := errors.New(jobDescrption + "TCP Connect was not run")

	retries := 0

	for err != nil && retries < AppConfig.HealthCheckRetries {
		if retries != 0 {
			err = errors.New(jobDescrption + "TCP Connect was failed... timeout occured")
		}
		select {
		case <-ctx.Done():
			debugMessage(DEBUG_SHOW_STATISTICS_MESSAGE, jobDescrption+"Context timeout occured")
			return &HealthCheckResult{Error: errors.New(jobDescrption + "timeout context")}
		default:

			startTime := time.Now()

			client := net.Dialer{
				Timeout: AppConfig.HealthCheckTimeout,
				LocalAddr: &net.TCPAddr{
					IP: net.ParseIP(job.Profile.Interface.Address),
				},
			}
			conn, err := client.Dial("tcp", AppConfig.HealthCheckEndpoint)
			if err != nil {
				debugMessage(DEBUG_SHOW_INFO_MESSAGE, fmt.Sprintf("%s%s", jobDescrption, err.Error()))
				if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
					retries++
					time.Sleep(AppConfig.HealthCheckInterval)
					continue
				} else {
					return &HealthCheckResult{Error: err}
				}
			} else {
				conn.Close()
				rtt := time.Since(startTime)
				return &HealthCheckResult{SuccessMessage: fmt.Sprintf("%srtt=%dms", jobDescrption, rtt.Milliseconds())}
			}

		}
	}

	if err == nil {
		return &HealthCheckResult{Error: errors.New("unknown error")}
	}

	return &HealthCheckResult{Error: err}

}

func healthCheckHTTP(subJobSequence int, workerNum int, job WireguardJob) *HealthCheckResult {

	jobDescrption := fmt.Sprintf("[Worker#%d,Subjob#%d,%s,http_%s] ", workerNum, subJobSequence, job.Profile.Interface.Address, AppConfig.HealthCheckEndpoint)

	ctx, _ := context.WithTimeout(context.Background(), AppConfig.HealthCheckRunTimeout)
	err := errors.New(jobDescrption + "HTTP Request was not run")

	retries := 0

	for err != nil && retries < AppConfig.HealthCheckRetries {
		if retries != 0 {
			err = errors.New(jobDescrption + "HTTP Request was failed... timeout occured")
		}
		select {
		case <-ctx.Done():
			debugMessage(DEBUG_SHOW_STATISTICS_MESSAGE, jobDescrption+"Context timeout occured")
			return &HealthCheckResult{Error: errors.New(jobDescrption + "timeout context")}
		default:

			startTime := time.Now()

			client := http.Client{
				Timeout: AppConfig.HealthCheckTimeout,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
					DialContext: (&net.Dialer{
						LocalAddr: &net.TCPAddr{
							IP: net.ParseIP(job.Profile.Interface.Address),
						},
					}).DialContext,
					DisableKeepAlives: true,
				},
			}

			parsedUrl, err := url.Parse(AppConfig.HealthCheckEndpoint)
			if err != nil {
				return &HealthCheckResult{Error: errors.New(jobDescrption + err.Error())}
			}

			req := http.Request{
				Method: "GET",
				URL:    parsedUrl,
			}

			// NOTE: https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/
			resp, err := client.Do(&req)
			if err != nil {
				debugMessage(DEBUG_SHOW_INFO_MESSAGE, fmt.Sprintf("%s%s", jobDescrption, err.Error()))
				if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
					retries++
					time.Sleep(AppConfig.HealthCheckInterval)
				} else {
					return &HealthCheckResult{Error: err}
				}
			} else {
				defer resp.Body.Close()
				rtt := time.Since(startTime)

				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					return &HealthCheckResult{SuccessMessage: fmt.Sprintf("%srtt=%dms", jobDescrption, rtt.Milliseconds())}
				} else {
					return &HealthCheckResult{Error: errors.New(fmt.Sprintf("%sRemote server returned status code: %d, rtt=%dms", jobDescrption, resp.StatusCode, rtt.Milliseconds()))}
				}

			}

		}
	}

	if err == nil {
		return &HealthCheckResult{Error: errors.New("unknown error")}
	}

	return &HealthCheckResult{Error: err}

}
