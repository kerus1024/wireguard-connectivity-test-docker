package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

func healthCheckICMP(subJobSequence int, workerNum int, job WireguardJob) error {

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	err := errors.New("ICMP ping was not run")

	retries := 0

	for err != nil && retries < AppConfig.HealthCheckRetries {
		if retries != 0 {
			err = errors.New("ICMP Ping was failed")
		}
		select {
		case <-ctx.Done():

			debugMessage(DEBUG_SHOW_STATISTICS_MESSAGE, fmt.Sprintf("Worker#%d,SubJob#%d,Context Timeout Exceeded [%s->%s]", workerNum, subJobSequence, job.Profile.Interface.Address, AppConfig.HealthCheckEndpoint))

			return errors.New("timeout context")
		default:

			pinger, err := probing.NewPinger(AppConfig.HealthCheckEndpoint)
			if err != nil {
				debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, err.Error())
				return err
			}
			debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, fmt.Sprintf("Pinging to %s", AppConfig.HealthCheckEndpoint))
			pinger.SetPrivileged(false)

			pinger.Source = job.Profile.Interface.Address
			pinger.Interval = 250 * time.Millisecond
			pinger.Count = 3
			pinger.Timeout = 800 * time.Millisecond

			pinger.OnRecv = func(pkt *probing.Packet) {
				debugMessage(DEBUG_SHOW_STATISTICS_MESSAGE, fmt.Sprintf("%d bytes from %s: icmp_seq=%d time=%v\n",
					pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt))
			}

			isError := false

			err = pinger.Run() // Blocks until finished.
			if err != nil {
				isError = true
				debugMessage(DEBUG_SHOW_DEBUG_MESSAGE, err.Error())
			}

			if pinger.Statistics().PacketLoss >= 0.99 {
				isError = true
			} else {
				debugMessage(DEBUG_SHOW_STATISTICS_MESSAGE, fmt.Sprintf("Successful pinging to %s", AppConfig.HealthCheckEndpoint))
			}

			if isError {
				retries++
				time.Sleep(AppConfig.HealthCheckInterval)
			} else {
				return nil
			}

		}
	}

	if err == nil {
		return errors.New("unknown error")
	}

	return err
}
