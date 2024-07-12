package main

import (
	"context"
	"io"
	golog "log"
	"math/rand/v2"
	"net"
	"sync/atomic"
	"time"

	"github.com/hugefiver/fakessh/conf"
	"github.com/hugefiver/fakessh/third/ssh"
	"github.com/samber/lo"
)

type Option struct {
	SSHRateLimits      []*conf.RateLimitConfig
	MaxConnections     conf.MaxConnectionsConfig
	MaxSuccConnections conf.MaxConnectionsConfig
}

type SSHConnectionContext struct {
	net.Conn

	SuccConnections  *atomic.Int64
	MaxSuccConns     int64
	HardMaxSuccConns int64
	SuccLossRatio    float64
}

func (c *SSHConnectionContext) CheckMaxConnections() bool {
	return checkMaxConnections(c.SuccConnections.Add(1), c.MaxSuccConns, c.HardMaxSuccConns, c.SuccLossRatio)
}

func StartSSHServer(config *ssh.ServerConfig, opt *Option) {
	port := cl.ServPort

	pConf, gConf := lo.FilterReject(opt.SSHRateLimits, func(x *conf.RateLimitConfig, _ int) bool {
		return x.PerIP
	})
	limiter := NewSSHRateLimiter(gConf, pConf)

	if limiter.HasPerIP() {
		log.Debug("[RateLimiterClean] Start in every 5 minutes")
		go func() {
			const InitDuration = time.Minute * 5
			const MaxDuration = time.Hour

			currDuration := InitDuration
			ticker := time.NewTicker(InitDuration)
			clearCount := 0

			for range ticker.C {
				c, k := limiter.CleanEmpty()
				if c == 0 {
					clearCount++
					if k == 0 && clearCount >= 3 {
						currDuration *= 2
						if currDuration > MaxDuration {
							currDuration = MaxDuration
						}
						ticker.Reset(currDuration)
					} else if k != 0 {
						currDuration = InitDuration * 2
						ticker.Reset(currDuration)
					}
				} else {
					clearCount = 0
					currDuration = InitDuration
					ticker.Reset(currDuration)
				}
			}
		}()
	}

	// max connections
	connections := atomic.Int64{}
	maxConn := int64(opt.MaxConnections.Max)
	if maxConn == 0 {
		maxConn = conf.DefaultMaxConnections
	} else if maxConn < 0 {
		maxConn = 0
	}

	hardMaxConn := int64(opt.MaxConnections.HardMax)
	if hardMaxConn <= 0 && maxConn > 0 {
		hardMaxConn = max(maxConn*2, conf.DefaultHardMaxConnections)
	}

	lossRatio := opt.MaxConnections.LossRatio
	if lossRatio <= 0 || lossRatio >= 1 {
		lossRatio = 1.
	}

	// max success connections
	succConnections := atomic.Int64{}
	maxSuccConn := int64(opt.MaxSuccConnections.Max)
	if maxSuccConn == 0 {
		maxSuccConn = conf.DefaultMaxSuccessConnections
	} else if maxSuccConn < 0 {
		maxSuccConn = 0
	}

	hardMaxSuccConn := int64(opt.MaxSuccConnections.HardMax)
	if hardMaxSuccConn <= 0 && maxSuccConn > 0 {
		hardMaxSuccConn = max(maxConn*2, conf.DefaultHardMaxSucessConnections)
	}

	succLossRatio := opt.MaxSuccConnections.LossRatio
	if succLossRatio <= 0 || succLossRatio >= 1 {
		succLossRatio = 1.
	}

	// Binding port
	listener, err := net.Listen("tcp", port)
	if err != nil {
		golog.Fatalf("Error on listenning to %s: %v ", port, err)
	}
	log.Warnf("[Server] SSH Server Started on %s", port)

	// Handle connects
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Debugf("[Disconnect] failed to accept connect %v : %v", conn.RemoteAddr(), err)
		}

		if !checkMaxConnections(connections.Add(1), maxConn, hardMaxConn, lossRatio) {
			_ = conn.Close()
			connections.Add(-1)
			continue
		}

		var ip string
		addr, ok := conn.RemoteAddr().(*net.TCPAddr)
		if !ok {
			ip = conn.RemoteAddr().String()
		} else {
			ip = addr.IP.String()
		}

		pass := limiter.Allow(conn.RemoteAddr().String()).OK()
		if !pass {
			log.Infof("[Disconnect] out of rate limit, ip: %s", ip)
			_ = conn.Close()
			connections.Add(-1)
			continue
		}

		go func() {
			defer connections.Add(-1)
			handleConn(&SSHConnectionContext{
				SuccConnections:  &succConnections,
				MaxSuccConns:     maxSuccConn,
				HardMaxSuccConns: hardMaxSuccConn,
				SuccLossRatio:    succLossRatio,
			}, config)
		}()
	}
}

func handleConn(sshCtx *SSHConnectionContext, config *ssh.ServerConfig) {
	defer sshCtx.Close()

	c, chs, reqs, err := ssh.NewServerConn(sshCtx.Conn, config)
	if c != nil {
		log.Debugf("[Client] client version is %s", c.ClientVersion())
	}

	if err != nil {
		log.Debugf("[Disconnect] ssh from %s disconnected: %v", sshCtx.RemoteAddr().String(), err)
		return
	}

	ok := !sshCtx.CheckMaxConnections()
	defer sshCtx.SuccConnections.Add(-1)
	if !ok {
		return
	}

	ctx, cancelFn := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelFn()

	channelCount := 0

	for {
		select {
		case ch, ok := <-chs:
			if !ok {
				return
			}
			chanType := ch.ChannelType()
			log.Debugf("[ClientNewChannel] client from %v request a new channel %s", sshCtx.RemoteAddr(), chanType)
			if channelCount < 1 && chanType == "session" {
				channel, _reqs, err := ch.Accept()
				if err == nil {
					go ssh.DiscardRequests(_reqs)
					go func() {
						for {
							_, err = io.Copy(io.Discard, channel)
							if err != nil {
								return
							}
						}
					}()
					defer channel.Close()
					channelCount++
				}
			} else {
				ch.Reject(ssh.Prohibited, "funck off")
			}
		case req, ok := <-reqs:
			if !ok {
				return
			}
			log.Debugf("[ClientRequest] client from %v send a request %s", sshCtx.RemoteAddr(), req.Type)
			if req.WantReply {
				req.Reply(true, []byte{})
			}
		case <-ctx.Done():
			return
		}
	}
}

func checkMaxConnections(curr, max, hardMax int64, rate float64) bool {
	if max <= 0 {
		return hardMax <= 0 || curr <= hardMax
	}

	if curr > hardMax {
		return false
	}

	if rate <= 0 || rate >= 1 {
		return rate <= 0
	}

	increaseRate := (1 - rate) * (float64(curr-max) / float64(hardMax-max))
	if increaseRate < 0 {
		increaseRate = 0
	}

	return rand.Float64() >= (rate + increaseRate)
}
