package main

import (
	"context"
	"io"
	golog "log"
	"net"
	"time"

	"github.com/hugefiver/fakessh/conf"
	"github.com/hugefiver/fakessh/third/ssh"
	"github.com/samber/lo"
)

type Option struct {
	SSHRateLimits []*conf.RateLimitConfig
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
			continue
		}

		go handleConn(conn, config)
	}
}

func handleConn(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()

	c, chs, reqs, err := ssh.NewServerConn(conn, config)
	if c != nil {
		log.Debugf("[Client] client version is %s", c.ClientVersion())
	}

	if err != nil {
		log.Debugf("[Disconnect] ssh from %s disconnected: %v", conn.RemoteAddr().String(), err)
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
			log.Debugf("[ClientNewChannel] client from %v request a new channel %s", conn.RemoteAddr(), chanType)
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
			log.Debugf("[ClientRequest] client from %v send a request %s", conn.RemoteAddr(), req.Type)
			if req.WantReply {
				req.Reply(true, []byte{})
			}
		case <-ctx.Done():
			return
		}
	}
}
