package main

import (
	"context"
	"io"
	golog "log"
	"net"
	"time"

	"github.com/hugefiver/fakessh/third/ssh"
)

func StartSSHServer(config *ssh.ServerConfig) {
	port := cl.ServPort

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
