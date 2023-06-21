package main

import (
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

	timeout := time.After(10 * time.Second)
	var channels []ssh.Channel
	// var requestChs []<-chan *ssh.Request
	for {
		select {
		case ch := <-chs:
			if ch == nil {
				continue
			}
			chanType := ch.ChannelType()
			log.Debugf("[ClientNewChannel] client from %v request a new channel %s", conn.RemoteAddr(), chanType)
			if len(channels) < 1 && chanType == "session" {
				channel, _, err := ch.Accept()
				if err == nil {
					channels = append(channels, channel)
					// requestChs = append(requestChs, requests)
				}
			} else {
				ch.Reject(ssh.Prohibited, "funck off")
			}
		case req := <-reqs:
			if req == nil {
				continue
			}
			log.Debugf("[ClientRequest] client from %v send a request %s", conn.RemoteAddr(), req.Type)
		case <-timeout:
			return
		}
	}
}
