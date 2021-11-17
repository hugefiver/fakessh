package main

import (
	golog "log"
	"net"

	"golang.org/x/crypto/ssh"
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

	c, _, _, err := ssh.NewServerConn(conn, config)
	if c != nil {
		log.Debugf("[Client] client version is %s", c.ClientVersion())
	}

	if err != nil {
		log.Debugf("[Disconnect] ssh from %s disconnected: %v", conn.RemoteAddr().String(), err)
		return
	}
}
