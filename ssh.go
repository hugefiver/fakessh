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
			log.Errorf("[ConnectError] failed to accept connect %s : %v", conn.RemoteAddr().String(), err)
		}
		go handleConn(conn, config)
	}
}

func handleConn(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()

	_, _, _, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Errorf("[ConnectError] failed to ssh shake hands for %s : %v", conn.RemoteAddr().String(), err)
	}

}
