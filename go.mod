module github.com/hugefiver/fakessh

go 1.16

require (
	go.uber.org/zap v1.19.1
	golang.org/x/crypto v0.0.0-20211115234514-b4de73f9ece8
	golang.org/x/term v0.0.0-20201126162022-7de9c90e9dd1
)

// replace golang.org/x/crypto => ./third/crypto
