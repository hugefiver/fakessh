module github.com/hugefiver/fakessh

go 1.16

require (
	go.uber.org/zap v1.19.1
	golang.org/x/crypto v0.0.0-20211115234514-b4de73f9ece8
)

replace golang.org/x/crypto => ./third/crypto
