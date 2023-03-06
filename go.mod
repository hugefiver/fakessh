module github.com/hugefiver/fakessh

go 1.19

require (
	// github.com/BurntSushi/toml v1.0.0
	// github.com/pelletier/go-toml v1.9.4
	github.com/pelletier/go-toml/v2 v2.0.7
	github.com/stretchr/testify v1.8.2
	go.uber.org/zap v1.24.0
	golang.org/x/crypto v0.7.0
	golang.org/x/term v0.6.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	go.uber.org/multierr v1.8.0 // indirect
	golang.org/x/sys v0.6.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect; inirt
)

// replace golang.org/x/crypto => ./third/crypto
