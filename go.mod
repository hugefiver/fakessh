module github.com/hugefiver/fakessh

go 1.19

require (
	// github.com/BurntSushi/toml v1.0.0
	// github.com/pelletier/go-toml v1.9.4
	github.com/pelletier/go-toml/v2 v2.0.6
	github.com/stretchr/testify v1.8.1
	go.uber.org/zap v1.23.0
	golang.org/x/crypto v0.0.0-20220926161630-eccd6366d1be
	golang.org/x/term v0.0.0-20220919170432-7a66f970e087
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	go.uber.org/multierr v1.8.0 // indirect
	golang.org/x/sys v0.0.0-20220928140112-f11e5e49a4ec // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect; inirt
)

// replace golang.org/x/crypto => ./third/crypto
