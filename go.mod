module github.com/hugefiver/fakessh

go 1.24.0

toolchain go1.24.1

require (
	// github.com/BurntSushi/toml v1.0.0
	// github.com/pelletier/go-toml v1.9.4
	github.com/pelletier/go-toml/v2 v2.2.4
	github.com/stretchr/testify v1.11.1
	go.uber.org/zap v1.27.0
	golang.org/x/crypto v0.42.0
	golang.org/x/term v0.35.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect; inirt
)

require golang.org/x/time v0.13.0

require github.com/mitchellh/mapstructure v1.5.0

require (
	github.com/cespare/xxhash/v2 v2.3.0
	github.com/puzpuzpuz/xsync/v2 v2.5.1
	github.com/samber/lo v1.51.0
	github.com/spf13/afero v1.15.0
	golang.org/x/text v0.29.0 // indirect
)

// replace golang.org/x/crypto => ./third/crypto
