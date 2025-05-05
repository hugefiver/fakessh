module github.com/hugefiver/fakessh

go 1.24

toolchain go1.24.1

require (
	// github.com/BurntSushi/toml v1.0.0
	// github.com/pelletier/go-toml v1.9.4
	github.com/pelletier/go-toml/v2 v2.2.4
	github.com/stretchr/testify v1.10.0
	go.uber.org/zap v1.27.0
	golang.org/x/crypto v0.37.0
	golang.org/x/term v0.32.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect; inirt
)

require golang.org/x/time v0.11.0

require github.com/mitchellh/mapstructure v1.5.0

require (
	github.com/cespare/xxhash/v2 v2.3.0
	github.com/puzpuzpuz/xsync/v2 v2.5.1
	github.com/samber/lo v1.50.0
	github.com/spf13/afero v1.14.0
	golang.org/x/text v0.24.0 // indirect
)

// replace golang.org/x/crypto => ./third/crypto
