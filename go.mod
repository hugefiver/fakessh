module github.com/hugefiver/fakessh

go 1.22

require (
	// github.com/BurntSushi/toml v1.0.0
	// github.com/pelletier/go-toml v1.9.4
	github.com/pelletier/go-toml/v2 v2.2.2
	github.com/stretchr/testify v1.9.0
	go.uber.org/zap v1.27.0
	golang.org/x/crypto v0.26.0
	golang.org/x/term v0.23.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/sys v0.23.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect; inirt
)

require golang.org/x/time v0.5.0

require github.com/mitchellh/mapstructure v1.5.0

require (
	github.com/cespare/xxhash/v2 v2.3.0
	github.com/puzpuzpuz/xsync/v2 v2.5.1
	github.com/samber/lo v1.46.0
	github.com/spf13/afero v1.11.0
	golang.org/x/text v0.17.0 // indirect
)

// replace golang.org/x/crypto => ./third/crypto
