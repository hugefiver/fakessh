module github.com/hugefiver/fakessh

go 1.26

require (
	// github.com/BurntSushi/toml v1.0.0
	// github.com/pelletier/go-toml v1.9.4
	github.com/pelletier/go-toml/v2 v2.4.3
	github.com/stretchr/testify v1.12.1
	go.uber.org/zap v1.28.0
	golang.org/x/crypto v0.55.0
	golang.org/x/term v0.45.0
)

require (
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/sys v0.47.0
)

require golang.org/x/time v0.15.0

require github.com/mitchellh/mapstructure v1.5.0

require go.yaml.in/yaml/v3 v3.0.5 // indirect

require (
	github.com/cespare/xxhash/v2 v2.3.0
	github.com/puzpuzpuz/xsync/v2 v2.5.1
	github.com/samber/lo v1.53.0
	github.com/spf13/afero v1.15.0
	golang.org/x/text v0.41.0 // indirect
)

// replace golang.org/x/crypto => ./third/crypto
