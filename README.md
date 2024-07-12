# Fake SSH Server

* __可用__
* __It Does Work__

## Why Write This

Make self happy.

## How to download

Go to [release page](https://github.com/hugefiver/fakessh/releases/latest), and download the latest binary.

### How to choose

The pre-built binary files are named with `fakessh_{version}_{os}_{arch}[_minimal]`.

* `darwin` os means `macOS`.
* `amd64` arch means `x86_64`, and it may have suffix like `v2`, `v3`. `v3` means high performance but need CPU microarchitecture support, no suffix means `v1` that can run on nearly all AMD/Intel x86_64 CPUs. See [this wikipedia](https://en.wikipedia.org/wiki/X86-64#Microarchitecture_levels) for more information.
* There is a binary named `fakessh_{version}_macosuniversal` that is a universal binary of macOS containing all architectures (`amd64`, `arm64`).
* Most of us should use the `minimal` binary. It contains basic features only, but also enough for most users. And some avanced features will be added in the future, may since version `0.5.0`.

## TODO

* [x] configure file
* [ ] shell for git server
* [x] max connections
* [x] rate limit
* [ ] fake shell for log interders' actions (WIP in v0.5.0)

## Configure File

Read [this file](./conf/config.toml) for information.

## CommandLine Usage

```text
Usage of FakeSSH:
  -A    disable anti honeypot scan
  -V    show version of this binary
  -a    enable anti honeypot scan (default)
  -bind addr
        binding addr (default ":22")
  -c path
        config path
  -config path
        config path
  -delay int
        wait time for each login (ms)
  -devia int
        deviation for wait time (ms)
  -format [plain|json]
        log format: [plain|json] (default "plain")
  -gen
        generate a private key to key file path
  -h    show this page
  -help
        show this page
  -key path
        key file path, can set more than one
  -level [debug|info|warning]
        log level: [debug|info|warning] (default "info")
  -log file
        log file
  -max maxconn
        see maxconn
  -maxconn max:loss_ratio:hard_max
        max connections in format max:loss_ratio:hard_max, every value is optional means [default, 1.0, default]
  -maxsucc maxsuccconn
        see maxsuccconn
  -maxsuccconn max:loss_rate:hard_max
        max success connections in format max:loss_rate:hard_max, see maxconn
  -mc maxconn
        see maxconn
  -msc maxsuccconn
        see maxsuccconn
  -passwd
        log password to file
  -r float
        success ratio float percent age (0.0 ~ 100.0, default: 0)
  -rate interval:limit
        rate limit in format interval:limit
  -seed string
        success seed (any string)
  -try int
        max try times (default 3)
  -type string
        type for generate private key (default "ed25519")
  -user user:password
        users in format user:password, can set more than one
  -version string
        ssh server version (default "OpenSSH_9.3p1")
```

### key option

1. The general format is `type:option`, and the option part can leave blank.

2. Following types is available: `ed25519`, `rsa`, `ecdsa`, default is `ed25519` if it's left empty.

3. If key path is not specialed, you can set multi types, separated with `,` . For example, `rsa` | `rsa:2048` | `ecdsa:P256,rsa` | `ed25519,ecdsa` are all available, but only the first type set is used for generating mode.

4. Option for `rsa` is key size, default is `4096`.

5. Option for `ecdsa` is curve type, such as `P256`, `P384`, `P521`, and default is `P384`.

### max connections

You can use the commandline option `-maxconn` (or shorter `-mc`) to set the max connections, the `server.max_conn` in configure file does it the same.

And `-maxsuccconn` (shorter `-msc` or `server.max_succ_conn` in configure file) to set the max success connections, with the same syntax.

The format of `-maxconn` and `-maxsuccconn` is `max:loss_ratio:hard_max`, and the format of configure file is shown in [this file](./conf/config.toml).

It means when the count of connections mathes `max`, it will loss the connection with the ratio. And the ratio will increase literally, and it will be `1.0` when connections equal or larger than `hard_max`.

* `max` is interger, optional means `0`:
  * `max < 0` => unlimited connections, unless `hard_max`.
  * `max = 0` => use program default value, current is `100` for `maxconn` and `unlimited` for `maxsuccconn`.
* `loss_ratio` is float, optional means `0`:
  * `loss_ratio < 0` => not loss connections until it reaches `hard_max`.
  * `loss_ratio >= 0` => loss connections with the ratio.
* `hard_max` is interger, optional means `0`:
  * `hard_max <= 0` when `max < 0` => unlimited connections.
  * `hard_max <= 0` when `max >= 0` => it will be the max value of `max * 2` and default value(current if `65535`)
