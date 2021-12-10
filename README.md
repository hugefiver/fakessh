# Fake SSH Server

* __可用__
* __It Does Work__

* ~~_开发中_~~
* ~~_In Developing_~~

## Why Write This

长期以来，服务器的22端口始终有人试图爆破，每次登陆都会显示有数百次失败的尝试。

一段时间之前我已经更换为密钥登陆（**建议停止口令登陆SSH而使用密钥，尤其是您正在遭受穷举的情况下**），可以说是~~基本~~没有被穷尽成功的可能，但是看着log里的记录还是很烦。

即便使用了`fail2ban`仍收效甚微，即使在每次登录失败即封禁IP一周的情况下，本月仍有千余条IP的登陆失败记录。

虽然暂时通过更换端口的方式缓解了这样的现象，但仍不能保证以后新的端口不会被爆破。

所以写这个**假的SSH服务器**。首先是迷惑攻击者认为端口仍在正常工作，然而其实是不可能入侵成功的。其次收集访问者的IP和相关信息。最终目的是分析访问者信息，形成封禁策略，可以应用于其他的服务器上。

## Usage

```text
Usage of FakeSSH:
  -A	disable anti honeypot scan
  -a	enable anti honeypot scan (default)
  -bind port
    	binding port (default ":22")
  -delay int
    	wait time for each login (ms)
  -devia int
    	deviation for wait time (ms)
  -format [plain|json]
    	log format: [plain|json] (default "plain")
  -gen
    	generate a private key to key file path
  -h	show this page
  -help
    	show this page
  -key value
    	key file path
  -level [debug|info|warning]
    	log level: [debug|info|warning] (default "info")
  -log file
    	log file
  -passwd
    	log password to file
  -type string
    	type for generate private key (default "ed25519")
  -version string
    	ssh server version (default "OpenSSH_8.2p1")
```

### key option

1. The general format is `type:option`, and the option part can leave blank.

2. Following types is available: `ed25519`, `rsa`, `ecdsa`, default is `ed25519` if it's left empty.

3. If key path is not specialed, you can set multi types, separated with `,` . For example, `rsa` | `rsa:2048` | `ecdsa:P256,rsa` | `ed25519,ecdsa` are all available, but only the first type set is used for generating mode.

4. Option for `rsa` is key size, default is `4096`.

5. Option for `ecdsa` is curve type, such as `P256`, `P384`, `P521`, and default is `P384`.
