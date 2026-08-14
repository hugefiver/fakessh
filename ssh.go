package main

import (
	"context"
	"io"
	golog "log"
	"math/rand/v2"
	"net"
	"sync/atomic"
	"time"

	"github.com/hugefiver/fakessh/conf"
	"github.com/hugefiver/fakessh/modules/fakeshell"
	"github.com/hugefiver/fakessh/modules/gitserver"
	"github.com/hugefiver/fakessh/third/ssh"
	"github.com/samber/lo"
)

const sshHandshakeTimeout = 10 * time.Second

type Option struct {
	ServPort           string
	SSHRateLimits      []*conf.RateLimitConfig
	MaxConnections     conf.MaxConnectionsConfig
	MaxSuccConnections conf.MaxConnectionsConfig

	FakeShellConfig *fakeshell.Config

	// GitServer is the initialized gitserver.Server used to route Git SSH
	// sessions when the gitserver module is embedded and enabled. It is nil
	// when gitserver is disabled or compiled out (no_gitserver); in that
	// case the connection handler falls back to the legacy fakeshell / io-
	// copy-discard behavior for every session.
	GitServer *gitserver.Server
}

type SSHConnectionContext struct {
	net.Conn

	FakeShellConfig *fakeshell.Config

	// GitServer is the per-connection handle to the gitserver.Server (or
	// nil). It is threaded down from Option so handleConn can call
	// shouldRouteGitSession / HandleSession without a global.
	GitServer *gitserver.Server

	Connections      *atomic.Int64
	SuccConnections  *atomic.Int64
	MaxSuccConns     int64
	HardMaxSuccConns int64
	SuccLossRatio    float64
}

func (c *SSHConnectionContext) CheckMaxSuccussConnections() bool {
	return checkMaxConnections(c.SuccConnections.Add(1), c.MaxSuccConns, c.HardMaxSuccConns, c.SuccLossRatio)
}

func StartSSHServer(config *ssh.ServerConfig, opt *Option) {
	port := opt.ServPort
	if port == "" {
		port = conf.DefaultBind
	}

	pConf, gConf := lo.FilterReject(opt.SSHRateLimits, func(x *conf.RateLimitConfig, _ int) bool {
		return x.PerIP
	})
	limiter := NewSSHRateLimiter(gConf, pConf)

	if limiter.HasPerIP() {
		log.Debug("[RateLimiterClean] Start in every 5 minutes")
		go func() {
			const InitDuration = time.Minute * 5
			const MaxDuration = time.Hour

			currDuration := InitDuration
			ticker := time.NewTicker(InitDuration)
			clearCount := 0

			for range ticker.C {
				c, k := limiter.CleanEmpty()
				if c == 0 {
					clearCount++
					if k == 0 && clearCount >= 3 {
						currDuration *= 2
						if currDuration > MaxDuration {
							currDuration = MaxDuration
						}
						ticker.Reset(currDuration)
					} else if k != 0 {
						currDuration = InitDuration * 2
						ticker.Reset(currDuration)
					}
				} else {
					clearCount = 0
					currDuration = InitDuration
					ticker.Reset(currDuration)
				}
			}
		}()
	}

	// max connections
	connections := atomic.Int64{}
	maxConn := int64(opt.MaxConnections.Max)
	if maxConn == 0 {
		maxConn = conf.DefaultMaxConnections
	} else if maxConn < 0 {
		maxConn = 0
	}

	hardMaxConn := int64(opt.MaxConnections.HardMax)
	if hardMaxConn <= maxConn && maxConn > 0 {
		hardMaxConn = max(maxConn*2, conf.DefaultHardMaxConnections)
	}

	lossRatio := opt.MaxConnections.LossRatio
	if lossRatio <= 0 {
		lossRatio = 0.
	} else if lossRatio >= 1 {
		lossRatio = 1.
	}

	// max success connections
	succConnections := atomic.Int64{}
	maxSuccConn := int64(opt.MaxSuccConnections.Max)
	if maxSuccConn == 0 {
		maxSuccConn = conf.DefaultMaxSuccessConnections
	} else if maxSuccConn < 0 {
		maxSuccConn = 0
	}

	hardMaxSuccConn := int64(opt.MaxSuccConnections.HardMax)
	if hardMaxSuccConn <= maxSuccConn && maxSuccConn > 0 {
		hardMaxSuccConn = max(maxSuccConn*2, conf.DefaultHardMaxSucessConnections)
	}

	succLossRatio := opt.MaxSuccConnections.LossRatio
	if succLossRatio <= 0 {
		succLossRatio = 0.
	} else if succLossRatio >= 1 {
		succLossRatio = 1.
	}

	// Binding port
	listener, err := net.Listen("tcp", port)
	if err != nil {
		golog.Fatalf("Error on listenning to %s: %v ", port, err)
	}
	log.Warnf("[Server] SSH Server Started on %s", port)

	// Handle connects
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Debugf("[Disconnect] failed to accept connect: %v", err)
			continue
		}

		if !checkMaxConnections(connections.Add(1), maxConn, hardMaxConn, lossRatio) {
			go func() {
				disconnectWithMaxConenctions(conn)
				connections.Add(-1)
				log.Infof("[Disconnect] reached max connections limit, disconnect from: %s", conn.RemoteAddr().String())
			}()
			continue
		}

		ip := remoteIPString(conn.RemoteAddr())

		pass := limiter.Allow(ip).OK()
		if !pass {
			log.Infof("[Disconnect] out of rate limit, ip: %s", ip)
			go func() {
				disconnectWithMaxConenctions(conn)
				connections.Add(-1)
			}()
			continue
		}

		go func() {
			handleConn(&SSHConnectionContext{
				Conn:             conn,
				Connections:      &connections,
				SuccConnections:  &succConnections,
				MaxSuccConns:     maxSuccConn,
				HardMaxSuccConns: hardMaxSuccConn,
				SuccLossRatio:    succLossRatio,

				FakeShellConfig: opt.FakeShellConfig,
				GitServer:       opt.GitServer,
			}, config)
		}()
	}
}

func handleConn(sshCtx *SSHConnectionContext, config *ssh.ServerConfig) {
	defer sshCtx.Close()
	unauthenticated := true
	defer func() {
		if unauthenticated {
			sshCtx.Connections.Add(-1)
		}
	}()

	if err := sshCtx.SetDeadline(time.Now().Add(sshHandshakeTimeout)); err != nil {
		log.Debugf("[Client] failed to set pre-auth deadline for %s: %v", sshCtx.RemoteAddr().String(), err)
	}

	c, chs, reqs, err := ssh.NewServerConn(sshCtx.Conn, config)
	if c != nil {
		log.Debugf("[Client] client version is %s", c.ClientVersion())
	}

	if err != nil {
		log.Debugf("[Disconnect] ssh from %s disconnected: %v", sshCtx.RemoteAddr().String(), err)
		return
	}
	if err := sshCtx.SetDeadline(time.Time{}); err != nil {
		log.Debugf("[Client] failed to clear pre-auth deadline for %s: %v", sshCtx.RemoteAddr().String(), err)
	}

	// minus 1 for unauthenticated connection count
	sshCtx.Connections.Add(-1)
	unauthenticated = false
	ok := sshCtx.CheckMaxSuccussConnections()
	defer sshCtx.SuccConnections.Add(-1)
	if !ok {
		_ = c.Close()
		log.Infof("[Disconnect] reached max success connections, disconnect from %s", sshCtx.RemoteAddr().String())
		return
	}

	// Connection-level context. Previously the whole connection was wrapped
	// in a 10s context.WithTimeout, which is fine for honeypot fakeshell
	// sessions but actively kills long-running Git transfers (clone/fetch/
	// push of non-trivial repos routinely take longer than 10s). The new
	// behavior: a 10s idle timer gates waiting for the first session channel;
	// Git sessions then get their own pre-exec timer inside HandleSession and
	// are unbounded after exec. Non-Git/fakeshell sessions keep the old 10s
	// lifetime bound so password/success_ratio clients cannot pin success
	// slots indefinitely by opening an idle channel.
	connCtx, cancelConn := context.WithCancel(context.Background())
	defer cancelConn()

	// idleTimer fires if no session channel / global request arrives within
	// 10s of auth. It is stopped (timer.Stop) as soon as the first session
	// is accepted so long Git transfers are not bounded by it. A separate
	// idleC channel surfaces the fire; select on it below.
	const postAuthIdle = 10 * time.Second
	idleTimer := time.NewTimer(postAuthIdle)
	defer idleTimer.Stop()
	idleC := idleTimer.C

	channelCount := 0

	for {
		select {
		case ch, ok := <-chs:
			if !ok {
				return
			}
			chanType := ch.ChannelType()
			log.Debugf("[ClientNewChannel] client from %v request a new channel %s", sshCtx.RemoteAddr(), chanType)
			if channelCount < 1 && chanType == "session" {
				channel, _reqs, err := ch.Accept()
				if err != nil {
					// Accept failure: leave the channel rejected-by-
					// inaction and keep the loop going so other channels
					// / the idle timer still work.
					continue
				}

				// First session accepted: stop the idle timer so long Git
				// transfers are not killed at 10s. The connection now
				// lives until the session finishes, ctx is cancelled, or
				// the channel/request streams close.
				if !idleTimer.Stop() {
					// Stop() returns false if the timer already fired but
					// the value has not been read. Drain it so a stale
					// fire does not wake us next loop iteration. The
					// non-blocking drain pattern is from time.Timer docs.
					select {
					case <-idleTimer.C:
					default:
					}
				}
				channelCount++

				routeGit := shouldRouteGitSession(sshCtx.GitServer, c.Permissions)

				// Decide whether this session belongs to the gitserver
				// (public-key auth produced a git permission) or to the
				// legacy fakeshell/discard path. Git sessions are fully
				// driven by gitserver.HandleSession, which owns the
				// channel's request stream and lifecycle; fakeshell
				// sessions keep the old DiscardRequests + RunLoop/discard
				// behavior.
				//
				// The session helper runs in a goroutine and signals
				// sessionDone when it returns. The select below keeps
				// servicing global requests (keepalives) and rejecting
				// extra session channels while the session runs, and exits
				// when the session finishes or connCtx is cancelled.
				sessionDone := make(chan struct{})
				if routeGit {
					go func() {
						defer close(sessionDone)
						defer channel.Close()
						serveGitSession(connCtx, sshCtx.GitServer, c.Permissions, channel, _reqs, sshCtx.RemoteAddr())
					}()
				} else {
					sessionCtx, cancelSession := context.WithTimeout(connCtx, postAuthIdle)
					go func() {
						defer close(sessionDone)
						defer cancelSession()
						defer channel.Close()
						serveFakeShell(sessionCtx, sshCtx, channel, _reqs)
					}()
				}

				// Switch to the post-session-accept loop: keep handling
				// global requests and rejecting extra channels until the
				// session finishes or the connection is torn down.
				for {
					select {
					case <-sessionDone:
						return
					case <-connCtx.Done():
						return
					case ch, ok := <-chs:
						if !ok {
							return
						}
						rejectExtraChannel(ch)
					case req, ok := <-reqs:
						if !ok {
							return
						}
						log.Debugf("[ClientRequest] client from %v send a request %s", sshCtx.RemoteAddr(), req.Type)
						replyGlobalRequest(req)
					}
				}
			} else {
				rejectExtraChannel(ch)
			}
		case req, ok := <-reqs:
			if !ok {
				return
			}
			log.Debugf("[ClientRequest] client from %v send a request %s", sshCtx.RemoteAddr(), req.Type)
			replyGlobalRequest(req)
		case <-idleC:
			// Post-auth idle timeout: no session channel / global request
			// arrived within 10s. Drop the connection. This preserves the
			// previous honeypot behavior where scanners that authenticate
			// and then sit idle are reaped.
			log.Debugf("[Disconnect] post-auth idle timeout from %s", sshCtx.RemoteAddr().String())
			return
		case <-connCtx.Done():
			return
		}
	}
}

func replyGlobalRequest(req *ssh.Request) {
	if !req.WantReply {
		return
	}
	switch req.Type {
	case "keepalive@openssh.com", "no-more-sessions@openssh.com":
		_ = req.Reply(true, nil)
	default:
		_ = req.Reply(false, nil)
	}
}

// serveGitSession hands the accepted session channel off to the gitserver
// backend. It does NOT call ssh.DiscardRequests on _reqs because
// HandleSession owns the channel's request stream (it replies to env/exec
// and drains post-exec requests itself). The call blocks until the git
// session finishes (backend returns, context cancelled, or stream closed);
// when it returns the channel is closed by the caller's deferred close.
func serveGitSession(ctx context.Context, srv *gitserver.Server, perms *ssh.Permissions, channel ssh.Channel, reqs <-chan *ssh.Request, remote net.Addr) {
	if err := srv.HandleSession(ctx, perms, channel, reqs); err != nil {
		log.Debugf("[GitSession] session ended with error from %s: %v", remote.String(), err)
	}
}

// serveFakeShell preserves the legacy non-git session behavior: the channel's
// request stream is discarded (no exec/shell handling) and the data stream
// is either driven by fakeshell (when embedded + enabled) or copied to
// io.Discard until the channel closes. This is the honeypot path for
// password/success_ratio auth and for connections where no gitserver is
// configured.
//
// serveFakeShell blocks until the channel closes (EOF on Read) or ctx is
// cancelled, so the caller's sessionDone signal fires only when the session
// is truly finished. This preserves the original behavior where the fakeshell
// goroutine ran for the lifetime of the connection.
func serveFakeShell(ctx context.Context, sshCtx *SSHConnectionContext, channel ssh.Channel, _reqs <-chan *ssh.Request) {
	go func() {
		<-ctx.Done()
		_ = channel.Close()
	}()
	if _reqs != nil {
		go ssh.DiscardRequests(_reqs)
	}
	if fakeshell.Embedded && sshCtx.FakeShellConfig.Enable {
		// Run the fakeshell in the current goroutine so it owns the channel
		// for its whole lifetime; recover from panics so a buggy shell
		// cannot crash the connection handler.
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Error("[panic] module fakeshell: ", r)
				}
			}()
			shell := fakeshell.NewShell(sshCtx.FakeShellConfig, channel)
			shell.RunLoop(ctx)
		}()
		return
	}
	// No fakeshell: drain the channel until it closes or ctx is cancelled.
	// io.Copy returns when the channel's Read returns EOF (channel closed)
	// or an error. We loop because io.Copy may return on a transient error
	// that leaves the channel open.
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_, err := io.Copy(io.Discard, channel)
		if err != nil {
			return
		}
	}
}

// shouldRouteGitSession reports whether an accepted session channel should be
// handed to the gitserver backend instead of the legacy fakeshell/discard
// path. It returns true only when a gitserver.Server is configured (non-nil)
// AND the authenticated permissions were produced by the gitserver
// PublicKeyCallback (IsGitPermission). This keeps Git access strictly
// opt-in: password / success_ratio auth never produces a git permission, so
// it never reaches HandleSession, and connections without a configured
// gitserver always fall back to fakeshell.
func shouldRouteGitSession(srv *gitserver.Server, perms *ssh.Permissions) bool {
	if srv == nil {
		return false
	}
	return gitserver.IsGitPermission(perms)
}

func checkMaxConnections(curr, max, hardMax int64, ratio float64) bool {
	if max <= 0 {
		return hardMax <= 0 || curr <= hardMax
	}
	if curr <= max {
		return true
	}

	if curr > hardMax {
		return false
	}

	if ratio <= 0 {
		return curr <= hardMax
	} else if ratio >= 1 {
		return false
	}

	lossRatio := connectionLossProbability(curr, max, hardMax, ratio)
	return rand.Float64() >= lossRatio
}

func connectionLossProbability(curr, max, hardMax int64, ratio float64) float64 {
	if hardMax <= max+1 {
		return 1
	}

	increaseRatio := (1 - ratio) * (float64(curr-(max+1)) / float64(hardMax-(max+1)))
	if increaseRatio < 0 {
		increaseRatio = 0
	}

	return ratio + increaseRatio
}

func remoteIPString(addr net.Addr) string {
	switch addr := addr.(type) {
	case *net.UDPAddr:
		return addr.IP.String()
	case *net.TCPAddr:
		return addr.IP.String()
	case *net.IPAddr:
		return addr.IP.String()
	default:
		return addr.String()
	}
}

func disconnectWithMaxConenctions(conn net.Conn) {
	// notify client just like openssh does
	// see `drop_connection` of [`openssh/sshd.c`](https://github.com/openssh/openssh-portable/blob/master/sshd.c)
	const msg = "Not allowed at this time\r\n"
	_, _ = conn.Write([]byte(msg))
	_ = conn.Close()
}
