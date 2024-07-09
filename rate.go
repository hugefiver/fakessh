package main

import (
	"hash/maphash"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/hugefiver/fakessh/conf"
	"github.com/puzpuzpuz/xsync/v2"
	"golang.org/x/time/rate"
)

type RateLimiter struct {
	limiters []*rate.Limiter
}

type Reservation struct {
	reservations []*rate.Reservation
	ok           bool
}

func (r Reservation) OK() bool {
	return r.ok
}

func (r Reservation) CancelAt(t time.Time) {
	for _, x := range r.reservations {
		x.CancelAt(t)
	}
}

func (r Reservation) Cancel() {
	r.CancelAt(time.Now())
}

func (r Reservation) Merge(o Reservation) Reservation {
	if !r.ok || !o.ok {
		return Reservation{ok: false}
	}

	reservations := make([]*rate.Reservation, 0, len(r.reservations)+len(o.reservations))
	return Reservation{
		reservations: append(append(reservations, r.reservations...), o.reservations...),
		ok:           true,
	}
}

func NewRateLimiter(cs []*conf.RateLimitConfig) *RateLimiter {
	rs := make([]*rate.Limiter, len(cs))

	for i, c := range cs {
		rs[i] = rate.NewLimiter(rate.Every(c.Interval.Duration()), c.Limit)
	}
	return &RateLimiter{limiters: rs}
}

func (r *RateLimiter) AllowN(n int) Reservation {
	if len(r.limiters) == 0 {
		return Reservation{ok: true}
	}

	var taken []*rate.Reservation
	now := time.Now()
	for _, l := range r.limiters {
		if rsv := l.ReserveN(now, n); !rsv.OK() {
			for _, x := range taken {
				x.CancelAt(now)
			}
			return Reservation{ok: false}
		} else {
			taken = append(taken, rsv)
		}
	}
	return Reservation{ok: true, reservations: taken}
}

func (r *RateLimiter) Allow() Reservation {
	return r.AllowN(1)
}

type SSHRateLimiter struct {
	globalConfs []*conf.RateLimitConfig
	peripConfs  []*conf.RateLimitConfig

	globalRl *RateLimiter
	peripRls *xsync.MapOf[string, *RateLimiter]
}

func hashString(seed maphash.Seed, s string) uint64 {
	h := xxhash.NewWithSeed(seedSize)

	_, _ = h.WriteString(s)
	return h.Sum64()
}

func NewSSHRateLimiter(global []*conf.RateLimitConfig, perip []*conf.RateLimitConfig) *SSHRateLimiter {
	return &SSHRateLimiter{
		globalConfs: global,
		peripConfs:  perip,
		globalRl:    NewRateLimiter(global),
		peripRls:    xsync.NewTypedMapOf[string, *RateLimiter](hashString),
	}
}

func (r *SSHRateLimiter) HasPerIP() bool {
	return len(r.peripConfs) > 0
}

func (r *SSHRateLimiter) AllowGlobal() Reservation {
	return r.globalRl.Allow()
}

func (r *SSHRateLimiter) AllowPerIP(ip string) Reservation {
	if !r.HasPerIP() {
		return Reservation{ok: true}
	}

	var rl *RateLimiter
	if v, ok := r.peripRls.Load(ip); ok {
		rl = v
	} else {
		rl = NewRateLimiter(r.peripConfs)
		rl, _ = r.peripRls.LoadOrStore(ip, rl)
	}

	return rl.Allow()
}

func (r *SSHRateLimiter) Allow(ip string) Reservation {
	rsv := r.AllowGlobal()
	if rsv.OK() && r.HasPerIP() {
		if rsv2 := r.AllowPerIP(ip); rsv2.OK() {
			return rsv.Merge(rsv2)
		}
		rsv.Cancel()
		return Reservation{ok: false}
	}

	return rsv
}

func (r *SSHRateLimiter) CleanEmpty() (int, int) {
	cleaned := 0
	kept := 0
	r.peripRls.Range(func(k string, v *RateLimiter) bool {
		ok := true
		for _, l := range v.limiters {
			if l.Tokens() < float64(l.Burst()) {
				ok = false
				break
			}
		}

		if ok {
			r.peripRls.Delete(k)
			cleaned++
		} else {
			kept++
		}
		return true
	})

	log.Debugf("[RateLimiterClean] cleaned %d, kept %d", cleaned, kept)

	return cleaned, kept
}
