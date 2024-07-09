package main

import (
	"hash/maphash"
	"reflect"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/hugefiver/fakessh/conf"
	"github.com/puzpuzpuz/xsync/v2"
	"golang.org/x/time/rate"
)

var rateLimiterPrivateReserveNMethodFunc reflect.Value

func init() {
	rl := &rate.Limiter{}
	t := reflect.TypeOf(rl)
	m, ok := t.MethodByName("reserveN")
	if !ok {
		panic(`cannot get "reserveN" method in "rate.Limiter"`)
	}

	mt := m.Type
	if mt.NumIn() != 4 || mt.NumOut() != 1 {
		panic(`"reserveN" method in "rate.Limiter" has wrong signature: ` + mt.String())
	}

	if in := mt.In(0); in != reflect.TypeFor[*rate.Limiter]() {
		panic(`"reserveN" method in "rate.Limiter": argument 0 must be "rate.Limiter", but got ` + in.String())
	}
	if in := mt.In(1); in != reflect.TypeFor[time.Time]() {
		panic(`"reserveN" method in "rate.Limiter": argument 1 must be "time.Time", but got ` + in.String())
	}
	if in := mt.In(2); in != reflect.TypeFor[int]() {
		panic(`"reserveN" method in "rate.Limiter": argument 2 must be "int", but got ` + in.String())
	}
	if in := mt.In(3); in != reflect.TypeFor[time.Duration]() {
		panic(`"reserveN" method in "rate.Limiter": argument 3 must be "time.Duration", but got ` + in.String())
	}
	if out := mt.Out(0); out != reflect.TypeFor[rate.Reservation]() {
		panic(`"reserveN" method in "rate.Limiter": return value must be "rate.Reservation", but got ` + out.String())
	}

	fn := m.Func
	rateLimiterPrivateReserveNMethodFunc = fn
}

func callRateLimiterReserveN(r *rate.Limiter, t time.Time, n int, maxFutureReserve time.Duration) *rate.Reservation {
	ret := rateLimiterPrivateReserveNMethodFunc.Call([]reflect.Value{reflect.ValueOf(r), reflect.ValueOf(t), reflect.ValueOf(n), reflect.ValueOf(maxFutureReserve)})[0]

	x := ret.Interface().(rate.Reservation)
	return &x
}

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
		if rsv := callRateLimiterReserveN(l, now, n, 0); !rsv.OK() {
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
