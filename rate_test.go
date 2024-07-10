package main

import (
	"testing"
	"time"

	"github.com/hugefiver/fakessh/conf"
)

func TestRateLimiter(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter([]*conf.RateLimitConfig{
		{Limit: 3, Interval: conf.Duration(time.Second)},
		{Limit: 5, Interval: conf.Duration(time.Second * 10)},
	})

	r1 := rl.Allow()
	r2 := rl.Allow()
	r3 := rl.Allow()

	t.Logf("reservations: %#v, %#v, %#v", r1.reservations, r2.reservations, r3.reservations)
	if !r1.OK() || !r2.OK() || !r3.OK() {
		t.Errorf("r1: %v, r2: %v, r3: %v", r1.ok, r2.ok, r3.ok)
	}

	re := rl.Allow()
	if re.OK() {
		t.Errorf("re: %v", re)
	}

	time.Sleep(time.Second * 1)

	r4 := rl.Allow()
	r5 := rl.Allow()
	r6 := rl.Allow()

	t.Logf("reservations: %#v, %#v, %#v", r4.reservations, r5.reservations, r6.reservations)
	if !r4.OK() || !r5.OK() || r6.OK() {
		t.Errorf("r4: %v, r5: %v, r6: %v", r4.ok, r5.ok, r6.ok)
	}
}

func TestSSHRateLimiter(t *testing.T) {
	t.Parallel()

	rl := NewSSHRateLimiter([]*conf.RateLimitConfig{
		{Limit: 3, Interval: conf.Duration(time.Second)},
		{Limit: 5, Interval: conf.Duration(time.Second * 10)},
	}, []*conf.RateLimitConfig{
		{Limit: 1, Interval: conf.Duration(time.Second), PerIP: true},
	})

	x1 := rl.Allow("1")
	x2 := rl.Allow("1")

	if !x1.OK() || x2.OK() {
		t.Errorf("x1: %v, x2: %v", x1, x2)
	}

	y1 := rl.Allow("2")
	y2 := rl.Allow("2")

	if !y1.OK() || y2.OK() {
		t.Errorf("y1: %v, y2: %v", y1, y2)
	}

	z1 := rl.Allow("3")
	z2 := rl.Allow("3")

	if !z1.OK() || z2.OK() {
		t.Errorf("z1: %v, z2: %v", z1, z2)
	}

	time.Sleep(time.Second * 1)

	x3 := rl.Allow("1")

	if !x3.OK() {
		t.Errorf("x3: %v", x3)
	}

	y3 := rl.Allow("2")

	if !y3.OK() {
		t.Errorf("y3: %v", y3)
	}

	z3 := rl.Allow("3")

	if z3.OK() {
		t.Errorf("z3: %v", z3)
	}
}
