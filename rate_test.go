package main

import (
	"testing"
	"time"

	"github.com/hugefiver/fakessh/conf"
	"github.com/hugefiver/fakessh/utils"
)

func TestRateLimiter(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter([]*conf.RateLimitConfig{
		{Limit: 3, Interval: utils.Duration(time.Second)},
		{Limit: 5, Interval: utils.Duration(time.Second * 10)},
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

	rl := NewSSHRateLimiter(
		[]*conf.RateLimitConfig{
			{Limit: 3, Interval: utils.Duration(time.Second * 2)},
			{Limit: 6, Interval: utils.Duration(time.Second * 9)},
		},
		[]*conf.RateLimitConfig{
			{Limit: 1, Interval: utils.Duration(time.Second), PerIP: true},
		})

	x1 := rl.Allow("1")
	x2 := rl.Allow("1")

	// global: 1|1, `1`: 1
	if !x1.OK() || x2.OK() {
		t.Errorf("x1: %v, x2: %v", x1, x2)
	}

	y1 := rl.Allow("2")
	y2 := rl.Allow("2")

	// global: 2|2, `1`: 1, `2`: 1
	if !y1.OK() || y2.OK() {
		t.Errorf("y1: %v, y2: %v", y1, y2)
	}

	// to avoid timer lag
	time.Sleep(time.Second * 1)

	z1 := rl.Allow("3")
	z2 := rl.Allow("3")

	// global: 3|3, `1`: 0~1, `2`: 0~1, `3`: 1
	if !z1.OK() || z2.OK() {
		t.Errorf("z1: %v, z2: %v", z1, z2)
	}

	time.Sleep(time.Second * 2)
	// global: 0|1(because sleep ~1/3 ratelimiter duration), `1`: 0, `2`: 0, `3`: 0

	x3 := rl.Allow("1")

	// global: 1|2, `1`: 1, `2`: 0, `3`: 0
	if !x3.OK() {
		t.Errorf("x3: %v", x3)
	}

	y3 := rl.Allow("2")

	// global: 2|3, `1`: 1, `2`: 1, `3`: 0
	if !y3.OK() {
		t.Errorf("y3: %v", y3)
	}

	z3 := rl.Allow("3")

	// global: 3|4, `1`: 1, `2`: 1, `3`: 1
	if !z3.OK() {
		t.Errorf("z3: %v", z3)
	}
}
