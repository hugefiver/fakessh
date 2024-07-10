package utils

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type RateLimitConfig struct {
	Interval Duration `toml:"interval"`
	Limit    int      `toml:"limit"`
	PerIP    bool     `toml:"per_ip,omitempty"`
}

type Duration time.Duration

func (d *Duration) UnmarshalText(text []byte) error {
	if n, err := strconv.ParseFloat(string(text), 64); err == nil {
		*d = Duration(time.Duration(n*1000) * time.Millisecond)
		return nil
	}

	if n, err := time.ParseDuration(string(text)); err == nil {
		*d = Duration(n)
		return nil
	}
	return fmt.Errorf("cannot unmarshal %q into a Duration", text)
}

func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

func ParseRateLimit(s string) (*RateLimitConfig, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 && len(parts) != 3 {
		return nil, fmt.Errorf("invalid rate limit string: '%s', expected format: `interval:limit[:tag]`", s)
	}

	perip := false
	if len(parts) == 3 {
		switch strings.ToLower(parts[2]) {
		case "p", "perip":
			perip = true
		default:
		}
	}

	var interval Duration
	if err := interval.UnmarshalText([]byte(parts[0])); err != nil {
		return nil, err
	}
	limit, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, err
	}
	return &RateLimitConfig{interval, limit, perip}, nil
}

func ParseCmdlineRateLimits(ss []string) ([]*RateLimitConfig, error) {
	var ret []*RateLimitConfig
	for _, s := range ss {
		// format "interval:limit"
		// or "interval:limit:perip"/"interval:limit:p" or "interval:limit:global"/"interval:limit:g", default global
		// or "interval:limit;interval:limit" for multiple rate limits in one string
		rs := strings.Split(s, ";")
		for _, r := range rs {
			r = strings.TrimSpace(r)
			if r == "" {
				continue
			}

			r, err := ParseRateLimit(r)
			if err != nil {
				return nil, err
			}

			ret = append(ret, r)
		}
	}
	return ret, nil
}
