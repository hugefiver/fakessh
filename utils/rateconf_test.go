package utils

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseRateLimit(t *testing.T) {
	tests := []struct {
		input    string
		expected *RateLimitConfig
		err      bool
	}{
		{
			input: "10:10",
			expected: &RateLimitConfig{
				Interval: Duration(time.Second * 10),
				Limit:    10,
				PerIP:    false,
			},
		},
		{
			input: "1m:10",
			expected: &RateLimitConfig{
				Interval: Duration(time.Second * 60),
				Limit:    10,
				PerIP:    false,
			},
		},
		{
			input: "10s:10",
			expected: &RateLimitConfig{
				Interval: Duration(time.Second * 10),
				Limit:    10,
				PerIP:    false,
			},
		},
		{
			input: "10s:10:p",
			expected: &RateLimitConfig{
				Interval: Duration(time.Second * 10),
				Limit:    10,
				PerIP:    true,
			},
		},
		{
			input: "10s:10:perip",
			expected: &RateLimitConfig{
				Interval: Duration(time.Second * 10),
				Limit:    10,
				PerIP:    true,
			},
		},
		{
			input:    "invalid:10",
			expected: nil,
			err:      true,
		},
		{
			input:    "10s:invalid",
			expected: nil,
			err:      true,
		},
	}

	for _, tt := range tests {
		actual, err := ParseRateLimit(tt.input)
		assert.Equal(t, tt.expected, actual)
		assert.Equal(t, tt.err, err != nil, "expect error: %v, got: %v", tt.err, err)
	}
}

func TestParseCmdlineRateLimits(t *testing.T) {
	tests := []struct {
		input    []string
		expected []*RateLimitConfig
		err      bool
	}{
		{
			input:    []string{"10s:10"},
			expected: []*RateLimitConfig{{Interval: Duration(10 * time.Second), Limit: 10}},
		},
		{
			input: []string{"10s:10:perip", "10s:20:global"},
			expected: []*RateLimitConfig{
				{Interval: Duration(10 * time.Second), Limit: 10, PerIP: true},
				{Interval: Duration(10 * time.Second), Limit: 20},
			},
		},
		{
			input: []string{"10s:10;10s:20"},
			expected: []*RateLimitConfig{
				{Interval: Duration(10 * time.Second), Limit: 10},
				{Interval: Duration(10 * time.Second), Limit: 20},
			},
		},
		{
			input: []string{"invalid"},
			err:   true,
		},
		{
			input: []string{"10s:invalid"},
			err:   true,
		},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			got, err := ParseCmdlineRateLimits(tt.input)
			assert.Equal(t, tt.expected, got)
			assert.Equal(t, tt.err, err != nil, "expect error: %v, got: %v", tt.err, err)
		})
	}
}
