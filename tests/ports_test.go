package tests

import (
	"testing"

	"github.com/Anas-Magane/zrecon/internal/modules/network/ports"
)

func TestParsePortSpec(t *testing.T) {
	tests := []struct {
		input string
		want  []int
	}{
		{"80", []int{80}},
		{"22,80,443", []int{22, 80, 443}},
		{"8000-8003", []int{8000, 8001, 8002, 8003}},
		{"22,80-82", []int{22, 80, 81, 82}},
		{"80,80,80", []int{80}}, // dedup
		{"invalid", []int{}},
		{"", []int{}},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := ports.ParsePortSpec(tc.input)
			if len(got) != len(tc.want) {
				t.Errorf("ParsePortSpec(%q) = %v, want %v", tc.input, got, tc.want)
				return
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("ParsePortSpec(%q)[%d] = %d, want %d", tc.input, i, got[i], tc.want[i])
				}
			}
		})
	}
}
