package engine

import (
	"context"

	"github.com/Anas-Magane/zrecon/internal/models"
)

// ScanState holds shared mutable scan results protected by the engine.
type ScanState struct {
	Result   *models.ScanResult
	Warnings []string
}

func NewScanState(target models.Target) *ScanState {
	return &ScanState{
		Result: &models.ScanResult{
			Target: target,
		},
	}
}

func (s *ScanState) AddWarning(w string) {
	s.Warnings = append(s.Warnings, w)
}

// Module is the interface every reconnaissance module must implement.
type Module interface {
	Name() string
	Description() string
	Category() string
	IsPassive() bool
	RequiresAuthorization() bool
	Run(ctx context.Context, target models.Target, state *ScanState) error
}
