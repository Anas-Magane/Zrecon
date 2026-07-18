package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Anas-Magane/zrecon/internal/logger"
	"github.com/Anas-Magane/zrecon/internal/models"
)

// Engine orchestrates module execution.
type Engine struct {
	modules []Module
	cfg     *models.ScanConfig
}

func New(cfg *models.ScanConfig) *Engine {
	return &Engine{cfg: cfg}
}

func (e *Engine) Register(m Module) {
	e.modules = append(e.modules, m)
}

// Run executes all registered modules sequentially (modules handle internal concurrency).
func (e *Engine) Run(ctx context.Context, target models.Target) (*ScanState, error) {
	state := NewScanState(target)
	state.Result.StartedAt = time.Now()

	var mu sync.Mutex

	for _, mod := range e.modules {
		select {
		case <-ctx.Done():
			logger.Warn("Scan interrupted by user")
			break
		default:
		}

		if ctx.Err() != nil {
			break
		}

		// Check authorization for active modules
		if !mod.IsPassive() && mod.RequiresAuthorization() && !e.cfg.Authorized {
			logger.Warn(fmt.Sprintf("Skipping active module %q — use --authorized to enable", mod.Name()))
			continue
		}

		// Check passive-only flag
		if e.cfg.Passive && !mod.IsPassive() {
			logger.Verbose(fmt.Sprintf("Skipping active module %q (--passive mode)", mod.Name()))
			continue
		}

		start := time.Now()
		logger.ModuleStart(mod.Description())

		err := mod.Run(ctx, target, state)
		duration := time.Since(start)

		mr := models.ModuleResult{
			Module:   mod.Name(),
			Duration: duration,
		}

		if err != nil {
			mr.Success = false
			mr.Error = err.Error()
			logger.Error(fmt.Sprintf("Module %q failed: %v", mod.Name(), err))
			warning := fmt.Sprintf("Module %q failed: %v", mod.Name(), err)
			mu.Lock()
			state.AddWarning(warning)
			mu.Unlock()
		} else {
			mr.Success = true
		}

		mu.Lock()
		state.Result.ModuleResults = append(state.Result.ModuleResults, mr)
		mu.Unlock()
	}

	state.Result.CompletedAt = time.Now()
	return state, nil
}
