package engine

import (
	"context"
	"sync"

	"github.com/drag-team/relayprobe/internal/model"
)

type Processor interface {
	Check(context.Context, model.Proxy) model.Result
}

type Engine struct {
	Workers   int
	QueueSize int
	Processor Processor
}

func (e Engine) Run(ctx context.Context, input <-chan model.Proxy) <-chan model.Result {
	out := make(chan model.Result, max(1, e.QueueSize))
	workers := e.Workers
	if workers < 1 {
		workers = 1
	}
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case p, ok := <-input:
					if !ok {
						return
					}
					r := e.Processor.Check(ctx, p)
					select {
					case out <- r:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
	go func() { wg.Wait(); close(out) }()
	return out
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
