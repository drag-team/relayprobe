package engine

import (
	"context"
	"testing"

	"github.com/drag-team/relayprobe/internal/model"
)

type immediateProcessor struct{}

func (immediateProcessor) Check(_ context.Context, p model.Proxy) model.Result {
	return model.Result{ID: p.Key(), Status: model.StatusOK}
}

func BenchmarkEngineScheduler(b *testing.B) {
	for _, workers := range []int{1, 16, 128} {
		b.Run(workerName(workers), func(b *testing.B) {
			jobs := make(chan model.Proxy, workers*2)
			e := Engine{Workers: workers, QueueSize: workers * 2, Processor: immediateProcessor{}}
			go func() {
				defer close(jobs)
				for i := 0; i < b.N; i++ {
					jobs <- model.Proxy{Protocol: model.ProtocolHTTP, Host: "bench.invalid", Port: uint16(1000 + i%64000)}
				}
			}()
			b.ResetTimer()
			n := 0
			for range e.Run(context.Background(), jobs) {
				n++
			}
			if n != b.N {
				b.Fatalf("got %d", n)
			}
		})
	}
}
func workerName(n int) string {
	if n == 1 {
		return "workers_1"
	}
	if n == 16 {
		return "workers_16"
	}
	return "workers_128"
}
