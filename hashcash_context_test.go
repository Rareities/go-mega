package mega

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSolveHashCashChallengeContextAlreadyCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	solverCalled := make(chan struct{}, 1)
	result, err := solveHashCashChallengeContextWithSolver(ctx, "token", 1, time.Minute, 2,
		func(context.Context, string, int) string {
			select {
			case solverCalled <- struct{}{}:
			default:
			}
			return "unexpected"
		})

	if result != "" {
		t.Fatalf("result = %q, want empty", result)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if cash := gencash(ctx, "dG9rZW4", 1); cash != "" {
		t.Fatalf("gencash result = %q with an already-canceled context, want empty", cash)
	}
	select {
	case <-solverCalled:
		t.Fatal("solver ran with an already-canceled context")
	default:
	}
}

func TestSolveHashCashChallengeContextCancellationJoinsWorkers(t *testing.T) {
	const workerCount = 4

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := make(chan struct{}, workerCount)
	exited := make(chan struct{}, workerCount)
	type solveResult struct {
		value string
		err   error
	}
	finished := make(chan solveResult, 1)

	go func() {
		value, err := solveHashCashChallengeContextWithSolver(ctx, "token", 1, time.Minute, workerCount,
			func(ctx context.Context, _ string, _ int) string {
				started <- struct{}{}
				<-ctx.Done()
				exited <- struct{}{}
				return ""
			})
		finished <- solveResult{value: value, err: err}
	}()

	for i := 0; i < workerCount; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d of %d workers started", i, workerCount)
		}
	}

	cancel()
	select {
	case got := <-finished:
		if got.value != "" {
			t.Fatalf("result = %q, want empty", got.value)
		}
		if !errors.Is(got.err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("solver did not return promptly after cancellation")
	}

	for i := 0; i < workerCount; i++ {
		select {
		case <-exited:
		case <-time.After(2 * time.Second):
			t.Fatalf("worker %d did not exit before the solver returned", i+1)
		}
	}
}
