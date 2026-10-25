package daemon

import (
	"context"
	"sync"
)

// jobKind orders what a worker must do for a container. A stronger kind
// absorbs a weaker one when both are queued.
type jobKind int

const (
	// jobVerify re-applies only if the policy changed or the table drifted.
	jobVerify jobKind = iota + 1
	// jobApply applies if the policy differs from what was applied.
	jobApply
	// jobRebuild always rebuilds the table (fresh domain addresses).
	jobRebuild
)

// queue is a keyed work queue: at most one job per container is queued, and
// a container is never processed by two workers at once. A job added while
// its container is being processed runs again right after.
type queue struct {
	mu      sync.Mutex
	cond    *sync.Cond
	order   []string
	pending map[string]jobKind
	active  map[string]bool
	dirty   map[string]jobKind
	closed  bool
}

func newQueue() *queue {
	q := &queue{pending: map[string]jobKind{}, active: map[string]bool{}, dirty: map[string]jobKind{}}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *queue) add(id string, kind jobKind) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	if q.active[id] {
		q.dirty[id] = max(q.dirty[id], kind)
		return
	}
	if old, ok := q.pending[id]; ok {
		q.pending[id] = max(old, kind)
		return
	}
	q.pending[id] = kind
	q.order = append(q.order, id)
	q.cond.Signal()
}

// get blocks until a job is available or the queue is closed.
func (q *queue) get() (string, jobKind, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.order) == 0 && !q.closed {
		q.cond.Wait()
	}
	if q.closed {
		return "", 0, false
	}
	id := q.order[0]
	q.order = q.order[1:]
	kind := q.pending[id]
	delete(q.pending, id)
	q.active[id] = true
	return id, kind, true
}

func (q *queue) done(id string) {
	q.mu.Lock()
	delete(q.active, id)
	kind, again := q.dirty[id]
	delete(q.dirty, id)
	q.mu.Unlock()
	if again {
		q.add(id, kind)
	}
}

func (q *queue) close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
	q.cond.Broadcast()
}

// idle reports whether nothing is queued or running (for tests).
func (q *queue) idle() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.order) == 0 && len(q.active) == 0
}

// run starts n workers calling fn until ctx is done.
func (q *queue) run(ctx context.Context, n int, fn func(id string, kind jobKind)) *sync.WaitGroup {
	var wg sync.WaitGroup
	go func() {
		<-ctx.Done()
		q.close()
	}()
	for range n {
		wg.Go(func() {
			for {
				id, kind, ok := q.get()
				if !ok {
					return
				}
				fn(id, kind)
				q.done(id)
			}
		})
	}
	return &wg
}
