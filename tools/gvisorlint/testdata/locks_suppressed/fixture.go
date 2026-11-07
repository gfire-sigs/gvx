package fixture

import "sync"

// counter has no annotation, so checklocks only suggests one.
type counter struct {
	mu sync.Mutex
	n  int
}

func (c *counter) increment() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
}
