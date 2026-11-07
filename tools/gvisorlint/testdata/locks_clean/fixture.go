package fixture

import "sync"

type counter struct {
	mu sync.Mutex
	// +checklocks:mu
	n int
}

func (c *counter) increment() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
}

// +checklocks:c.mu
func (c *counter) incrementLocked() {
	c.n++
}
