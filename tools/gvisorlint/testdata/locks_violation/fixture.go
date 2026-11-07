package fixture

import "sync"

type counter struct {
	mu sync.Mutex
	// +checklocks:mu
	n int
}

func (c *counter) unsafeIncrement() {
	c.n++
}
