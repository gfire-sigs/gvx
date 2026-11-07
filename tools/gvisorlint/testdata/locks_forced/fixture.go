package fixture

import "sync"

type counter struct {
	mu sync.Mutex
	// +checklocks:mu
	n int
}

func (c *counter) forcedIncrement() {
	c.n++ // +checklocksforce: the test forces the lock
}
