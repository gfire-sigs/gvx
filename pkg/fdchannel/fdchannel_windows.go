//go:build windows

package fdchannel

import "z.gfire.dev/gvx/internal/xsys/unix"

// NewConnectedSockets returns ENOSYS on Windows.
func NewConnectedSockets() ([2]int, error) {
	return [2]int{-1, -1}, unix.ENOSYS
}

// Endpoint is a stub FD channel endpoint on Windows.
type Endpoint struct {
	sockfd int32
}

// Init initializes the endpoint.
func (ep *Endpoint) Init(sockfd int) {
	ep.sockfd = int32(sockfd)
}

// NewEndpoint creates an initialized Endpoint.
func NewEndpoint(sockfd int) *Endpoint {
	ep := &Endpoint{}
	ep.Init(sockfd)
	return ep
}

// Destroy releases resources owned by ep.
func (ep *Endpoint) Destroy() {
	ep.sockfd = -1
}

// Shutdown unblocks concurrent calls.
func (ep *Endpoint) Shutdown() {}

// SendFD returns ENOSYS on Windows.
func (ep *Endpoint) SendFD(_ int) error {
	return unix.ENOSYS
}

// RecvFD returns ENOSYS on Windows.
func (ep *Endpoint) RecvFD() (int, error) {
	return -1, unix.ENOSYS
}

// RecvFDNonblock returns ENOSYS on Windows.
func (ep *Endpoint) RecvFDNonblock() (int, error) {
	return -1, unix.ENOSYS
}
