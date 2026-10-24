package gvxshim

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	errStopping           = errors.New("shim is stopping")
	errHandoffExpired     = errors.New("shim handoff deadline expired")
	errReplyUnregistered  = errors.New("shutdown response has no registered obligation")
	errConflict           = errors.New("shim ownership conflict")
	errInvalidState       = errors.New("invalid shim state")
	errUnsupportedOptions = errors.New("runtime options are unsupported")
)

type controlState struct {
	mu              sync.Mutex
	handoffDeadline time.Time
	drainTimeout    time.Duration
	drainDeadline   time.Time
	attached        bool
	stopping        bool
	sealed          bool
	replies         uint64
	attachCh        chan struct{}
	stopCh          chan struct{}
	changed         chan struct{}
}

func newControlState(handoffDeadline time.Time, drainTimeout time.Duration) *controlState {
	if drainTimeout <= 0 {
		panic("nonpositive shim drain timeout")
	}
	return &controlState{handoffDeadline: handoffDeadline, drainTimeout: drainTimeout, attachCh: make(chan struct{}), stopCh: make(chan struct{}), changed: make(chan struct{})}
}

func (s *controlState) notifyLocked() { close(s.changed); s.changed = make(chan struct{}) }

func (s *controlState) stopLocked() {
	if s.stopping {
		return
	}
	s.stopping = true
	s.drainDeadline = time.Now().Add(s.drainTimeout)
	close(s.stopCh)
	s.notifyLocked()
}

func (s *controlState) attachLocked() error {
	if s.stopping {
		return errStopping
	}
	if s.attached {
		return nil
	}
	if !time.Now().Before(s.handoffDeadline) {
		s.stopLocked()
		return errHandoffExpired
	}
	s.attached = true
	close(s.attachCh)
	return nil
}

func (s *controlState) Attach() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attachLocked()
}

func (s *controlState) Attached() <-chan struct{}      { return s.attachCh }
func (s *controlState) StopRequested() <-chan struct{} { return s.stopCh }
func (s *controlState) Stopping() bool                 { s.mu.Lock(); defer s.mu.Unlock(); return s.stopping }
func (s *controlState) DrainDeadline() (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.drainDeadline, s.stopping
}
func (s *controlState) RequestStop() { s.mu.Lock(); defer s.mu.Unlock(); s.stopLocked() }

func (s *controlState) BeginRPCStop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sealed {
		return errStopping
	}
	if !s.stopping {
		if err := s.attachLocked(); err != nil {
			return err
		}
	}
	s.replies++
	s.stopLocked()
	s.notifyLocked()
	return nil
}

func (s *controlState) ReplyWritten() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.replies == 0 {
		return errReplyUnregistered
	}
	s.replies--
	s.notifyLocked()
	return nil
}

func (s *controlState) WaitAndSeal(ctx context.Context) error {
	for {
		s.mu.Lock()
		if s.replies == 0 {
			s.sealed = true
			s.mu.Unlock()
			return nil
		}
		changed := s.changed
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

func (s *controlState) expireHandoff() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.attached && !time.Now().Before(s.handoffDeadline) {
		s.stopLocked()
	}
}
