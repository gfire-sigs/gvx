package whpx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
)

const runReplySize = 8 + exitCtxBufSize

type runRequest struct {
	index    uint32
	resumePC uint64
	setPC    bool
}

type runReply struct {
	exit [exitCtxBufSize]byte
	err  error
}

type runClient struct {
	connection io.ReadWriteCloser
	writeMu    sync.Mutex
	reader     chan struct{}
	mu         sync.Mutex
	pending    [maxVPs]chan runReply
	resume     [maxVPs]runRequest
	err        error
}

func newRunClient(connection io.ReadWriteCloser) *runClient {
	c := &runClient{connection: connection, reader: make(chan struct{}, 1)}
	c.reader <- struct{}{}
	return c
}

func (c *runClient) run(index uint32, exit []byte) error {
	if index >= maxVPs || len(exit) != exitCtxBufSize {
		return errors.New("whpx: invalid run request")
	}
	result := make(chan runReply, 1)
	c.mu.Lock()
	if c.err != nil {
		err := c.err
		c.mu.Unlock()
		return err
	}
	if c.pending[index] != nil {
		c.mu.Unlock()
		return errors.New("whpx: processor already has a pending run")
	}
	c.pending[index] = result
	resume := c.resume[index]
	c.resume[index] = runRequest{}
	c.mu.Unlock()
	var request [16]byte
	binary.LittleEndian.PutUint32(request[:], index)
	if resume.setPC {
		binary.LittleEndian.PutUint32(request[4:8], 1)
		binary.LittleEndian.PutUint64(request[8:], resume.resumePC)
	}
	c.writeMu.Lock()
	err := writeRunFrame(c.connection, request[:])
	c.writeMu.Unlock()
	if err != nil {
		c.fail(err)
	}
	reply := c.await(result)
	if reply.err == nil {
		copy(exit, reply.exit[:])
	}
	return reply.err
}

func (c *runClient) await(result <-chan runReply) runReply {
	for {
		select {
		case reply := <-result:
			return reply
		case <-c.reader:
			select {
			case reply := <-result:
				c.reader <- struct{}{}
				return reply
			default:
			}
			c.readOne()
			c.reader <- struct{}{}
		}
	}
}

func (c *runClient) prepareResumePC(index uint32, pc uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	if index >= maxVPs || c.pending[index] != nil {
		return errors.New("whpx: cannot prepare an active processor")
	}
	c.resume[index] = runRequest{resumePC: pc, setPC: true}
	return nil
}

func (c *runClient) clearResumePC(index uint32) {
	c.mu.Lock()
	c.resume[index] = runRequest{}
	c.mu.Unlock()
}

func (c *runClient) readOne() {
	var packet [runReplySize]byte
	if _, err := io.ReadFull(c.connection, packet[:]); err != nil {
		c.fail(err)
		return
	}
	index := binary.LittleEndian.Uint32(packet[:4])
	errorSize := binary.LittleEndian.Uint32(packet[4:8])
	if index >= maxVPs || errorSize > exitCtxBufSize {
		c.fail(errors.New("whpx: invalid run response"))
		return
	}
	var reply runReply
	if errorSize != 0 {
		reply.err = errors.New(string(packet[8 : 8+errorSize]))
	} else {
		copy(reply.exit[:], packet[8:])
	}
	c.mu.Lock()
	result := c.pending[index]
	c.pending[index] = nil
	if c.err != nil {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	if result == nil {
		c.fail(errors.New("whpx: unexpected run response"))
		return
	}
	result <- reply
}

func (c *runClient) fail(err error) {
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return
	}
	c.err = err
	for index, result := range c.pending {
		if result != nil {
			result <- runReply{err: err}
			c.pending[index] = nil
		}
	}
	c.mu.Unlock()
	_ = c.connection.Close()
}

func (c *runClient) Close() error {
	c.fail(io.ErrClosedPipe)
	<-c.reader
	c.reader <- struct{}{}
	return nil
}

// serveRuns owns connection and stops the partition before joining its workers.
// Each processor has one worker and at most one outstanding request.
func serveRuns(connection io.ReadWriteCloser, run func(runRequest, []byte) error, stop func() error) (err error) {
	var workers [maxVPs]chan runRequest
	var busy [maxVPs]atomic.Bool
	var running sync.WaitGroup
	var writeMu sync.Mutex
	defer func() {
		_ = connection.Close()
		err = errors.Join(err, stop())
		for _, requests := range workers {
			if requests != nil {
				close(requests)
			}
		}
		running.Wait()
	}()
	var request [16]byte
	for {
		if _, readErr := io.ReadFull(connection, request[:]); readErr != nil {
			if errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrClosedPipe) || errors.Is(readErr, net.ErrClosed) || errors.Is(readErr, os.ErrClosed) {
				return nil
			}
			return readErr
		}
		index := binary.LittleEndian.Uint32(request[:])
		flags := binary.LittleEndian.Uint32(request[4:8])
		if index >= maxVPs {
			return fmt.Errorf("whpx: run processor index %d exceeds the limit", index)
		}
		if flags > 1 {
			return errors.New("whpx: invalid run flags")
		}
		resume := runRequest{index: index, setPC: flags == 1, resumePC: binary.LittleEndian.Uint64(request[8:])}
		if !busy[index].CompareAndSwap(false, true) {
			return fmt.Errorf("whpx: duplicate run for processor %d", index)
		}
		if workers[index] == nil {
			requests := make(chan runRequest, 1)
			workers[index] = requests
			running.Add(1)
			go func() {
				defer running.Done()
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				exit := alignedBuf(exitCtxBufSize, 16)
				var packet [runReplySize]byte
				binary.LittleEndian.PutUint32(packet[:4], index)
				for resume := range requests {
					runErr := run(resume, exit)
					clear(packet[4:])
					if runErr == nil {
						copy(packet[8:], exit)
					} else {
						message := runErr.Error()
						if message == "" {
							message = "whpx: run failed"
						}
						n := copy(packet[8:], message)
						binary.LittleEndian.PutUint32(packet[4:8], uint32(n))
					}
					// Release before the reply permits the client to submit its next run.
					busy[index].Store(false)
					writeMu.Lock()
					writeErr := writeRunFrame(connection, packet[:])
					writeMu.Unlock()
					if writeErr != nil {
						_ = connection.Close()
						return
					}
				}
			}()
		}
		workers[index] <- resume
	}
}

func writeRunFrame(writer io.Writer, data []byte) error {
	for len(data) != 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
