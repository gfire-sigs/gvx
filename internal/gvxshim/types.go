package gvxshim

import (
	"context"
	"io"
	"net"
	"os"
)

type instanceIdentity struct {
	Owner             string `json:"owner"`
	ContainerdAddress string `json:"containerd_address"`
	Namespace         string `json:"namespace"`
	ID                string `json:"id"`
	Bundle            string `json:"bundle"`
}

type fileIdentity struct {
	Volume uint64   `json:"volume"`
	Object [16]byte `json:"object"`
}

type entryKind uint8

const (
	regularEntry entryKind = iota + 1
	directoryEntry
	socketEntry
)

type ownedEntry struct {
	Name     string       `json:"name"`
	Kind     entryKind    `json:"kind"`
	Identity fileIdentity `json:"identity"`
}

type pathSnapshot struct {
	BundleParent     fileIdentity  `json:"bundle_parent"`
	Bundle           fileIdentity  `json:"bundle"`
	State            fileIdentity  `json:"state"`
	CommandLock      fileIdentity  `json:"command_lock"`
	Lease            fileIdentity  `json:"lease"`
	UnixEndpointRoot *fileIdentity `json:"unix_endpoint_root,omitempty"`
	UnixEndpointDir  *fileIdentity `json:"unix_endpoint_dir,omitempty"`
}

type endpointRef struct {
	Address string      `json:"address"`
	Socket  *ownedEntry `json:"socket,omitempty"`
}

type recordPhase string

const (
	recordPrepared recordPhase = "prepared"
	recordReady    recordPhase = "ready"
)

type stateRecord struct {
	Version    uint32           `json:"version"`
	Phase      recordPhase      `json:"phase"`
	Identity   instanceIdentity `json:"identity"`
	Generation string           `json:"generation"`
	ShimPID    uint32           `json:"shim_pid"`
	Paths      pathSnapshot     `json:"paths"`
	Task       endpointRef      `json:"task"`
	Stop       endpointRef      `json:"stop"`
	Log        ownedEntry       `json:"log"`
}

type pinnedDir struct {
	Root   *os.Root
	Handle *os.File
	ID     fileIdentity
}

type instancePaths struct {
	Identity         instanceIdentity
	BundleParent     *pinnedDir
	BundleName       string
	Bundle           *pinnedDir
	State            *pinnedDir
	UnixEndpointRoot *pinnedDir
	UnixEndpointDir  *pinnedDir
	Snapshot         pathSnapshot
	TaskAddress      string
	StopAddress      string
}

type ownedLock struct {
	File *os.File
	Ref  ownedEntry
}

type ownedEndpoint struct {
	Listener net.Listener
	Ref      endpointRef
}

type logOutput struct {
	Writer io.Writer
	Close  func(context.Context) error
}

type startupConfig struct {
	Prepared stateRecord `json:"prepared"`
}

type boundReport struct {
	PID   uint32      `json:"pid"`
	Task  endpointRef `json:"task"`
	Stop  endpointRef `json:"stop"`
	Error string      `json:"error,omitempty"`
}

type deleteAdmission struct {
	Paths      *instancePaths
	Snapshot   pathSnapshot
	Record     *stateRecord
	RecordFile *ownedEntry
}

type processExit struct {
	Code        int
	RetainLease *ownedLock
}

type pathMode uint8

const (
	inspectPaths pathMode = iota
	createPaths
)

type endpointKind uint8

const (
	taskEndpoint endpointKind = iota
	stopEndpoint
)

type lockName uint8

const (
	commandLock lockName = iota
	lifetimeLease
)
