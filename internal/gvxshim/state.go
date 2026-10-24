package gvxshim

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/containerd/containerd/v2/pkg/identifiers"
)

const maxPrivateFrame = 64 * 1024

func validateIdentity(id instanceIdentity) error {
	if id.Owner == "" || id.ContainerdAddress == "" || id.Bundle == "" || !filepath.IsAbs(id.Bundle) || filepath.Clean(id.Bundle) != id.Bundle {
		return fmt.Errorf("identity: %w", errInvalidState)
	}
	if err := identifiers.Validate(id.Namespace); err != nil {
		return fmt.Errorf("namespace: %w", err)
	}
	if err := identifiers.Validate(id.ID); err != nil {
		return fmt.Errorf("id: %w", err)
	}
	address, err := normalizeContainerdAddress(id.ContainerdAddress)
	if err != nil {
		return err
	}
	if address != id.ContainerdAddress {
		return fmt.Errorf("address normalization: %w", errInvalidState)
	}
	return nil
}

func endpointKey(id instanceIdentity) string {
	data, _ := json.Marshal([5]string{id.Owner, id.ContainerdAddress, id.Namespace, id.ID, id.Bundle})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func decodeGeneration(generation string) ([32]byte, error) {
	var token [32]byte
	if len(generation) != 64 || strings.ToLower(generation) != generation {
		return token, errInvalidState
	}
	n, err := hex.Decode(token[:], []byte(generation))
	if err != nil || n != len(token) {
		return token, errors.Join(errInvalidState, err)
	}
	return token, nil
}

func validateRecord(paths *instancePaths, record stateRecord) error {
	if record.Version != 1 || record.Identity != paths.Identity {
		return errInvalidState
	}
	if err := validateIdentity(record.Identity); err != nil {
		return err
	}
	if _, err := decodeGeneration(record.Generation); err != nil {
		return err
	}
	if record.Task.Address != paths.TaskAddress || record.Stop.Address != paths.StopAddress {
		return errInvalidState
	}
	if record.Paths.BundleParent != paths.Snapshot.BundleParent || record.Paths.Bundle != paths.Snapshot.Bundle || record.Paths.State != paths.Snapshot.State || record.Paths.CommandLock != paths.Snapshot.CommandLock || record.Paths.Lease != paths.Snapshot.Lease {
		return errConflict
	}
	if record.Paths.Bundle == (fileIdentity{}) || record.Paths.State == (fileIdentity{}) || record.Paths.CommandLock == (fileIdentity{}) || record.Paths.Lease == (fileIdentity{}) {
		return errInvalidState
	}
	if record.Log.Name != "diagnostics.log" || record.Log.Kind != regularEntry || record.Log.Identity == (fileIdentity{}) {
		return errInvalidState
	}
	unix := record.Paths.UnixEndpointRoot != nil
	if unix != (record.Paths.UnixEndpointDir != nil) {
		return errInvalidState
	}
	if unix != strings.HasPrefix(paths.TaskAddress, "unix://") {
		return errInvalidState
	}
	if paths.UnixEndpointRoot != nil && (!unix || paths.UnixEndpointRoot.ID != *record.Paths.UnixEndpointRoot) {
		return errConflict
	}
	if paths.UnixEndpointDir != nil && (!unix || paths.UnixEndpointDir.ID != *record.Paths.UnixEndpointDir) {
		return errConflict
	}
	switch record.Phase {
	case recordPrepared:
		if record.ShimPID != 0 || record.Task.Socket != nil || record.Stop.Socket != nil {
			return errInvalidState
		}
	case recordReady:
		if record.ShimPID == 0 {
			return errInvalidState
		}
		for _, endpoint := range [...]struct {
			name string
			ref  endpointRef
		}{{"task", record.Task}, {"stop", record.Stop}} {
			if unix {
				if endpoint.ref.Socket == nil || endpoint.ref.Socket.Name != endpoint.name || endpoint.ref.Socket.Kind != socketEntry || endpoint.ref.Socket.Identity == (fileIdentity{}) {
					return errInvalidState
				}
			} else if endpoint.ref.Socket != nil {
				return errInvalidState
			}
		}
	default:
		return errInvalidState
	}
	return nil
}

func decodeJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.Join(errInvalidState, err)
	}
	return nil
}

func readRecord(paths *instancePaths) (recordResult *stateRecord, refResult *ownedEntry, result error) {
	if paths.State == nil {
		return nil, nil, nil
	}
	file, err := openPrivateFile(paths.State, "state.json", os.O_RDONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	id, err := validateFile(file, regularEntry, true)
	if err != nil {
		return nil, nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxPrivateFrame+1))
	if err != nil {
		return nil, nil, err
	}
	if len(data) > maxPrivateFrame {
		return nil, nil, errInvalidState
	}
	var record stateRecord
	if err := decodeJSON(data, &record); err != nil {
		return nil, nil, errors.Join(errInvalidState, err)
	}
	if err := validateRecord(paths, record); err != nil {
		return nil, nil, err
	}
	ref, err := inspectEntry(paths.State, "state.json", regularEntry)
	if err != nil {
		return nil, nil, err
	}
	if ref.Identity != id {
		return nil, nil, errConflict
	}
	return &record, &ref, nil
}

func publishRecord(paths *instancePaths, record stateRecord) (ref ownedEntry, result error) {
	if err := paths.Revalidate(paths.Snapshot); err != nil {
		return ref, err
	}
	if err := validateRecord(paths, record); err != nil {
		return ref, err
	}
	// Validate an existing record before atomic replacement; do not replace an unsafe entry.
	existing, existingRef, err := readRecord(paths)
	if err != nil {
		return ref, err
	}
	if existing != nil && (existing.Generation != record.Generation || existing.Phase != recordPrepared || record.Phase != recordReady) {
		return ref, errConflict
	}
	data, err := json.Marshal(record)
	if err != nil {
		return ref, err
	}
	file, temporary, err := createRecordTemp(paths.State)
	if err != nil {
		return ref, err
	}
	closed := false
	defer func() {
		if !closed {
			result = errors.Join(result, file.Close())
		}
		result = errors.Join(result, removeOwned(paths.State, temporary))
	}()
	if _, err := file.Write(data); err != nil {
		return ref, err
	}
	if err := file.Sync(); err != nil {
		return ref, err
	}
	if err := file.Close(); err != nil {
		closed = true
		return ref, err
	}
	closed = true
	if err := paths.Revalidate(paths.Snapshot); err != nil {
		return ref, err
	}
	current, currentRef, err := readRecord(paths)
	if err != nil {
		return ref, err
	}
	if !reflect.DeepEqual(current, existing) || !reflect.DeepEqual(currentRef, existingRef) {
		return ref, errConflict
	}
	if err := paths.State.Root.Rename(temporary.Name, "state.json"); err != nil {
		return ref, err
	}
	ref = temporary
	ref.Name = "state.json"
	return ref, nil
}

func admitDelete(ctx context.Context, id instanceIdentity) (*deleteAdmission, error) {
	paths, err := openPaths(ctx, id, inspectPaths)
	if err != nil {
		return nil, err
	}
	record, ref, err := readRecord(paths)
	if err != nil {
		return nil, errors.Join(err, paths.Close())
	}
	if err := paths.Revalidate(paths.Snapshot); err != nil {
		return nil, errors.Join(err, paths.Close())
	}
	return &deleteAdmission{Paths: paths, Snapshot: paths.Snapshot, Record: record, RecordFile: ref}, nil
}

func (a *deleteAdmission) Close() error { return a.Paths.Close() }

func revalidateAdmission(a *deleteAdmission) error {
	if err := a.Paths.Revalidate(a.Snapshot); err != nil {
		return err
	}
	record, ref, err := readRecord(a.Paths)
	if err != nil {
		return err
	}
	if a.Record == nil {
		if record != nil {
			return errConflict
		}
		return nil
	}
	if record == nil {
		return nil
	}
	if !reflect.DeepEqual(record, a.Record) || !reflect.DeepEqual(ref, a.RecordFile) {
		return errConflict
	}
	return nil
}
