package gvxshim

import (
	"context"
	"errors"
	"fmt"

	sandbox "github.com/containerd/containerd/api/runtime/sandbox/v1"
	task "github.com/containerd/containerd/api/runtime/task/v3"
	"github.com/containerd/containerd/v2/pkg/identifiers"
	"github.com/containerd/ttrpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	namespaceMetadata    = "containerd-namespace-ttrpc"
	startupProbeMetadata = "gvx-startup-probe"
	controlVersion       = "gvx-control-v1"
)

var errInvalidService = errors.New("service requires a positive process PID and control state")

type service struct {
	identity   instanceIdentity
	generation string
	pid        uint32
	state      *controlState
}

func newService(id instanceIdentity, generation string, pid uint32, state *controlState) (*service, error) {
	if err := validateIdentity(id); err != nil {
		return nil, fmt.Errorf("validate service identity: %w", err)
	}
	if _, err := decodeGeneration(generation); err != nil {
		return nil, fmt.Errorf("validate service generation: %w", err)
	}
	if pid == 0 || state == nil {
		return nil, errInvalidService
	}
	return &service{identity: id, generation: generation, pid: pid, state: state}, nil
}

func (s *service) Register(server *ttrpc.Server) {
	server.RegisterService("containerd.task.v3.Task", &ttrpc.ServiceDesc{
		Methods: map[string]ttrpc.Method{
			"Connect": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req task.ConnectRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return s.Connect(ctx, &req)
			},
			"Shutdown": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req task.ShutdownRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return s.Shutdown(ctx, &req)
			},
		},
	})
	server.RegisterService("containerd.runtime.sandbox.v1.Sandbox", &ttrpc.ServiceDesc{
		Methods: map[string]ttrpc.Method{
			"CreateSandbox": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req sandbox.CreateSandboxRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return s.CreateSandbox(ctx, &req)
			},
			"ShutdownSandbox": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req sandbox.ShutdownSandboxRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return s.ShutdownSandbox(ctx, &req)
			},
		},
	})
}

func (s *service) validateRequest(ctx context.Context, id string, allowProbe bool) (bool, error) {
	metadata, _ := ttrpc.GetMetadata(ctx)
	namespaces := metadata[namespaceMetadata]
	if len(namespaces) != 1 || namespaces[0] == "" {
		return false, status.Error(codes.InvalidArgument, "exactly one namespace is required")
	}
	if namespaces[0] != s.identity.Namespace {
		return false, status.Error(codes.PermissionDenied, "namespace does not match control instance")
	}
	if err := identifiers.Validate(id); err != nil {
		return false, status.Error(codes.InvalidArgument, "invalid control instance ID")
	}
	if id != s.identity.ID {
		return false, status.Error(codes.NotFound, "control instance ID does not match")
	}
	probes, present := metadata[startupProbeMetadata]
	if !present {
		return false, nil
	}
	if !allowProbe || len(probes) != 1 || probes[0] != s.generation {
		return false, status.Error(codes.InvalidArgument, "invalid startup probe metadata")
	}
	return true, nil
}

func (s *service) Connect(ctx context.Context, req *task.ConnectRequest) (*task.ConnectResponse, error) {
	probe, err := s.validateRequest(ctx, req.GetID(), true)
	if err != nil {
		return nil, err
	}
	if probe {
		if s.state.Stopping() {
			return nil, status.Error(codes.FailedPrecondition, "control instance is stopping")
		}
	} else if err := s.state.Attach(); err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return &task.ConnectResponse{ShimPid: s.pid, TaskPid: 0, Version: controlVersion}, nil
}

func (s *service) Shutdown(ctx context.Context, req *task.ShutdownRequest) (*emptypb.Empty, error) {
	if _, err := s.validateRequest(ctx, req.GetID(), false); err != nil {
		return nil, err
	}
	if err := s.state.BeginRPCStop(); err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return &emptypb.Empty{}, nil
}

func (s *service) CreateSandbox(ctx context.Context, req *sandbox.CreateSandboxRequest) (*sandbox.CreateSandboxResponse, error) {
	if _, err := s.validateRequest(ctx, req.GetSandboxID(), false); err != nil {
		return nil, err
	}
	if err := s.state.Attach(); err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return nil, status.Error(codes.Unimplemented, "gvx control daemon does not create sandboxes")
}

func (s *service) ShutdownSandbox(ctx context.Context, req *sandbox.ShutdownSandboxRequest) (*sandbox.ShutdownSandboxResponse, error) {
	if _, err := s.validateRequest(ctx, req.GetSandboxID(), false); err != nil {
		return nil, err
	}
	if err := s.state.BeginRPCStop(); err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return &sandbox.ShutdownSandboxResponse{}, nil
}
