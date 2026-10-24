package gvxshim

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"google.golang.org/protobuf/proto"
)

type commandOptions struct {
	namespace     string
	id            string
	address       string
	bundle        string
	timeout       time.Duration
	debug         bool
	publishBinary string
	version       bool
}

func Main() {
	// Broken bootstrap and readiness pipes must run rollback instead of terminating the process.
	signal.Ignore(syscall.SIGPIPE)
	exit := dispatch(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	// Keep the serving lease rooted until the operating system closes all process handles.
	defer runtime.KeepAlive(exit.RetainLease)
	os.Exit(exit.Code)
}

func dispatch(args []string, input, output, diagnostics *os.File) processExit {
	options := commandOptions{}
	flags := flag.NewFlagSet("containerd-shim-gvx-v2", flag.ContinueOnError)
	var usage bytes.Buffer
	flags.SetOutput(&usage)
	flags.StringVar(&options.namespace, "namespace", "", "containerd namespace")
	flags.StringVar(&options.id, "id", "", "control instance ID")
	flags.StringVar(&options.address, "address", "", "local containerd address")
	flags.StringVar(&options.bundle, "bundle", "", "containerd bundle directory")
	flags.DurationVar(&options.timeout, "timeout", 5*time.Second, "lifecycle and drain timeout")
	flags.BoolVar(&options.debug, "debug", false, "accept containerd debug mode")
	flags.StringVar(&options.publishBinary, "publish-binary", "", "accept the legacy publisher path")
	flags.BoolVar(&options.version, "v", false, "print version")
	parseError := flags.Parse(args)
	duration := options.timeout
	if duration <= 0 {
		duration = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	if parseError != nil {
		if errors.Is(parseError, flag.ErrHelp) {
			err := boundedFileIO(ctx, output, func(stream io.ReadWriter) error { return writeAll(stream, usage.Bytes()) })
			if err == nil {
				return processExit{}
			}
			return commandFailure(ctx, diagnostics, err)
		}
		return commandFailure(ctx, diagnostics, parseError)
	}
	if options.timeout <= 0 {
		return commandFailure(ctx, diagnostics, errPositiveTimeout)
	}
	if options.version {
		err := boundedFileIO(ctx, output, func(stream io.ReadWriter) error {
			_, err := fmt.Fprintln(stream, "containerd-shim-gvx-v2 "+controlVersion+" (control-only; Task v3; JSON bootstrap v3)")
			return err
		})
		if err != nil {
			return commandFailure(ctx, diagnostics, err)
		}
		return processExit{}
	}
	if flags.NArg() != 1 {
		return commandFailure(ctx, diagnostics, errOneAction)
	}
	action := flags.Arg(0)
	if action != "start" && action != "serve" && action != "delete" {
		return commandFailure(ctx, diagnostics, errUnsupportedAction)
	}
	if action == "delete" && options.bundle == "" {
		return commandFailure(ctx, diagnostics, errExplicitBundle)
	}
	if action == "start" {
		if err := emptyOptions(ctx, input); err != nil {
			return commandFailure(ctx, diagnostics, err)
		}
	}
	identity, err := options.identity()
	if err != nil {
		return commandFailure(ctx, diagnostics, err)
	}
	if action == "serve" {
		exit, err := serveInstance(ctx, identity, options.timeout, input, output)
		if err != nil {
			writeCommandError(ctx, diagnostics, err)
			exit.Code = 1
		}
		return exit
	}
	if action == "start" {
		if err := startInstance(ctx, identity, options.timeout, output); err != nil {
			return commandFailure(ctx, diagnostics, err)
		}
		return processExit{}
	}
	admission, err := admitDelete(ctx, identity)
	if err != nil {
		return commandFailure(ctx, diagnostics, err)
	}
	response, err := deleteInstance(ctx, admission)
	err = errors.Join(err, admission.Close())
	if err == nil {
		var data []byte
		data, err = proto.Marshal(response)
		if err == nil {
			err = boundedFileIO(ctx, output, func(stream io.ReadWriter) error { return writeAll(stream, data) })
		}
	}
	if err != nil {
		return commandFailure(ctx, diagnostics, err)
	}
	return processExit{}
}

func (o commandOptions) identity() (instanceIdentity, error) {
	owner, err := currentOwner()
	if err != nil {
		return instanceIdentity{}, err
	}
	address, err := normalizeContainerdAddress(o.address)
	if err != nil {
		return instanceIdentity{}, err
	}
	bundle := o.bundle
	if bundle == "" {
		bundle, err = os.Getwd()
		if err != nil {
			return instanceIdentity{}, err
		}
	}
	bundle, err = canonicalBundle(bundle)
	if err != nil {
		return instanceIdentity{}, err
	}
	id := instanceIdentity{Owner: owner, ContainerdAddress: address, Namespace: o.namespace, ID: o.id, Bundle: bundle}
	return id, validateIdentity(id)
}

var (
	errPositiveTimeout   = errors.New("timeout must be positive")
	errOneAction         = errors.New("exactly one action is required: start, serve, delete")
	errUnsupportedAction = errors.New("unsupported action")
	errExplicitBundle    = errors.New("delete requires an explicit bundle")
)

func commandFailure(ctx context.Context, diagnostics *os.File, err error) processExit {
	writeCommandError(ctx, diagnostics, err)
	return processExit{Code: 1}
}

func writeCommandError(ctx context.Context, diagnostics *os.File, err error) {
	// An expired lifecycle cannot wait for a diagnostic reader.
	_ = boundedFileIO(ctx, diagnostics, func(stream io.ReadWriter) error {
		_, writeError := fmt.Fprintln(stream, err)
		return writeError
	})
}

func emptyOptions(ctx context.Context, input *os.File) error {
	return boundedFileIO(ctx, input, func(stream io.ReadWriter) error {
		var one [1]byte
		n, err := stream.Read(one[:])
		if n != 0 {
			return errUnsupportedOptions
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		return io.ErrNoProgress
	})
}

func writeAll(writer io.Writer, data []byte) error {
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

func writePrivateFrame(ctx context.Context, output *os.File, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > maxPrivateFrame {
		return errInvalidState
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	return boundedFileIO(ctx, output, func(stream io.ReadWriter) error {
		if err := writeAll(stream, header[:]); err != nil {
			return err
		}
		return writeAll(stream, data)
	})
}

func readPrivateFrame(ctx context.Context, input *os.File, value any) error {
	return boundedFileIO(ctx, input, func(stream io.ReadWriter) error {
		var header [4]byte
		if _, err := io.ReadFull(stream, header[:]); err != nil {
			return err
		}
		size := binary.BigEndian.Uint32(header[:])
		if size == 0 || size > maxPrivateFrame {
			return errInvalidState
		}
		data := make([]byte, int(size))
		if _, err := io.ReadFull(stream, data); err != nil {
			return err
		}
		return decodeJSON(data, value)
	})
}
