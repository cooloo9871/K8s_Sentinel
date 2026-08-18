package k8s

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Events are collected over the Tetragon and Hubble gRPC APIs rather than by
// running their CLIs through `kubectl exec`. The exec transport required
// create on pods/exec cluster-wide, which is equivalent to running any command
// in any container — the direct cost of the old transport, removed with it.
//
// The wire messages are bridged back to the existing NDJSON parsers by
// marshaling each protobuf with the proto field names, which is exactly what
// `tetra getevents -o json` and `hubble observe -o json` do. protoNames
// reproduces their output, so parseTetragonLog and parseCiliumFlow are reused
// unchanged.
var protoNames = protojson.MarshalOptions{UseProtoNames: true}

// marshalJSON renders a protobuf message as the CLI would.
func marshalJSON(m proto.Message) (string, error) {
	b, err := protoNames.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// dialGRPC connects to an in-cluster gRPC endpoint. Insecure by default,
// because Tetragon's gRPC server ships without TLS and Sentinel reaches these
// endpoints over the cluster network it already trusts; setting the matching
// <PREFIX>_TLS env turns on TLS, with <PREFIX>_CA naming a CA file when the
// server certificate is not signed by a system root.
func dialGRPC(prefix, addr string) (*grpc.ClientConn, error) {
	creds := insecure.NewCredentials()
	if os.Getenv(prefix+"_TLS") == "true" {
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if caPath := os.Getenv(prefix + "_CA"); caPath != "" {
			pem, err := os.ReadFile(caPath)
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", prefix+"_CA", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("%s: no certificates found", prefix+"_CA")
			}
			cfg.RootCAs = pool
		}
		creds = credentials.NewTLS(cfg)
	}
	// NewClient connects lazily; the first RPC establishes the connection, and a
	// stream RPC that fails is what the reconnect loop retries on.
	return grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
}

// envOr returns the environment value, or a default when unset.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
