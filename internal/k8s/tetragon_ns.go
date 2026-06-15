package k8s

import "os"

// tetragonNamespace returns the namespace where Tetragon is installed.
// Defaults to "kube-system"; override with TETRAGON_NAMESPACE env var.
func tetragonNamespace() string {
	if ns := os.Getenv("TETRAGON_NAMESPACE"); ns != "" {
		return ns
	}
	return "kube-system"
}
