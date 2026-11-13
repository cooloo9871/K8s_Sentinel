package k8s

import (
	"strings"
	"testing"
)

// kubeadm sets --cluster-cidr whatever the CNI; with Cilium allocating from its
// own pool, the pool is where the pods are.
func TestCiliumPoolIsThePodRangeOnlyWhenCiliumAllocates(t *testing.T) {
	cases := []struct {
		name string
		cfg  map[string]string
		want string
	}{
		{"cluster-pool", map[string]string{"ipam": "cluster-pool", "cluster-pool-ipv4-cidr": "10.0.0.0/8"}, "10.0.0.0/8"},
		{"default mode", map[string]string{"cluster-pool-ipv4-cidr": "10.0.0.0/8"}, "10.0.0.0/8"},
		{"several pools, dual stack", map[string]string{"ipam": "cluster-pool", "cluster-pool-ipv4-cidr": "10.0.0.0/9 10.128.0.0/9", "cluster-pool-ipv6-cidr": "fd00::/104"}, "10.0.0.0/9,10.128.0.0/9,fd00::/104"},
		{"kubernetes ipam", map[string]string{"ipam": "kubernetes", "cluster-pool-ipv4-cidr": "10.0.0.0/8"}, ""},
		{"no cilium", nil, ""},
	}
	for _, c := range cases {
		if got := strings.Join(ciliumPoolCIDRs(c.cfg), ","); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
