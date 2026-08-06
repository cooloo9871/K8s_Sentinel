package k8s

import "testing"

// The pair that exposed the gap. A Gateway published at *.test.com:80, and a
// VirtualService whose hosts are ["*"] — which in Istio means "every host the
// attached Gateway serves", not "reachable under any name". Reporting the
// VirtualService's hosts verbatim showed a bare "*", which says nothing.
func TestAVirtualServiceWildcardTakesTheGatewaysHosts(t *testing.T) {
	gateways := map[string][]istioServer{
		"test/canary-gateway": {{hosts: []string{"*.test.com"}, port: 80, protocol: "HTTP"}},
	}
	got := istioReach([]string{"canary-gateway"}, "test", []string{"*"}, gateways)

	if len(got) != 1 {
		t.Fatalf("got %d addresses, want 1: %+v", len(got), got)
	}
	if got[0].host != "*.test.com" {
		t.Errorf("host = %q, want the Gateway's *.test.com", got[0].host)
	}
	if got[0].detail != "HTTP · 80" {
		t.Errorf("detail = %q, want the Gateway's port", got[0].detail)
	}
	if got[0].gateway != "test/canary-gateway" {
		t.Errorf("gateway = %q, want it namespace-qualified", got[0].gateway)
	}
}

// The more specific of the two wins, which is what Istio resolves to.
func TestHostsAreNarrowedToTheMoreSpecific(t *testing.T) {
	cases := []struct{ gateway, vs, want string }{
		{"*.test.com", "*", "*.test.com"},
		{"*", "app.test.com", "app.test.com"},
		{"*", "*", "*"},
		{"*.test.com", "app.test.com", "app.test.com"},
		{"app.test.com", "*.test.com", "app.test.com"},
		{"app.test.com", "app.test.com", "app.test.com"},
		{"*.test.com", "*.eu.test.com", "*.eu.test.com"},
		// Namespace-qualified Gateway hosts are a valid Istio form.
		{"test/*.test.com", "*", "*.test.com"},
		{"./app.test.com", "*", "app.test.com"},
		// No intersection: Istio ignores the route, so nothing is exposed.
		{"*.test.com", "app.other.com", ""},
		{"a.test.com", "b.test.com", ""},
		// A wildcard covers subdomains, not the bare suffix.
		{"*.test.com", "test.com", ""},
	}
	for _, c := range cases {
		if got := narrowHost(c.gateway, c.vs); got != c.want {
			t.Errorf("narrowHost(%q, %q) = %q, want %q", c.gateway, c.vs, got, c.want)
		}
	}
}

// A VirtualService naming a host its Gateway does not serve is inert. Reporting
// it would claim an exposure that does not exist.
func TestAHostTheGatewayDoesNotServeIsNotExposed(t *testing.T) {
	gateways := map[string][]istioServer{
		"test/canary-gateway": {{hosts: []string{"*.test.com"}, port: 80, protocol: "HTTP"}},
	}
	if got := istioReach([]string{"canary-gateway"}, "test", []string{"app.elsewhere.com"}, gateways); len(got) != 0 {
		t.Errorf("got %+v, want nothing — the Gateway does not serve that host", got)
	}
}

// One Gateway can publish several ports; each is a way in and each is listed.
func TestEveryServerOnAGatewayIsReported(t *testing.T) {
	gateways := map[string][]istioServer{
		"test/canary-gateway": {
			{hosts: []string{"*.test.com"}, port: 80, protocol: "HTTP"},
			{hosts: []string{"*.test.com"}, port: 443, protocol: "HTTPS"},
		},
	}
	got := istioReach([]string{"canary-gateway"}, "test", []string{"*"}, gateways)
	if len(got) != 2 {
		t.Fatalf("got %d addresses, want both servers: %+v", len(got), got)
	}
	if got[0].detail != "HTTP · 80" || got[1].detail != "HTTPS · 443" {
		t.Errorf("details = %q, %q — want both ports", got[0].detail, got[1].detail)
	}
}

// A Gateway in another namespace is referenced as "namespace/name".
func TestAGatewayInAnotherNamespaceIsResolved(t *testing.T) {
	gateways := map[string][]istioServer{
		"istio-system/shared": {{hosts: []string{"*.test.com"}, port: 80, protocol: "HTTP"}},
	}
	got := istioReach([]string{"istio-system/shared"}, "test", []string{"*"}, gateways)
	if len(got) != 1 || got[0].host != "*.test.com" {
		t.Fatalf("got %+v, want the shared Gateway's host", got)
	}
}

func TestGatewayReferenceForms(t *testing.T) {
	cases := []struct{ ref, defaultNs, wantNs, wantName string }{
		{"canary-gateway", "test", "test", "canary-gateway"},
		{"istio-system/shared", "test", "istio-system", "shared"},
		{"shared.istio-system.svc.cluster.local", "test", "istio-system", "shared"},
	}
	for _, c := range cases {
		ns, name := splitGatewayRef(c.ref, c.defaultNs)
		if ns != c.wantNs || name != c.wantName {
			t.Errorf("splitGatewayRef(%q) = %q/%q, want %q/%q", c.ref, ns, name, c.wantNs, c.wantName)
		}
	}
}

// A Gateway that cannot be read — absent, or no RBAC for it — must not silently
// erase the exposure. Something is still published; saying so imprecisely beats
// saying nothing at all in a view whose whole job is attack surface.
func TestAnUnreadableGatewayFallsBackToTheVirtualServiceHosts(t *testing.T) {
	got := istioReach([]string{"canary-gateway"}, "test", []string{"app.test.com"}, map[string][]istioServer{})
	if len(got) != 1 {
		t.Fatalf("got %d addresses, want the exposure kept: %+v", len(got), got)
	}
	if got[0].host != "app.test.com" {
		t.Errorf("host = %q, want the VirtualService's own host", got[0].host)
	}
	if got[0].detail != "" {
		t.Errorf("detail = %q, want none — the port is not knowable without the Gateway", got[0].detail)
	}
}

// A server with no hosts serves everything on its port.
func TestAServerWithNoHostsServesAnything(t *testing.T) {
	gateways := map[string][]istioServer{
		"test/gw": {{port: 8080, protocol: "HTTP"}},
	}
	got := istioReach([]string{"gw"}, "test", []string{"app.test.com"}, gateways)
	if len(got) != 1 || got[0].host != "app.test.com" {
		t.Fatalf("got %+v, want the VirtualService's host on the server's port", got)
	}
	if got[0].detail != "HTTP · 8080" {
		t.Errorf("detail = %q, want HTTP · 8080", got[0].detail)
	}
}
