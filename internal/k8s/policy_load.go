package k8s

import (
	"context"
	"sync"
	"time"

	tetragon "github.com/cilium/tetragon/api/v1/tetragon"
)

// A policy that exists in the cluster is not thereby in force: each Tetragon
// agent loads it for its own node, and can fail to. Tetragon holds a fixed
// number of policies, and one past that is created, listed, and does nothing.
// The object says none of this, so the agents are asked.

// policyLoadTTL is how long an answer is reused, so that several people on the
// list page are one round of questions.
const policyLoadTTL = 10 * time.Second

type policyLoads struct {
	mu      sync.Mutex
	failed  map[string]string // "namespace/name" → why
	loaded  map[string]int    // "namespace/name" → agents that have it in force
	agents  int
	expires time.Time
}

// tracingPoliciesOn asks one agent for its policies. A variable so that a test
// can answer in its place.
var tracingPoliciesOn = func(ctx context.Context, agent podEndpoint) ([]*tetragon.TracingPolicyStatus, error) {
	conn, err := dialGRPC("TETRAGON_GRPC", agent.IP+":"+tetragonGRPCPort())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := tetragon.NewFineGuidanceSensorsClient(conn).ListTracingPolicies(ctx, &tetragon.ListTracingPoliciesRequest{})
	if err != nil {
		return nil, err
	}
	return res.GetPolicies(), nil
}

// readPolicyLoads asks every agent, at once. An agent that does not answer
// says nothing about any policy.
func (s *Store) readPolicyLoads(ctx context.Context) (failed map[string]string, loaded map[string]int, agents int) {
	failed, loaded = map[string]string{}, map[string]int{}
	if s.typed == nil {
		return failed, loaded, 0
	}
	pods, err := s.findAllTetragonPods(ctx)
	if err != nil {
		return failed, loaded, 0
	}
	answers := make([][]*tetragon.TracingPolicyStatus, len(pods))
	var wg sync.WaitGroup
	for i, p := range pods {
		wg.Add(1)
		go func() {
			defer wg.Done()
			answers[i], _ = tracingPoliciesOn(ctx, p)
		}()
	}
	wg.Wait()
	for _, policies := range answers {
		if policies == nil {
			continue
		}
		agents++
		for _, p := range policies {
			key := p.GetNamespace() + "/" + p.GetName()
			switch p.GetState() {
			case tetragon.TracingPolicyState_TP_STATE_LOAD_ERROR, tetragon.TracingPolicyState_TP_STATE_ERROR:
				if _, seen := failed[key]; !seen {
					failed[key] = p.GetError()
					if failed[key] == "" {
						failed[key] = "Tetragon did not load this policy"
					}
				}
			case tetragon.TracingPolicyState_TP_STATE_ENABLED:
				loaded[key]++
			}
		}
	}
	return failed, loaded, agents
}

// MarkInactive fills in, for each policy an agent failed to load, why. One
// that is still being loaded is left unmarked: only a failure is said.
func (s *Store) MarkInactive(ctx context.Context, records []PolicyRecord) {
	l := &s.policyLoads
	l.mu.Lock()
	if time.Now().After(l.expires) {
		l.failed, l.loaded, l.agents = s.readPolicyLoads(ctx)
		l.expires = time.Now().Add(policyLoadTTL)
	}
	failed := l.failed
	l.mu.Unlock()
	for i := range records {
		records[i].Inactive = failed[records[i].Namespace+"/"+records[i].Name]
	}
}
