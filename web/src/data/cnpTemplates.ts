// Starter manifests for common Cilium network policy scenarios.
//
// These are deliberately raw YAML rather than a form builder: a network policy
// mistake causes an outage, so the operator should see exactly what will be
// applied. Every template carries an explicit warning where it introduces
// default-deny behaviour.

export interface CNPTemplate {
  id: string
  name: string
  description: string
  /** Shown as a warning banner when the template is selected. */
  caution?: string
  tags: string[]
  yaml: string
}

export const cnpTemplates: CNPTemplate[] = [
  {
    id: 'l7-http-visibility',
    name: 'L7 HTTP Visibility',
    description:
      'Routes a workload\'s HTTP traffic through the Cilium proxy so Hubble reports method, path and status code. Network Topology then shows [HTTP] on those edges.',
    caution:
      'Adds an ingress section, which switches the selected pods to ingress default-deny. The first rule allows all sources so nothing is blocked — keep it.',
    tags: ['l7', 'visibility'],
    yaml: `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: l7-http-visibility
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      app: my-app
  ingress:
    # Catch-all: keeps every source allowed despite default-deny
    - fromEntities:
        - all
    # Same sources again, but routed through the proxy on port 80 for L7 data
    - fromEntities:
        - all
      toPorts:
        - ports:
            - port: "80"
              protocol: TCP
          rules:
            http:
              - {}
`,
  },
  {
    id: 'namespace-isolation',
    name: 'Namespace Isolation',
    description:
      'Allows ingress only from pods in the same namespace. Cross-namespace traffic is dropped and appears as a red Blocked edge in Network Topology.',
    caution:
      'Enforcing. Anything outside this namespace — including ingress controllers and monitoring — loses access unless you add it below.',
    tags: ['isolation', 'enforcing'],
    yaml: `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: namespace-isolation
  namespace: default
spec:
  # Empty selector = every endpoint in this namespace
  endpointSelector: {}
  ingress:
    - fromEndpoints:
        # Empty selector under fromEndpoints means "same namespace"
        - {}
`,
  },
  {
    id: 'egress-dns-only',
    name: 'Egress: Cluster DNS Only',
    description:
      'Locks a workload down to cluster DNS and nothing else. Useful as the base layer before adding specific allowances.',
    caution:
      'Enforcing. The selected pods lose all egress except DNS — add the destinations they need before applying in production.',
    tags: ['egress', 'enforcing'],
    yaml: `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: egress-dns-only
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      app: my-app
  egress:
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: kube-system
            k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: UDP
          rules:
            dns:
              - matchPattern: "*"
`,
  },
  {
    id: 'egress-fqdn-allowlist',
    name: 'Egress: FQDN Allowlist',
    description:
      'Restricts outbound traffic to named domains. Cilium resolves the FQDN rules from observed DNS answers, so the DNS rule below is required.',
    caution:
      'Enforcing. Only the listed domains stay reachable — everything else is dropped.',
    tags: ['egress', 'fqdn', 'enforcing'],
    yaml: `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: egress-fqdn-allowlist
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      app: my-app
  egress:
    # DNS must be visible to the proxy for toFQDNs to resolve
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: kube-system
            k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: UDP
          rules:
            dns:
              - matchPattern: "*"
    - toFQDNs:
        - matchName: "api.github.com"
        - matchPattern: "*.googleapis.com"
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
`,
  },
  {
    id: 'allow-ingress-controller',
    name: 'Allow Ingress Controller Only',
    description:
      'Accepts ingress solely from the ingress controller, so the workload cannot be reached directly by other pods bypassing the routing layer.',
    caution:
      'Enforcing. Adjust the controller labels to match your installation (the defaults target ingress-nginx).',
    tags: ['ingress', 'enforcing'],
    yaml: `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-ingress-controller
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      app: my-app
  ingress:
    - fromEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: ingress-nginx
            app.kubernetes.io/name: ingress-nginx
      toPorts:
        - ports:
            - port: "80"
              protocol: TCP
`,
  },
  {
    id: 'deny-external-egress',
    name: 'Deny Egress Outside Cluster',
    description:
      'Blocks traffic leaving the cluster while leaving in-cluster communication untouched. A direct control against data exfiltration and C2 callbacks.',
    caution:
      'Enforcing. Workloads that legitimately call external APIs will break — pair it with an FQDN allowlist for those.',
    tags: ['egress', 'enforcing', 'exfiltration'],
    yaml: `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: deny-external-egress
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      app: my-app
  egressDeny:
    - toEntities:
        - world
`,
  },
  {
    id: 'cluster-wide-baseline',
    name: 'Cluster-wide: Allow DNS Everywhere',
    description:
      'A cluster-scoped policy every endpoint inherits. Apply it before namespace-level egress restrictions so DNS never becomes the thing that breaks.',
    tags: ['cluster-wide', 'baseline'],
    yaml: `apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: allow-dns-cluster-wide
spec:
  endpointSelector: {}
  egress:
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: kube-system
            k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: UDP
          rules:
            dns:
              - matchPattern: "*"
`,
  },
]
