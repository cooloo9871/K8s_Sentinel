import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  ReactFlow, Background, Controls, MiniMap,
  type Edge, type NodeTypes, MarkerType,
  Handle, Position, useNodesState, useEdgesState,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import dagre from 'dagre'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import {
  Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import { IconRefresh, IconNetwork, IconAlertTriangle, IconSearch, IconLayoutGrid, IconWorld } from '@tabler/icons-react'

// ── Types ──────────────────────────────────────────────────────────────────

interface TopologyNode {
  id: string
  label: string
  pod: string
  namespace: string
  kind: 'pod' | 'external' | 'node'
  ip?: string
  viaNode?: string
  // Static attack-surface paths (NodePort/LB/Ingress/hostNetwork), pod nodes only
  exposures?: { type: string; detail: string }[]
  // Derived client-side: this pod receives traffic from an ext: source
  extInbound?: boolean
}

interface TopologyEdge {
  id: string
  source: string
  target: string
  destIp?: string
  count: number
  blocked: boolean
  // The policy that denied the traffic, when one can be identified
  deniedBy?: string
  healthProbe?: boolean
  // Aggregated per-port breakdown (count-desc); ephemeral ports appear as "dynamic"
  ports?: { port: string; count: number }[]
  // L7 (populated from Cilium/Hubble data)
  l7Type?: string
  httpMethod?: string
  httpURL?: string
  httpStatus?: number
  dnsQuery?: string
}

interface TopologyResponse {
  nodes: TopologyNode[]
  edges: TopologyEdge[]
  hasNetworkEvents: boolean
  flowsEverSeen?: boolean
  dataSource?: string
  partialResolution?: boolean
}

// ── Custom node: pod ───────────────────────────────────────────────────────

function PodNode({ data }: { data: TopologyNode }) {
  const exposed = (data.exposures?.length ?? 0) > 0
  // External traffic arriving at a pod with no declared exposure path is a
  // security signal (config drift, hostPort bypass, or an active probe).
  const anomaly = !!data.extInbound && !exposed
  const border = anomaly ? 'border-red-500/70' : exposed ? 'border-amber-500/60' : 'border-primary/40'
  return (
    <div className={`relative rounded-lg border ${border} bg-background px-3 py-2 shadow-sm min-w-[120px] text-center`}>
      <Handle type="target" position={Position.Left} className="!bg-primary" />
      {anomaly
        ? <IconAlertTriangle size={12} className="absolute right-1 top-1 text-red-500" />
        : exposed && <IconWorld size={12} className="absolute right-1 top-1 text-amber-500" />}
      <div className="text-[10px] text-muted-foreground mb-0.5">{data.namespace}</div>
      <div className="text-xs font-medium truncate max-w-[140px]" title={data.pod}>{data.pod}</div>
      <Handle type="source" position={Position.Right} className="!bg-primary" />
    </div>
  )
}

// ── Custom node: Kubernetes node ──────────────────────────────────────────

function NodeHostNode({ data }: { data: TopologyNode }) {
  return (
    <div className="rounded-lg border border-slate-400/40 bg-slate-400/5 px-3 py-2 shadow-sm min-w-[120px] text-center">
      <Handle type="target" position={Position.Left} className="!bg-slate-500" />
      <div className="text-[10px] text-slate-500 mb-0.5">Node</div>
      <div className="text-xs font-medium truncate max-w-[140px]" title={data.label}>{data.label}</div>
      {data.ip && <div className="text-[10px] font-mono text-slate-400">{data.ip}</div>}
      <Handle type="source" position={Position.Right} className="!bg-slate-500" />
    </div>
  )
}

// ── Custom node: external IP ───────────────────────────────────────────────

function ExternalNode({ data }: { data: TopologyNode }) {
  return (
    <div className="rounded-lg border border-amber-500/40 bg-amber-500/5 px-3 py-2 shadow-sm min-w-[110px] text-center">
      {/* External can be both a connection target (pod→ext) and a source (ext→pod inbound) */}
      <Handle type="target" position={Position.Left} className="!bg-amber-500" />
      <div className="text-[10px] text-amber-600 mb-0.5">External</div>
      <div className="text-xs font-medium font-mono">{data.label}</div>
      <Handle type="source" position={Position.Right} className="!bg-amber-500" />
    </div>
  )
}

const nodeTypes: NodeTypes = {
  pod: PodNode as any,
  node: NodeHostNode as any,
  external: ExternalNode as any,
}

// ── Layout helper ──────────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function layoutNodes(apiNodes: TopologyNode[]): any[] {
  const pods = apiNodes.filter(n => n.kind === 'pod')
  const nodes = apiNodes.filter(n => n.kind === 'node')
  const externals = apiNodes.filter(n => n.kind === 'external')
  return [
    ...pods.map((n, i) => ({ id: n.id, type: 'pod', position: { x: 80, y: 80 + i * 100 }, data: n })),
    ...nodes.map((n, i) => ({ id: n.id, type: 'node', position: { x: 380, y: 80 + i * 100 }, data: n })),
    ...externals.map((n, i) => ({ id: n.id, type: 'external', position: { x: 680, y: 80 + i * 80 }, data: n })),
  ]
}

interface EdgeVisualData {
  count: number
  blocked: boolean
  l7Type?: string
  color: string
}

// edgeVisuals derives an edge's visual props from its data payload and the
// current focus target. Labels are hidden by default (they dominate visual
// clutter on dense graphs) and appear only on the focused node's edges;
// blocked edges always keep their label. Unrelated edges dim under focus.
function edgeVisuals(e: Edge, focusId: string | null): Edge {
  const d = (e.data ?? {}) as unknown as EdgeVisualData
  const focused = !focusId || e.source === focusId || e.target === focusId
  const dimmed = !!focusId && !focused
  if (d.blocked) {
    return {
      ...e,
      label: `×${d.count} ✕`,
      animated: false,
      style: { stroke: '#ef4444', strokeWidth: 1.5, strokeDasharray: '5 3', opacity: dimmed ? 0.12 : 1 },
      labelStyle: { fontSize: 10, fill: '#ef4444', fontWeight: 600, opacity: dimmed ? 0.2 : 1 },
      labelBgStyle: { fill: '#fef2f2', borderRadius: 4 },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#ef4444', width: 18, height: 18 },
    }
  }
  const showLabel = !!focusId && focused
  const l7badge = d.l7Type ? ` [${d.l7Type}]` : ''
  return {
    ...e,
    label: showLabel ? `×${d.count}${l7badge}` : undefined,
    animated: !dimmed,
    style: { stroke: d.color, strokeWidth: d.l7Type ? 2 : 1.5, opacity: dimmed ? 0.12 : 1 },
    labelStyle: { fontSize: 10, fill: d.l7Type ? '#3b82f6' : '#6b7280', fontWeight: d.l7Type ? 600 : 400 },
    labelBgStyle: { fill: d.l7Type ? '#eff6ff' : '#f9fafb', borderRadius: 4 },
    markerEnd: { type: MarkerType.ArrowClosed, color: d.color, width: 18, height: 18 },
  }
}

function layoutEdges(apiEdges: TopologyEdge[], nodeMap: Record<string, TopologyNode>): Edge[] {
  return apiEdges.map(e => {
    const targetKind = nodeMap[e.target]?.kind ?? 'external'
    const color = targetKind === 'external' ? '#f59e0b' : '#6366f1'
    const base: Edge = {
      id: e.id,
      source: e.source,
      target: e.target,
      data: { count: e.count, blocked: e.blocked, l7Type: e.l7Type, color },
    }
    return edgeVisuals(base, null)
  })
}

// ── Dagre auto-layout ──────────────────────────────────────────────────────

const NODE_WIDTH  = 160
const NODE_HEIGHT = 60

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function applyDagreLayout(nodes: any[], edges: any[]): any[] {
  const g = new dagre.graphlib.Graph()
  g.setDefaultEdgeLabel(() => ({}))
  g.setGraph({
    rankdir: 'LR',   // left → right flow
    nodesep: 50,     // vertical gap between nodes in the same rank
    ranksep: 120,    // horizontal gap between ranks
    marginx: 40,
    marginy: 40,
  })

  nodes.forEach(n => g.setNode(n.id, { width: NODE_WIDTH, height: NODE_HEIGHT }))
  edges.forEach(e => {
    // dagre ignores duplicate edges; just register source→target
    if (e.source !== e.target) g.setEdge(e.source, e.target)
  })

  dagre.layout(g)

  return nodes.map(n => {
    const pos = g.node(n.id)
    return {
      ...n,
      position: {
        x: pos.x - NODE_WIDTH  / 2,
        y: pos.y - NODE_HEIGHT / 2,
      },
    }
  })
}

// ── Page ───────────────────────────────────────────────────────────────────

export function NetworkTopologyPage() {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [nodes, setNodes, onNodesChange] = useNodesState<any>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState<any>([])
  const reactFlowRef = useRef<{ fitView: () => void } | null>(null)
  const [hasNetworkEvents, setHasNetworkEvents] = useState<boolean | null>(null)
  const [flowsEverSeen, setFlowsEverSeen] = useState(false)
  const [partialResolution, setPartialResolution] = useState(false)
  const [dataSource, setDataSource] = useState<string | undefined>()
  const [loading, setLoading] = useState(true)
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null)
  const [selectedEdge, setSelectedEdge] = useState<TopologyEdge | null>(null)
  const [nsFilter, setNsFilter] = useState('all')
  const [podSearch, setPodSearch] = useState('')
  // System namespaces are mostly control-plane noise (coredns, operators);
  // hidden by default, and auto-shown when kube-system is explicitly selected.
  const [hideSystem, setHideSystem] = useState(true)
  // The kubelet checking each pod is constant, uniform and says nothing about
  // how workloads talk to each other, so it is out of the way by default —
  // available because it is exactly what a whitelist ingress policy blocks.
  const [hideProbes, setHideProbes] = useState(true)
  // Show only pods with a declared exposure path (attack-surface audit view)
  const [exposedOnly, setExposedOnly] = useState(false)
  // Hover focus: highlight the hovered node's edges, dim everything else
  const [hoverId, setHoverId] = useState<string | null>(null)
  const adjacencyRef = useRef<Record<string, Set<string>>>({})

  // Raw data from API — source of truth for filtering
  const [rawNodes, setRawNodes] = useState<TopologyNode[]>([])
  const [rawEdges, setRawEdges] = useState<TopologyEdge[]>([])

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await fetch('/api/network-topology', { credentials: 'include', cache: 'no-store' })
      const data: TopologyResponse = await res.json()
      setHasNetworkEvents(data.hasNetworkEvents)
      setFlowsEverSeen(!!data.flowsEverSeen)
      setPartialResolution(!!data.partialResolution)
      setDataSource(data.dataSource)
      setRawNodes(data.nodes)
      setRawEdges(data.edges)
    } catch {
      setHasNetworkEvents(false)
      // The API is unreachable, so nothing is known about Hubble either — the
      // setup guidance is the more useful of the two messages.
      setFlowsEverSeen(false)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    // Auto-refresh every 30s so new connections appear without manual reload
    const timer = setInterval(() => load(), 30_000)
    return () => clearInterval(timer)
  }, [load])

  // Namespaces available for filter
  const namespaces = useMemo(() =>
    [...new Set(rawNodes.filter(n => n.kind === 'pod').map(n => n.namespace).filter(Boolean))].sort()
  , [rawNodes])

  // Apply search filters and re-layout
  useEffect(() => {
    const podQ = podSearch.trim().toLowerCase()

    const visibleEdges = hideProbes ? rawEdges.filter(e => !e.healthProbe) : rawEdges

    // Hide kube-system unless the user explicitly filters to it
    const effectiveHide = hideSystem && nsFilter !== 'kube-system'
    const scopedNodes = effectiveHide
      ? rawNodes.filter(n => n.namespace !== 'kube-system')
      : rawNodes
    const scopedIds = new Set(scopedNodes.map(n => n.id))
    const scopedEdges = effectiveHide
      ? visibleEdges.filter(e => scopedIds.has(e.source) && scopedIds.has(e.target))
      : visibleEdges

    // "Primary" nodes: pods matching the filter criteria.
    // external and node kinds are never seeds — they are pulled in by
    // connections to/from primary nodes (they have no namespace).
    const isPrimary = (n: TopologyNode): boolean => {
      if (n.kind === 'external' || n.kind === 'node') return false
      if (nsFilter !== 'all' && n.namespace !== nsFilter) return false
      if (exposedOnly && !(n.exposures?.length)) return false
      if (podQ) {
        const nameMatch =
          n.pod.toLowerCase().includes(podQ) ||
          n.label.toLowerCase().includes(podQ)
        if (!nameMatch) return false
      }
      return true
    }

    // When no filter is active, all pods are primary
    const noFilter = nsFilter === 'all' && !podQ && !exposedOnly
    const primaryIds = new Set(
      noFilter
        ? scopedNodes.filter(n => n.kind !== 'external' && n.kind !== 'node').map(n => n.id)
        : scopedNodes.filter(isPrimary).map(n => n.id)
    )

    // Include ALL edges where at least one end is a primary node.
    // This expands the view to show the complete connection path,
    // even if the other end is in a different namespace.
    const candidateEdges = scopedEdges.filter(e =>
      primaryIds.has(e.source) || primaryIds.has(e.target)
    )

    // If the same (source, target) pair has both a blocked and an allowed edge,
    // keep only the blocked one — it's more informative and the allowed events
    // likely predate when the policy was set to Protect mode.
    const blockedKeys = new Set(
      candidateEdges.filter(e => e.blocked).map(e => `${e.source}|${e.target}`)
    )
    const filteredEdges = candidateEdges.filter(e =>
      e.blocked || !blockedKeys.has(`${e.source}|${e.target}`)
    )

    // Collect every node referenced by the filtered edges
    const connectedIds = new Set(filteredEdges.flatMap(e => [e.source, e.target]))

    // Visible = anything reachable via filtered edges
    // (external nodes appear only when they have a connection)
    // Mark pods receiving traffic from an ext: source so PodNode can flag
    // undeclared exposure (ext traffic without any exposure path).
    const extInboundTargets = new Set(
      filteredEdges.filter(e => e.source.startsWith('ext:')).map(e => e.target)
    )
    const visibleNodes = scopedNodes
      .filter(n => connectedIds.has(n.id))
      .map(n => n.kind === 'pod' ? { ...n, extInbound: extInboundTargets.has(n.id) } : n)

    // Adjacency map for hover-focus dimming
    const adj: Record<string, Set<string>> = {}
    for (const e of filteredEdges) {
      ;(adj[e.source] ??= new Set()).add(e.target)
      ;(adj[e.target] ??= new Set()).add(e.source)
    }
    adjacencyRef.current = adj

    // Use dagre by default for proper edge routing; fall back to column layout if dagre fails
    const baseNodes = layoutNodes(visibleNodes)
    const laidOut = visibleNodes.length > 0 ? applyDagreLayout(baseNodes, filteredEdges) : baseNodes
    setNodes(laidOut)
    const nodeMap = Object.fromEntries(visibleNodes.map(n => [n.id, n]))
    setEdges(layoutEdges(filteredEdges, nodeMap))
    // Fit view after layout so nodes are always visible (especially on first load
    // or when switching from Tetragon→Cilium data source)
    setTimeout(() => reactFlowRef.current?.fitView(), 100)
    // Clear selectedNode if it's no longer visible after filter change
    setSelectedNode(prev => prev && nodeMap[prev.id] ? prev : null)
  }, [rawNodes, rawEdges, nsFilter, podSearch, hideSystem, hideProbes, exposedOnly, setNodes, setEdges])

  // Hover / selection focus: highlight the focused node's edges + neighbors,
  // dim everything else. Labels appear only on focused edges.
  useEffect(() => {
    const focusId = hoverId ?? selectedNode?.id ?? null
    setEdges(eds => eds.map(e => edgeVisuals(e, focusId)))
    setNodes(nds => nds.map(n => {
      const dim = !!focusId && n.id !== focusId && !adjacencyRef.current[focusId]?.has(n.id)
      return { ...n, style: { ...(n.style ?? {}), opacity: dim ? 0.25 : 1 } }
    }))
  }, [hoverId, selectedNode, setEdges, setNodes])

  const matchCount = useMemo(() => {
    const podQ = podSearch.trim().toLowerCase()
    if (nsFilter === 'all' && !podQ) return null
    return rawNodes.filter(n =>
      n.kind === 'pod' &&
      (nsFilter === 'all' || n.namespace === nsFilter) &&
      (!podQ || n.pod.toLowerCase().includes(podQ) || n.label.toLowerCase().includes(podQ))
    ).length
  }, [rawNodes, nsFilter, podSearch])

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const onNodeClick = useCallback((_: React.MouseEvent, node: any) => {
    setSelectedEdge(null)
    setSelectedNode(node.data as TopologyNode)
  }, [])

  const onEdgeClick = useCallback((_: React.MouseEvent, edge: any) => {
    setSelectedNode(null)
    const raw = rawEdges.find(e => e.id === edge.id)
    setSelectedEdge(raw ?? null)
  }, [rawEdges])

  const autoLayout = useCallback(() => {
    setNodes(prev => {
      const laid = applyDagreLayout(prev, edges)
      return laid
    })
    // fitView after layout settles
    setTimeout(() => reactFlowRef.current?.fitView(), 50)
  }, [edges, setNodes])

  return (
    <>
      <div className="mb-4 flex items-start justify-between">
        <div>
          <h4 className="text-xl font-semibold">Network Topology</h4>
          <p className="text-sm text-muted-foreground">
            Live pod connections from Cilium Hubble flows, over the last 15 minutes
          </p>
        </div>
        <div className="flex items-center gap-2">
          {dataSource === 'cilium' && (
            <span className="rounded-full border border-blue-200 bg-blue-50 px-2.5 py-0.5 text-[11px] font-medium text-blue-700">
              Cilium · L7
            </span>
          )}
          <Button variant="outline" size="sm" onClick={autoLayout} disabled={nodes.length === 0}>
            <IconLayoutGrid size={14} className="mr-1.5" />
            Auto Layout
          </Button>
          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            <IconRefresh size={14} className="mr-1.5" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Filter bar */}
      <div className="mb-4 flex items-center gap-2">
        <Select value={nsFilter} onValueChange={setNsFilter}>
          <SelectTrigger className="h-8 w-44">
            <SelectValue placeholder="All Namespaces" />
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              <SelectItem value="all">All Namespaces</SelectItem>
              {namespaces.map(ns => (
                <SelectItem key={ns} value={ns}>{ns}</SelectItem>
              ))}
            </SelectGroup>
          </SelectContent>
        </Select>
        <div className="relative">
          <IconSearch size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Pod name..."
            value={podSearch}
            onChange={e => setPodSearch(e.target.value)}
            className="h-8 w-44 pl-8 text-sm"
          />
        </div>
        <label className="flex cursor-pointer select-none items-center gap-1.5 text-xs text-muted-foreground">
          <Checkbox
            checked={hideSystem}
            onCheckedChange={v => setHideSystem(v === true)}
            className="size-3.5"
          />
          Hide kube-system
        </label>
        <label className="flex cursor-pointer select-none items-center gap-1.5 text-xs text-muted-foreground">
          <Checkbox
            checked={hideProbes}
            onCheckedChange={v => setHideProbes(v === true)}
            className="size-3.5"
          />
          Hide health probes
        </label>
        <label className="flex cursor-pointer select-none items-center gap-1.5 text-xs text-muted-foreground">
          <Checkbox
            checked={exposedOnly}
            onCheckedChange={v => setExposedOnly(v === true)}
            className="size-3.5"
          />
          Exposed only
        </label>
        {matchCount !== null && (
          <span className="text-xs text-muted-foreground">
            {matchCount} match{matchCount !== 1 ? 'es' : ''}
          </span>
        )}
        {(nsFilter !== 'all' || podSearch) && (
          <Button variant="ghost" size="sm" className="h-8 text-xs"
            onClick={() => { setNsFilter('all'); setPodSearch('') }}>
            Clear
          </Button>
        )}
        <div className="ml-auto flex items-center gap-4 text-xs text-muted-foreground">
          <span className="flex items-center gap-1.5">
            <span className="size-2.5 rounded border border-primary/40 bg-primary/10 inline-block" />
            Pod
          </span>
          <span className="flex items-center gap-1.5">
            <span className="size-2.5 rounded border border-slate-400/40 bg-slate-400/10 inline-block" />
            Node
          </span>
          <span className="flex items-center gap-1.5">
            <span className="size-2.5 rounded border border-amber-500/40 bg-amber-500/10 inline-block" />
            External
          </span>
          <span className="flex items-center gap-1">
            <IconWorld size={12} className="text-amber-500" />
            Exposed
          </span>
          <span className="flex items-center gap-1">
            <svg width="28" height="8"><line x1="0" y1="4" x2="22" y2="4" stroke="#6366f1" strokeWidth="1.5" /><polygon points="22,1 28,4 22,7" fill="#6366f1" /></svg>
            Pod
          </span>
          <span className="flex items-center gap-1">
            <svg width="28" height="8"><line x1="0" y1="4" x2="22" y2="4" stroke="#f59e0b" strokeWidth="1.5" /><polygon points="22,1 28,4 22,7" fill="#f59e0b" /></svg>
            External
          </span>
          <span className="flex items-center gap-1">
            <svg width="28" height="8"><line x1="0" y1="4" x2="22" y2="4" stroke="#ef4444" strokeWidth="1.5" strokeDasharray="5 3" /><polygon points="22,1 28,4 22,7" fill="#ef4444" /></svg>
            Blocked
          </span>
        </div>
      </div>

      {/* No network events — guide user */}
      {partialResolution && (
        <Card className="mb-4 border-yellow-500/30 bg-yellow-500/5">
          <CardContent className="flex items-center gap-3 p-3">
            <IconAlertTriangle size={16} className="shrink-0 text-yellow-600" />
            <p className="text-xs text-yellow-700">
              IP name resolution is degraded — some cluster IPs could not be resolved to pod/service names and appear as External nodes. Check K8s Sentinel RBAC permissions (requires <code className="font-mono">services list</code>).
            </p>
          </CardContent>
        </Card>
      )}

      {!loading && hasNetworkEvents === false && flowsEverSeen && (
        <Card className="mb-4">
          <CardContent className="flex items-start gap-3 p-4">
            <IconNetwork size={18} className="mt-0.5 shrink-0 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">
              No traffic in the last 15 minutes. The graph shows current connections, so it
              fills in again as soon as pods talk to each other.
            </p>
          </CardContent>
        </Card>
      )}

      {!loading && hasNetworkEvents === false && !flowsEverSeen && (
        <Card className="mb-4 border-amber-500/30 bg-amber-500/5">
          <CardContent className="flex items-start gap-3 p-4">
            <IconAlertTriangle size={18} className="mt-0.5 shrink-0 text-amber-600" />
            <div className="flex flex-col gap-1">
              <p className="text-sm font-medium text-amber-700">No network connections recorded yet</p>
              <p className="text-xs text-amber-600">
                Network Topology is built from Cilium Hubble flows. Confirm the cluster runs Cilium
                as its CNI with the Hubble agent enabled:
              </p>
              <pre className="mt-1 overflow-x-auto rounded bg-amber-500/10 px-2 py-1.5 font-mono text-[11px] text-amber-700">
{`cilium install --version 1.18.3 \\
  --set kubeProxyReplacement=true \\
  --set k8sServiceHost=<api-server-ip> --set k8sServicePort=6443 \\
  --set hubble.enabled=true`}
              </pre>
              <p className="mt-0.5 text-xs text-amber-600">
                <span className="font-medium">kubeProxyReplacement</span> is what lets Hubble observe
                NodePort traffic before SNAT, so inbound connections show their real source IP.
                No Hubble UI or Relay is needed — K8s Sentinel reads the agent socket directly.
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="flex gap-4" style={{ height: 'calc(100vh - 220px)' }}>
        {/* Graph */}
        <div className="flex-1 overflow-hidden rounded-lg border bg-background">
          {loading ? (
            <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
              <IconNetwork size={32} className="mr-2 opacity-30" />
              Loading topology...
            </div>
          ) : nodes.length === 0 ? (
            <div className="flex h-full flex-col items-center justify-center gap-2 text-muted-foreground">
              <IconNetwork size={40} strokeWidth={1.5} />
              <p className="text-sm">No connections to display</p>
            </div>
          ) : (
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onNodeClick={onNodeClick}
              onEdgeClick={onEdgeClick}
              onNodeMouseEnter={(_: React.MouseEvent, n: { id: string }) => setHoverId(n.id)}
              onNodeMouseLeave={() => setHoverId(null)}
              onInit={(instance: any) => { reactFlowRef.current = instance }}
              nodeTypes={nodeTypes}
              fitView
              fitViewOptions={{ padding: 0.2 }}
            >
              <Background gap={16} size={1} />
              <Controls />
              <MiniMap nodeColor={n => n.type === 'external' ? '#f59e0b' : n.type === 'node' ? '#64748b' : '#6366f1'} />
            </ReactFlow>
          )}
        </div>

        {/* Side panel — node or edge detail */}
        {(selectedNode || selectedEdge) && (
          <div className="w-64 shrink-0">
            <Card className="h-full">
              <CardContent className="p-4">
                <div className="mb-3 flex items-center justify-between">
                  <span className="text-sm font-semibold">
                    {selectedEdge ? 'Connection Detail'
                      : selectedNode?.kind === 'external' ? 'External IP'
                      : selectedNode?.kind === 'node' ? 'Node Detail'
                      : 'Pod Detail'}
                  </span>
                  <button
                    type="button"
                    onClick={() => { setSelectedNode(null); setSelectedEdge(null) }}
                    className="text-xs text-muted-foreground hover:text-foreground"
                  >
                    ✕
                  </button>
                </div>

                {selectedNode && (
                  <div className="flex flex-col gap-2 text-xs">
                    <div>
                      <span className="text-muted-foreground">Type</span>
                      <div className="mt-0.5">
                        <Badge variant={selectedNode.kind === 'external' || selectedNode.kind === 'node' ? 'secondary' : 'default'} className="text-[10px]">
                          {selectedNode.kind === 'external' ? 'External IP' : selectedNode.kind === 'node' ? 'Node' : 'Pod'}
                        </Badge>
                      </div>
                    </div>
                  {selectedNode.kind === 'pod' && (
                      <>
                        <div>
                          <span className="text-muted-foreground">Pod</span>
                          <div className="mt-0.5 font-mono font-medium break-all">{selectedNode.label}</div>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Namespace</span>
                          <div className="mt-0.5 font-mono">{selectedNode.namespace}</div>
                        </div>
                        {selectedNode.ip && (
                          <div>
                            <span className="text-muted-foreground">IP</span>
                            <div className="mt-0.5 font-mono">{selectedNode.ip}</div>
                          </div>
                        )}
                        {selectedNode.exposures && selectedNode.exposures.length > 0 && (
                          <div>
                            <span className="text-muted-foreground">Exposure</span>
                            <div className="mt-1 flex flex-col gap-1">
                              {selectedNode.exposures.map((x, i) => (
                                <div key={i} className="flex items-start gap-1.5">
                                  <span className="shrink-0 rounded bg-amber-500/10 px-1 py-0.5 text-[9px] font-medium uppercase text-amber-700">{x.type}</span>
                                  <span className="break-all font-mono text-[11px]">{x.detail}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                        {selectedNode.extInbound && !(selectedNode.exposures?.length) && (
                          <div className="mt-1 rounded bg-red-50 px-2 py-1.5 text-[11px] font-medium text-red-600">
                            ⚠ Receiving external traffic without any declared exposure path
                          </div>
                        )}
                      </>
                    )}
                    {/* The address of an SNATed inbound connection belongs to the
                        ingress node, not the client — without saying so it reads
                        as the client's. */}
                    {selectedNode.viaNode && (
                      <div className="rounded bg-amber-50 px-2 py-1.5 text-[11px] text-amber-700">
                        Arrived through node <span className="font-mono">{selectedNode.viaNode}</span>,
                        which replaced the client address. Cilium reports the source as outside the
                        cluster, but the original IP is lost to SNAT — set the Service to
                        <span className="font-mono"> externalTrafficPolicy: Local</span>, or run Cilium
                        in DSR mode, to keep it.
                      </div>
                    )}
                    {selectedNode.kind === 'external' && (
                      <div>
                        <span className="text-muted-foreground">IP Address</span>
                        <div className="mt-0.5 font-mono font-medium">{selectedNode.label}</div>
                      </div>
                    )}
                    {selectedNode.kind === 'node' && (
                      <>
                        <div>
                          <span className="text-muted-foreground">Node</span>
                          <div className="mt-0.5 font-mono font-medium break-all">{selectedNode.label}</div>
                        </div>
                        {selectedNode.ip && (
                          <div>
                            <span className="text-muted-foreground">IP Address</span>
                            <div className="mt-0.5 font-mono">{selectedNode.ip}</div>
                          </div>
                        )}
                      </>
                    )}
                    <div className="pt-1 text-[11px] text-muted-foreground">
                      {(() => {
                        const n = rawEdges.filter(e => e.source === selectedNode.id || e.target === selectedNode.id).length
                        return `${n} connection${n !== 1 ? 's' : ''}`
                      })()}
                    </div>
                  </div>
                )}

                {selectedEdge && (() => {
                  const srcNode = rawNodes.find(n => n.id === selectedEdge.source)
                  return (
                    <div className="flex flex-col gap-2 text-xs">
                      <div>
                        <span className="text-muted-foreground">From</span>
                        <div className="mt-0.5 font-mono font-medium break-all">{srcNode?.label ?? selectedEdge.source}</div>
                        {srcNode?.ip && <div className="font-mono text-muted-foreground">{srcNode.ip}</div>}
                      </div>
                      <div>
                        <span className="text-muted-foreground">To</span>
                        <div className="mt-0.5 font-mono font-medium">{selectedEdge.destIp ?? selectedEdge.target}</div>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Count</span>
                        <div className="mt-0.5">{selectedEdge.count} connection{selectedEdge.count !== 1 ? 's' : ''}</div>
                      </div>
                      {selectedEdge.ports && selectedEdge.ports.length > 0 && (
                        <div>
                          <span className="text-muted-foreground">Ports</span>
                          <div className="mt-1 flex flex-col gap-0.5">
                            {selectedEdge.ports.map(p => (
                              <div key={p.port} className="flex justify-between font-mono text-[11px]">
                                <span>{p.port === 'dynamic' ? 'dynamic (ephemeral)' : p.port}</span>
                                <span className="text-muted-foreground">×{p.count}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      {selectedEdge.l7Type && (
                        <div>
                          <span className="text-muted-foreground">Protocol</span>
                          <div className="mt-0.5 flex items-center gap-1.5">
                            <span className="rounded bg-blue-500/10 px-1.5 py-0.5 text-[10px] font-medium text-blue-700">{selectedEdge.l7Type}</span>
                            {selectedEdge.httpMethod && <span className="font-mono font-medium">{selectedEdge.httpMethod}</span>}
                          </div>
                          {selectedEdge.httpURL && (
                            <div className="mt-0.5 font-mono text-[10px] text-muted-foreground truncate" title={selectedEdge.httpURL}>{selectedEdge.httpURL}</div>
                          )}
                          {selectedEdge.httpStatus !== undefined && selectedEdge.httpStatus > 0 && (
                            <div className={`mt-0.5 text-[10px] font-medium ${selectedEdge.httpStatus >= 400 ? 'text-red-600' : 'text-green-600'}`}>
                              HTTP {selectedEdge.httpStatus}
                            </div>
                          )}
                          {selectedEdge.dnsQuery && (
                            <div className="mt-0.5 font-mono text-[10px] text-muted-foreground">{selectedEdge.dnsQuery}</div>
                          )}
                        </div>
                      )}
                      {selectedEdge.blocked && (
                        <div className="mt-1 rounded bg-red-50 px-2 py-1.5 text-[11px] text-red-600">
                          <div className="font-medium">✕ Blocked by policy</div>
                          {selectedEdge.deniedBy
                            ? <div className="mt-0.5 break-all font-mono">{selectedEdge.deniedBy}</div>
                            : <div className="mt-0.5 text-red-500/80">
                                No policy could be identified. Either the traffic was dropped by
                                default deny with no rule naming this pod, or the policy that
                                dropped it no longer exists.
                              </div>}
                        </div>
                      )}
                    </div>
                  )
                })()}
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </>
  )
}
