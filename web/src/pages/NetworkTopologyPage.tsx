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
import { Input } from '@/components/ui/input'
import {
  Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import { IconRefresh, IconNetwork, IconAlertTriangle, IconSearch, IconLayoutGrid } from '@tabler/icons-react'

// ── Types ──────────────────────────────────────────────────────────────────

interface TopologyNode {
  id: string
  label: string
  pod: string
  namespace: string
  kind: 'pod' | 'service' | 'external'
  ip?: string
  backingPods?: string[]
}

interface TopologyEdge {
  id: string
  source: string
  target: string
  destIp?: string
  port?: string
  count: number
  blocked: boolean
}

interface TopologyResponse {
  nodes: TopologyNode[]
  edges: TopologyEdge[]
  hasNetworkEvents: boolean
  partialResolution?: boolean
}

// ── Custom node: pod ───────────────────────────────────────────────────────

function PodNode({ data }: { data: TopologyNode }) {
  return (
    <div className="rounded-lg border border-primary/40 bg-background px-3 py-2 shadow-sm min-w-[120px] text-center">
      <Handle type="target" position={Position.Left} className="!bg-primary" />
      <div className="text-[10px] text-muted-foreground mb-0.5">{data.namespace}</div>
      <div className="text-xs font-medium truncate max-w-[140px]" title={data.pod}>{data.pod}</div>
      <Handle type="source" position={Position.Right} className="!bg-primary" />
    </div>
  )
}

// ── Custom node: service ──────────────────────────────────────────────────

function ServiceNode({ data }: { data: TopologyNode }) {
  return (
    <div className="rounded-lg border border-green-500/40 bg-green-500/5 px-3 py-2 shadow-sm min-w-[120px] text-center">
      <Handle type="target" position={Position.Left} className="!bg-green-500" />
      <div className="text-[10px] text-green-700 mb-0.5">{data.namespace} / svc</div>
      <div className="text-xs font-medium truncate max-w-[140px]" title={data.label}>{data.label}</div>
      <Handle type="source" position={Position.Right} className="!bg-green-500" />
    </div>
  )
}

// ── Custom node: external IP ───────────────────────────────────────────────

function ExternalNode({ data }: { data: TopologyNode }) {
  return (
    <div className="rounded-lg border border-amber-500/40 bg-amber-500/5 px-3 py-2 shadow-sm min-w-[110px] text-center">
      <Handle type="target" position={Position.Left} className="!bg-amber-500" />
      <div className="text-[10px] text-amber-600 mb-0.5">External</div>
      <div className="text-xs font-medium font-mono">{data.label}</div>
    </div>
  )
}

const nodeTypes: NodeTypes = {
  pod: PodNode as any,
  service: ServiceNode as any,
  external: ExternalNode as any,
}

// ── Layout helper ──────────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function layoutNodes(apiNodes: TopologyNode[]): any[] {
  const pods = apiNodes.filter(n => n.kind === 'pod')
  const services = apiNodes.filter(n => n.kind === 'service')
  const externals = apiNodes.filter(n => n.kind === 'external')
  return [
    ...pods.map((n, i) => ({ id: n.id, type: 'pod', position: { x: 80, y: 80 + i * 100 }, data: n })),
    ...services.map((n, i) => ({ id: n.id, type: 'service', position: { x: 380, y: 80 + i * 100 }, data: n })),
    ...externals.map((n, i) => ({ id: n.id, type: 'external', position: { x: 680, y: 80 + i * 80 }, data: n })),
  ]
}

function layoutEdges(apiEdges: TopologyEdge[], nodeMap: Record<string, TopologyNode>): Edge[] {
  return apiEdges.map(e => {
    if (e.blocked) {
      return {
        id: e.id,
        source: e.source,
        target: e.target,
        label: `×${e.count} ✕`,
        animated: false,
        style: { stroke: '#ef4444', strokeWidth: 1.5, strokeDasharray: '5 3' },
        labelStyle: { fontSize: 10, fill: '#ef4444', fontWeight: 600 },
        labelBgStyle: { fill: '#fef2f2', borderRadius: 4 },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#ef4444', width: 18, height: 18 },
      }
    }
    const targetKind = nodeMap[e.target]?.kind ?? 'external'
    const color = targetKind === 'external' ? '#f59e0b'
                : targetKind === 'service'  ? '#22c55e'
                : '#6366f1'
    return {
      id: e.id,
      source: e.source,
      target: e.target,
      label: `×${e.count}`,
      animated: true,
      style: { stroke: color, strokeWidth: 1.5 },
      labelStyle: { fontSize: 10, fill: '#6b7280' },
      labelBgStyle: { fill: '#f9fafb', borderRadius: 4 },
      markerEnd: { type: MarkerType.ArrowClosed, color, width: 18, height: 18 },
    }
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
  const [partialResolution, setPartialResolution] = useState(false)
  const [loading, setLoading] = useState(true)
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null)
  const [selectedEdge, setSelectedEdge] = useState<TopologyEdge | null>(null)
  const [nsFilter, setNsFilter] = useState('all')
  const [podSearch, setPodSearch] = useState('')

  // Raw data from API — source of truth for filtering
  const [rawNodes, setRawNodes] = useState<TopologyNode[]>([])
  const [rawEdges, setRawEdges] = useState<TopologyEdge[]>([])

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await fetch('/api/network-topology', { credentials: 'include' })
      const data: TopologyResponse = await res.json()
      setHasNetworkEvents(data.hasNetworkEvents)
      setPartialResolution(!!data.partialResolution)
      setRawNodes(data.nodes)
      setRawEdges(data.edges)
    } catch {
      setHasNetworkEvents(false)
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
    [...new Set(rawNodes.filter(n => n.kind === 'pod' || n.kind === 'service').map(n => n.namespace).filter(Boolean))].sort()
  , [rawNodes])

  // Apply search filters and re-layout
  useEffect(() => {
    const podQ = podSearch.trim().toLowerCase()

    // "Primary" nodes: pods/services/nodes matching the filter criteria.
    // external kind is never a seed — pulled in by connections.
    // node kind is always primary (host processes aren't namespaced).
    const isPrimary = (n: TopologyNode): boolean => {
      if (n.kind === 'external') return false
      if (nsFilter !== 'all' && n.namespace !== nsFilter) return false
      if (podQ) {
        // Search both pod name and service label
        const nameMatch =
          n.pod.toLowerCase().includes(podQ) ||
          n.label.toLowerCase().includes(podQ)
        if (!nameMatch) return false
      }
      return true
    }

    // When no filter is active, all pods/services are primary
    const noFilter = nsFilter === 'all' && !podQ
    const primaryIds = new Set(
      noFilter
        ? rawNodes.filter(n => n.kind !== 'external').map(n => n.id)
        : rawNodes.filter(isPrimary).map(n => n.id)
    )

    // Include ALL edges where at least one end is a primary node.
    // This expands the view to show the complete connection path,
    // even if the other end is in a different namespace.
    const candidateEdges = rawEdges.filter(e =>
      primaryIds.has(e.source) || primaryIds.has(e.target)
    )

    // If the same (source, target, port) has both a blocked and an allowed edge,
    // keep only the blocked one — it's more informative and the allowed events
    // likely predate when the policy was set to Protect mode.
    const blockedKeys = new Set(
      candidateEdges.filter(e => e.blocked).map(e => `${e.source}|${e.target}|${e.port}`)
    )
    const filteredEdges = candidateEdges.filter(e =>
      e.blocked || !blockedKeys.has(`${e.source}|${e.target}|${e.port}`)
    )

    // Collect every node referenced by the filtered edges
    const connectedIds = new Set(filteredEdges.flatMap(e => [e.source, e.target]))

    // Visible = anything reachable via filtered edges
    // (external nodes appear only when they have a connection)
    const visibleNodes = rawNodes.filter(n => connectedIds.has(n.id))

    // Use dagre by default for proper edge routing; fall back to column layout if dagre fails
    const baseNodes = layoutNodes(visibleNodes)
    const laidOut = visibleNodes.length > 0 ? applyDagreLayout(baseNodes, filteredEdges) : baseNodes
    setNodes(laidOut)
    const nodeMap = Object.fromEntries(visibleNodes.map(n => [n.id, n]))
    setEdges(layoutEdges(filteredEdges, nodeMap))
    // Clear selectedNode if it's no longer visible after filter change
    setSelectedNode(prev => prev && nodeMap[prev.id] ? prev : null)
  }, [rawNodes, rawEdges, nsFilter, podSearch, setNodes, setEdges])

  const matchCount = useMemo(() => {
    const podQ = podSearch.trim().toLowerCase()
    if (nsFilter === 'all' && !podQ) return null
    return rawNodes.filter(n =>
      (n.kind === 'pod' || n.kind === 'service') &&
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
            Pod network connections observed via Tetragon kprobe events
          </p>
        </div>
        <div className="flex gap-2">
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
            placeholder="Pod / Service name..."
            value={podSearch}
            onChange={e => setPodSearch(e.target.value)}
            className="h-8 w-44 pl-8 text-sm"
          />
        </div>
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
            <span className="size-2.5 rounded border border-green-500/40 bg-green-500/10 inline-block" />
            Service
          </span>
          <span className="flex items-center gap-1.5">
            <span className="size-2.5 rounded border border-amber-500/40 bg-amber-500/10 inline-block" />
            External
          </span>
          <span className="flex items-center gap-1">
            <svg width="28" height="8"><line x1="0" y1="4" x2="22" y2="4" stroke="#6366f1" strokeWidth="1.5" /><polygon points="22,1 28,4 22,7" fill="#6366f1" /></svg>
            Pod
          </span>
          <span className="flex items-center gap-1">
            <svg width="28" height="8"><line x1="0" y1="4" x2="22" y2="4" stroke="#22c55e" strokeWidth="1.5" /><polygon points="22,1 28,4 22,7" fill="#22c55e" /></svg>
            Service
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

      {!loading && hasNetworkEvents === false && (
        <Card className="mb-4 border-amber-500/30 bg-amber-500/5">
          <CardContent className="flex items-start gap-3 p-4">
            <IconAlertTriangle size={18} className="mt-0.5 shrink-0 text-amber-600" />
            <div className="flex flex-col gap-1">
              <p className="text-sm font-medium text-amber-700">No network connections recorded yet</p>
              <p className="text-xs text-amber-600">
                Apply a network monitoring template from Tracing Policy → Templates:
              </p>
              <ul className="text-xs text-amber-600 list-disc ml-4 mt-0.5 space-y-0.5">
                <li><span className="font-semibold">Monitor Internal Network (Inside Cluster)</span> — pod-to-pod and pod-to-service connections</li>
                <li><span className="font-semibold">Monitor External Network (Outside Cluster)</span> — connections leaving the cluster</li>
              </ul>
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
              onInit={(instance: any) => { reactFlowRef.current = instance }}
              nodeTypes={nodeTypes}
              fitView
              fitViewOptions={{ padding: 0.2 }}
            >
              <Background gap={16} size={1} />
              <Controls />
              <MiniMap nodeColor={n => n.type === 'external' ? '#f59e0b' : n.type === 'service' ? '#22c55e' : '#6366f1'} />
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
                      : selectedNode?.kind === 'service' ? 'Service Detail'
                      : selectedNode?.kind === 'external' ? 'External IP'
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
                        <Badge variant={selectedNode.kind === 'external' ? 'secondary' : 'default'} className="text-[10px]">
                          {selectedNode.kind === 'external' ? 'External IP' : selectedNode.kind === 'service' ? 'Service' : 'Pod'}
                        </Badge>
                      </div>
                    </div>
                  {(selectedNode.kind === 'pod' || selectedNode.kind === 'service') && (
                      <>
                        <div>
                          <span className="text-muted-foreground">{selectedNode.kind === 'service' ? 'Service' : 'Pod'}</span>
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
                        {selectedNode.kind === 'service' && selectedNode.backingPods && selectedNode.backingPods.length > 0 && (
                          <div>
                            <span className="text-muted-foreground">Backing Pods</span>
                            <div className="mt-1 flex flex-col gap-0.5">
                              {selectedNode.backingPods.map(p => (
                                <div key={p} className="font-mono text-xs break-all">{p}</div>
                              ))}
                            </div>
                          </div>
                        )}
                      </>
                    )}
                    {selectedNode.kind === 'external' && (
                      <div>
                        <span className="text-muted-foreground">IP Address</span>
                        <div className="mt-0.5 font-mono font-medium">{selectedNode.label}</div>
                      </div>
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
                        {selectedEdge.port && <div className="font-mono text-muted-foreground">Port: {selectedEdge.port}</div>}
                      </div>
                      <div>
                        <span className="text-muted-foreground">Count</span>
                        <div className="mt-0.5">{selectedEdge.count} connection{selectedEdge.count !== 1 ? 's' : ''}</div>
                      </div>
                      {selectedEdge.blocked && (
                        <div className="mt-1 rounded bg-red-50 px-2 py-1 text-[11px] font-medium text-red-600">
                          ✕ Blocked by policy
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
