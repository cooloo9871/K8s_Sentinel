import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  ReactFlow, Background, Controls, MiniMap,
  type Edge, type NodeTypes,
  Handle, Position, useNodesState, useEdgesState,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { IconRefresh, IconNetwork, IconAlertTriangle, IconSearch } from '@tabler/icons-react'

// ── Types ──────────────────────────────────────────────────────────────────

interface TopologyNode {
  id: string
  label: string
  pod: string
  namespace: string
  kind: 'pod' | 'external'
}

interface TopologyEdge {
  id: string
  source: string
  target: string
  port?: string
  count: number
}

interface TopologyResponse {
  nodes: TopologyNode[]
  edges: TopologyEdge[]
  hasNetworkEvents: boolean
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
  external: ExternalNode as any,
}

// ── Layout helper (simple force-like grid) ─────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function layoutNodes(apiNodes: TopologyNode[]): any[] {
  const pods = apiNodes.filter(n => n.kind === 'pod')
  const externals = apiNodes.filter(n => n.kind === 'external')
  return [
    ...pods.map((n, i) => ({ id: n.id, type: 'pod', position: { x: 100, y: 80 + i * 100 }, data: n })),
    ...externals.map((n, i) => ({ id: n.id, type: 'external', position: { x: 450, y: 80 + i * 80 }, data: n })),
  ]
}

function layoutEdges(apiEdges: TopologyEdge[]): Edge[] {
  return apiEdges.map(e => ({
    id: e.id,
    source: e.source,
    target: e.target,
    label: e.port ? `${e.port} ×${e.count}` : `×${e.count}`,
    animated: true,
    style: { stroke: '#6366f1' },
    labelStyle: { fontSize: 10, fill: '#6b7280' },
    labelBgStyle: { fill: '#f9fafb' },
  }))
}

// ── Page ───────────────────────────────────────────────────────────────────

export function NetworkTopologyPage() {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [nodes, setNodes, onNodesChange] = useNodesState<any>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState<any>([])
  const [hasNetworkEvents, setHasNetworkEvents] = useState<boolean | null>(null)
  const [loading, setLoading] = useState(true)
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null)
  const [nsSearch, setNsSearch] = useState('')
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
      setRawNodes(data.nodes)
      setRawEdges(data.edges)
    } catch {
      setHasNetworkEvents(false)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  // Apply search filters and re-layout
  useEffect(() => {
    const nsQ = nsSearch.trim().toLowerCase()
    const podQ = podSearch.trim().toLowerCase()

    const filteredNodes = rawNodes.filter(n => {
      if (n.kind === 'external') return true // always show external IPs
      if (nsQ && !n.namespace.toLowerCase().includes(nsQ)) return false
      if (podQ && !n.pod.toLowerCase().includes(podQ)) return false
      return true
    })

    const filteredIds = new Set(filteredNodes.map(n => n.id))
    const filteredEdges = rawEdges.filter(e =>
      filteredIds.has(e.source) && filteredIds.has(e.target)
    )

    // Remove external nodes that have no connections after pod filter
    const connectedIds = new Set(filteredEdges.flatMap(e => [e.source, e.target]))
    const visibleNodes = filteredNodes.filter(n => n.kind === 'pod' || connectedIds.has(n.id))

    setNodes(layoutNodes(visibleNodes))
    setEdges(layoutEdges(filteredEdges))
  }, [rawNodes, rawEdges, nsSearch, podSearch, setNodes, setEdges])

  const matchCount = useMemo(() => {
    const nsQ = nsSearch.trim().toLowerCase()
    const podQ = podSearch.trim().toLowerCase()
    if (!nsQ && !podQ) return null
    return rawNodes.filter(n => n.kind === 'pod' &&
      (!nsQ || n.namespace.toLowerCase().includes(nsQ)) &&
      (!podQ || n.pod.toLowerCase().includes(podQ))
    ).length
  }, [rawNodes, nsSearch, podSearch])

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const onNodeClick = useCallback((_: React.MouseEvent, node: any) => {
    setSelectedNode(node.data as TopologyNode)
  }, [])

  return (
    <>
      <div className="mb-4 flex items-start justify-between">
        <div>
          <h4 className="text-xl font-semibold">Network Topology</h4>
          <p className="text-sm text-muted-foreground">
            Pod network connections observed via Tetragon kprobe events
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={load} disabled={loading}>
          <IconRefresh size={14} className="mr-1.5" />
          Refresh
        </Button>
      </div>

      {/* Search bar */}
      <div className="mb-4 flex items-center gap-2">
        <div className="relative">
          <IconSearch size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Namespace..."
            value={nsSearch}
            onChange={e => setNsSearch(e.target.value)}
            className="h-8 w-40 pl-8 text-sm"
          />
        </div>
        <div className="relative">
          <IconSearch size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Pod name..."
            value={podSearch}
            onChange={e => setPodSearch(e.target.value)}
            className="h-8 w-44 pl-8 text-sm"
          />
        </div>
        {matchCount !== null && (
          <span className="text-xs text-muted-foreground">
            {matchCount} pod{matchCount !== 1 ? 's' : ''} matched
          </span>
        )}
        {(nsSearch || podSearch) && (
          <Button variant="ghost" size="sm" className="h-8 text-xs"
            onClick={() => { setNsSearch(''); setPodSearch('') }}>
            Clear
          </Button>
        )}
      </div>

      {/* No network events — guide user */}
      {!loading && hasNetworkEvents === false && (
        <Card className="mb-4 border-amber-500/30 bg-amber-500/5">
          <CardContent className="flex items-start gap-3 p-4">
            <IconAlertTriangle size={18} className="mt-0.5 shrink-0 text-amber-600" />
            <div className="flex flex-col gap-1">
              <p className="text-sm font-medium text-amber-700">No network connections recorded yet</p>
              <p className="text-xs text-amber-600">
                Apply the <span className="font-semibold">Monitor All Network (Outside Cluster)</span> template
                from Tracing Policy → Templates to start collecting TCP connection events.
                Connections will appear here once events are captured.
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
              nodeTypes={nodeTypes}
              fitView
              fitViewOptions={{ padding: 0.2 }}
            >
              <Background gap={16} size={1} />
              <Controls />
              <MiniMap nodeColor={n => n.type === 'external' ? '#f59e0b' : '#6366f1'} />
            </ReactFlow>
          )}
        </div>

        {/* Side panel */}
        {selectedNode && (
          <div className="w-64 shrink-0">
            <Card className="h-full">
              <CardContent className="p-4">
                <div className="mb-3 flex items-center justify-between">
                  <span className="text-sm font-semibold">Node Detail</span>
                  <button
                    type="button"
                    onClick={() => setSelectedNode(null)}
                    className="text-xs text-muted-foreground hover:text-foreground"
                  >
                    ✕
                  </button>
                </div>
                <div className="flex flex-col gap-2 text-xs">
                  <div>
                    <span className="text-muted-foreground">Type</span>
                    <div className="mt-0.5">
                      <Badge variant={selectedNode.kind === 'external' ? 'secondary' : 'default'} className="text-[10px]">
                        {selectedNode.kind === 'external' ? 'External IP' : 'Pod'}
                      </Badge>
                    </div>
                  </div>
                  {selectedNode.kind === 'pod' && (
                    <>
                      <div>
                        <span className="text-muted-foreground">Pod</span>
                        <div className="mt-0.5 font-mono font-medium break-all">{selectedNode.pod}</div>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Namespace</span>
                        <div className="mt-0.5 font-mono">{selectedNode.namespace}</div>
                      </div>
                    </>
                  )}
                  {selectedNode.kind === 'external' && (
                    <div>
                      <span className="text-muted-foreground">IP Address</span>
                      <div className="mt-0.5 font-mono font-medium">{selectedNode.label}</div>
                    </div>
                  )}
                  <div className="pt-1 text-[11px] text-muted-foreground">
                    {edges.filter(e =>
                      e.source === selectedNode.id || e.target === selectedNode.id
                    ).length} connection{edges.filter(e =>
                      e.source === selectedNode.id || e.target === selectedNode.id
                    ).length !== 1 ? 's' : ''}
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </>
  )
}
