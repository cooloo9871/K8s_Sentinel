import { Fragment, useCallback, useEffect, useRef, useState } from 'react'
import { Link, useMatch, useNavigate, useParams } from 'react-router-dom'
import {
  IconChevronDown, IconChevronRight, IconDownload, IconRefresh,
} from '@tabler/icons-react'
import { Card, CardContent } from '@/components/ui/card'
import {
  Table, TableHeader, TableBody, TableRow, TableHead, TableCell,
} from '@/components/ui/table'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import {
  registryApi,
  type Registry, type RegistryFinding, type RegistryImage, type RegistryInput, type RegistryType,
} from '../api/client'
import { useAuth } from '../layout/AuthContext'
import { useToast } from '../layout/AppToaster'
import { FilterPopover } from '../components/FilterPopover'
import { RelativeTime } from '../components/RelativeTime'
import { Count, FindingsTable } from '../components/FindingsTable'
import { downloadCSV } from '../utils/csv'
import {
  filterImages, summarizeImages, imageCsvRows, imagePath, scheduleLabel, leftOut, parseFilters,
  IMAGE_CSV_HEADERS,
} from '../utils/registries'

const BASE = '/registries'

const TYPES: { key: RegistryType; label: string }[] = [
  { key: 'harbor', label: 'Harbor' },
  { key: 'docker', label: 'Docker Registry' },
  { key: 'quay', label: 'Quay' },
]

const errorText = (e: unknown, fallback: string) =>
  e instanceof Error && e.message ? e.message : fallback

// A scan in progress changes by the second; an idle list only on a schedule
// measured in days.
const POLL_RUNNING_MS = 4_000
const POLL_IDLE_MS = 30_000

// What the last run of a registry amounts to, in a few words.
function RunStatus({ registry }: { registry: Registry }) {
  const run = registry.run
  if (run.running) {
    return (
      <span className="text-sm">
        Scanning{run.total > 0 ? `, ${run.done} of ${run.total}` : ''}
      </span>
    )
  }
  if (run.error) return <Badge variant="destructive" className="font-medium">Scan failed</Badge>
  if (!run.finishedAt) return <span className="text-sm text-muted-foreground">Not scanned yet</span>
  return <RelativeTime iso={run.finishedAt} />
}

// ── Form ────────────────────────────────────────────────────────────────────

const EMPTY: RegistryInput = {
  name: '', type: 'harbor', url: '', username: '', password: '',
  filters: [], intervalDays: 7, skipTLSVerify: false, caCert: '',
}

function RegistryForm({ initial, hasPassword, onSave, onCancel, saving }: {
  initial: RegistryInput
  hasPassword: boolean
  onSave: (c: RegistryInput) => void
  onCancel: () => void
  saving: boolean
}) {
  const [form, setForm] = useState(initial)
  const [filterText, setFilterText] = useState(initial.filters.join('\n'))
  const [interval, setIntervalText] = useState(String(initial.intervalDays))
  const [testing, setTesting] = useState(false)
  const [tested, setTested] = useState<
    { matched: number; maxImages: number; sample: string[] } | { error: string } | null
  >(null)
  const edited = () => { revision.current++; setTested(null) }
  const set = <K extends keyof RegistryInput>(k: K, v: RegistryInput[K]) => {
    setForm(f => ({ ...f, [k]: v }))
    edited()
  }

  const days = Number(interval)
  const intervalOk = Number.isInteger(days) && days >= 1 && days <= 30
  const filters = parseFilters(filterText)
  const value = (): RegistryInput => ({ ...form, filters, intervalDays: intervalOk ? days : 1 })
  const complete = form.name.trim() !== '' && form.url.trim() !== '' && filters.length > 0

  // Bumped by every edit, so an answer about what the form used to say is
  // dropped instead of being shown against what it says now.
  const revision = useRef(0)
  const test = async () => {
    setTesting(true)
    setTested(null)
    const asked = revision.current
    try {
      const result = await registryApi.test(value())
      if (revision.current === asked) setTested(result)
    } catch (e) {
      if (revision.current === asked) setTested({ error: errorText(e, 'The registry could not be reached') })
    } finally {
      setTesting(false)
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-1">
        <Label className="text-xs">Name <span className="text-destructive">*</span></Label>
        <Input className="h-8 text-sm" value={form.name} onChange={e => set('name', e.target.value)} />
      </div>

      <div className="flex flex-col gap-1">
        <Label className="text-xs">Registry type</Label>
        <div className="flex gap-2">
          {TYPES.map(t => (
            <Button key={t.key} size="sm" variant={form.type === t.key ? 'default' : 'outline'}
              className="h-7 text-xs" onClick={() => set('type', t.key)}>{t.label}</Button>
          ))}
        </div>
      </div>

      <div className="flex flex-col gap-1">
        <Label className="text-xs">URL <span className="text-destructive">*</span></Label>
        <Input className="h-8 font-mono text-sm" value={form.url} onChange={e => set('url', e.target.value)} />
        <p className="text-xs text-muted-foreground">
          The scheme and host only, such as https://harbor.internal or https://quay.io.
        </p>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="flex flex-col gap-1">
          <Label className="text-xs">Username</Label>
          <Input className="h-8 text-sm" autoComplete="off" value={form.username}
            onChange={e => set('username', e.target.value)} />
        </div>
        <div className="flex flex-col gap-1">
          <Label className="text-xs">Password</Label>
          <Input className="h-8 text-sm" type="password" autoComplete="new-password" value={form.password}
            onChange={e => set('password', e.target.value)} />
        </div>
        {hasPassword && (
          <p className="col-span-2 text-xs text-muted-foreground">
            A password is saved. Leave the field empty to keep it, unless the URL changes.
          </p>
        )}
      </div>

      <div className="flex flex-col gap-1">
        <Label className="text-xs">Filters <span className="text-destructive">*</span></Label>
        <textarea
          className="min-h-24 rounded-md border border-input bg-transparent px-3 py-2 font-mono text-sm shadow-xs outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50"
          value={filterText}
          onChange={e => { setFilterText(e.target.value); edited() }}
        />
        <p className="text-xs text-muted-foreground">
          Sample: <span className="font-mono">library/nginx:latest, library/*, library/*:*, library/n*:1*</span>
        </p>
      </div>

      <div className="flex flex-col gap-1">
        <Label className="text-xs">Scan every</Label>
        <div className="flex items-center gap-2">
          <Input className="h-8 w-20 text-sm" type="number" min={1} max={30} value={interval}
            onChange={e => setIntervalText(e.target.value)} />
          <span className="text-sm text-muted-foreground">days</span>
        </div>
        {!intervalOk && <p className="text-xs text-destructive">From 1 to 30.</p>}
      </div>

      <label className="flex cursor-pointer items-center gap-2 text-sm">
        <input type="checkbox" className="h-4 w-4 cursor-pointer accent-primary"
          checked={form.skipTLSVerify} onChange={e => set('skipTLSVerify', e.target.checked)} />
        Skip TLS certificate verification
        <span className="text-xs text-muted-foreground">accepts any certificate, so the registry's identity is not checked</span>
      </label>

      {!form.skipTLSVerify && (
        <div className="flex flex-col gap-1">
          <Label className="text-xs">CA certificate</Label>
          <textarea
            className="min-h-28 rounded-md border border-input bg-transparent px-3 py-2 font-mono text-xs shadow-xs outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50"
            spellCheck={false}
            value={form.caCert}
            onChange={e => set('caCert', e.target.value)}
          />
        </div>
      )}

      {tested && ('error' in tested ? (
        <Alert variant="destructive">
          <AlertDescription>{tested.error}</AlertDescription>
        </Alert>
      ) : (
        <Alert>
          <AlertDescription>
            <p>
              {tested.matched === 0
                ? 'No image matches these filters.'
                : `${tested.matched} image${tested.matched !== 1 ? 's' : ''} match${tested.matched === 1 ? 'es' : ''} these filters.`}
              {tested.matched > tested.maxImages &&
                ` Only the first ${tested.maxImages} will be scanned. Narrow the filters to cover the rest.`}
            </p>
            {tested.sample.length > 0 && (
              <ul className="mt-1.5 font-mono text-xs text-muted-foreground">
                {tested.sample.map(s => <li key={s} className="break-all">{s}</li>)}
                {tested.matched > tested.sample.length && <li>and {tested.matched - tested.sample.length} more</li>}
              </ul>
            )}
          </AlertDescription>
        </Alert>
      ))}

      <div className="flex justify-end gap-2 pt-1">
        <Button variant="outline" size="sm" className="mr-auto" onClick={test} disabled={testing || !complete}>
          {testing ? 'Listing the registry...' : 'Test filters'}
        </Button>
        <Button variant="outline" size="sm" onClick={onCancel} disabled={saving}>Cancel</Button>
        <Button size="sm" onClick={() => onSave(value())} disabled={saving || !complete || !intervalOk}>
          {saving ? 'Saving...' : 'Save'}
        </Button>
      </div>
    </div>
  )
}

// ── Images of one registry ──────────────────────────────────────────────────

type Findings = RegistryFinding[] | 'loading' | 'error'

function RegistryImages({ id, isAdmin }: { id: string; isAdmin: boolean }) {
  const toast = useToast()
  const [registry, setRegistry] = useState<Registry | null>(null)
  const [images, setImages] = useState<RegistryImage[]>([])
  const [missing, setMissing] = useState(false)
  const [loadError, setLoadError] = useState('')
  const [search, setSearch] = useState('')
  const [severities, setSeverities] = useState<string[]>([])
  const [flags, setFlags] = useState<string[]>([])
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [findings, setFindings] = useState<Record<string, Findings>>({})
  const [showAll, setShowAll] = useState<Set<string>>(new Set())
  // When each image's findings were fetched, to drop them once it is rescanned.
  const fetchedAt = useRef<Record<string, string | undefined>>({})

  const load = useCallback(async () => {
    try {
      const next = await registryApi.images(id)
      setRegistry(next.registry)
      setImages(next.images)
      setLoadError('')
      // Findings shown for an image that has since been rescanned are stale.
      setFindings(prev => {
        const kept: Record<string, Findings> = {}
        for (const img of next.images) {
          if (prev[img.image] !== undefined && fetchedAt.current[img.image] === img.scannedAt) {
            kept[img.image] = prev[img.image]
          }
        }
        return kept
      })
    } catch (e) {
      if ((e as { response?: { status?: number } })?.response?.status === 404) setMissing(true)
      else setLoadError(errorText(e, 'Failed to load the registry'))
    }
  }, [id])

  const running = registry?.run.running ?? false
  useEffect(() => {
    load()
    const timer = setInterval(load, running ? POLL_RUNNING_MS : POLL_IDLE_MS)
    return () => clearInterval(timer)
  }, [load, running])

  const fetchFindings = (img: RegistryImage) => {
    fetchedAt.current[img.image] = img.scannedAt
    setFindings(prev => ({ ...prev, [img.image]: 'loading' }))
    registryApi.findings(id, img.image)
      .then(f => setFindings(prev => ({ ...prev, [img.image]: f })))
      .catch(() => setFindings(prev => ({ ...prev, [img.image]: 'error' })))
  }

  const toggle = (img: RegistryImage) => {
    const opening = !expanded.has(img.image)
    setExpanded(prev => {
      const next = new Set(prev)
      opening ? next.add(img.image) : next.delete(img.image)
      return next
    })
    if (opening && img.scanned && !Array.isArray(findings[img.image])) fetchFindings(img)
  }

  // A row left open across a rescan lost its findings in load(); fetch the new ones.
  useEffect(() => {
    for (const img of images) {
      if (expanded.has(img.image) && img.scanned && findings[img.image] === undefined) fetchFindings(img)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [images, findings])

  const scan = async () => {
    try {
      await registryApi.scan(id)
      await load()
    } catch (e) {
      toast.error(errorText(e, 'The scan could not be started'))
    }
  }

  if (missing) {
    return (
      <>
        <h4 className="mb-4 text-xl font-semibold">Registry</h4>
        <Alert>
          <AlertDescription>
            This registry no longer exists. <Link to={BASE} className="underline underline-offset-2">Back to the list</Link>
          </AlertDescription>
        </Alert>
      </>
    )
  }
  if (!registry) {
    return loadError
      ? <Alert variant="destructive"><AlertDescription>{loadError}</AlertDescription></Alert>
      : null
  }

  const filtered = filterImages(images, { search, severities, flags })
  const isFiltered = search.trim() !== '' || severities.length > 0 || flags.length > 0
  const { critical, high, failed } = summarizeImages(filtered)
  const run = registry.run
  const excess = leftOut(registry)

  return (
    <>
      <div className="mb-4 flex items-start justify-between">
        <div>
          <h4 className="text-xl font-semibold">{registry.name}</h4>
          <p className="font-mono text-sm text-muted-foreground">{registry.url}</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" disabled={filtered.length === 0}
            onClick={() => downloadCSV(`${registry.name}-vulnerabilities.csv`, IMAGE_CSV_HEADERS, imageCsvRows(filtered))}>
            <IconDownload size={14} className="mr-1" /> Export CSV
          </Button>
          {isAdmin && (
            <Button variant="outline" size="sm" onClick={scan} disabled={running}>
              <IconRefresh size={14} className={`mr-1 ${running ? 'animate-spin' : ''}`} />
              {running ? 'Scanning...' : 'Scan now'}
            </Button>
          )}
        </div>
      </div>

      {loadError && (
        <Alert variant="destructive" className="mb-4">
          <AlertDescription>
            The list could not be refreshed, so what is shown may be out of date. {loadError}
          </AlertDescription>
        </Alert>
      )}
      {run.error && (
        <Alert variant="destructive" className="mb-4">
          <AlertDescription>
            The last scan did not complete
            {images.length > 0 && ', so some or all of the results below are from the scan before it'}. It will be
            tried again within the hour. {run.error}
          </AlertDescription>
        </Alert>
      )}
      {running && (
        <Alert className="mb-4">
          <AlertDescription>
            {run.total === 0
              ? 'Listing the registry...'
              : `Scanning: ${run.done} of ${run.total} images done. Results appear as each one finishes.`}
          </AlertDescription>
        </Alert>
      )}
      {excess > 0 && (
        <Alert className="mb-4">
          <AlertDescription>
            The filters match {run.matched} images and a scan covers the first {registry.maxImages}, so {excess} were
            left out. Narrow the filters, or split them across more than one registry entry, to cover the rest.
          </AlertDescription>
        </Alert>
      )}

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Input value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Search image..." className="h-8 w-56 text-sm" />
        <FilterPopover sections={[
          {
            label: 'Severity',
            value: severities,
            onChange: setSeverities,
            options: [
              { key: 'critical', label: 'Critical' },
              { key: 'high', label: 'High' },
              { key: 'medium', label: 'Medium' },
              { key: 'low', label: 'Low' },
              { key: 'unknown', label: 'Unknown' },
            ],
          },
          {
            label: 'Show only',
            value: flags,
            onChange: setFlags,
            options: [
              { key: 'fixable', label: 'Fix available' },
              { key: 'failed', label: 'Scan failed' },
            ],
          },
        ]} />
      </div>

      <Card className="overflow-x-hidden">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-1 border-b px-5 py-3 text-sm">
          <span className="text-muted-foreground">
            {filtered.length} image{filtered.length !== 1 ? 's' : ''}{isFiltered ? ' (filtered)' : ''}
          </span>
          <div className="flex items-center gap-1.5">
            <span className="size-2 rounded-full bg-destructive" />
            <span className="text-destructive">{critical} critical</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="size-2 rounded-full bg-orange-500" />
            <span className="text-orange-700">{high} high</span>
          </div>
          {failed > 0 && <span className="text-amber-700">{failed} could not be scanned</span>}
        </div>
        <CardContent className="p-0">
          {filtered.length === 0 ? (
            <div className="py-10 text-center text-sm text-muted-foreground">
              {images.length > 0 ? 'No images match the current filters.'
                : running ? 'No image has finished scanning yet.'
                : run.finishedAt && !run.error ? 'No image in the registry matches the filters.'
                : 'Nothing has been scanned yet.'}
            </div>
          ) : (
            <Table className="table-fixed">
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8" />
                  <TableHead>Image</TableHead>
                  <TableHead className="w-20 text-right">Critical</TableHead>
                  <TableHead className="w-20 text-right">High</TableHead>
                  <TableHead className="w-20 text-right">Medium</TableHead>
                  <TableHead className="w-20 text-right">Low</TableHead>
                  <TableHead className="w-20 text-right">Unknown</TableHead>
                  <TableHead className="w-20 text-right">Fixable</TableHead>
                  <TableHead className="w-28">Scanned</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map(img => {
                  const open = expanded.has(img.image)
                  const f = findings[img.image]
                  return (
                    <Fragment key={img.image}>
                      <TableRow className="cursor-pointer hover:bg-muted/50" onClick={() => toggle(img)}>
                        <TableCell className="py-2 pl-3 pr-0">
                          {open
                            ? <IconChevronDown size={14} className="text-muted-foreground" />
                            : <IconChevronRight size={14} className="text-muted-foreground" />}
                        </TableCell>
                        <TableCell className="truncate font-mono text-xs" title={img.image}>{imagePath(img.image)}</TableCell>
                        <TableCell className="text-right text-sm">
                          <Count value={img.counts.critical} scanned={img.scanned} className="text-destructive" />
                        </TableCell>
                        <TableCell className="text-right text-sm">
                          <Count value={img.counts.high} scanned={img.scanned} className="text-orange-700" />
                        </TableCell>
                        <TableCell className="text-right text-sm">
                          <Count value={img.counts.medium} scanned={img.scanned} className="text-amber-700" />
                        </TableCell>
                        <TableCell className="text-right text-sm">
                          <Count value={img.counts.low} scanned={img.scanned} className="text-foreground" />
                        </TableCell>
                        <TableCell className="text-right text-sm">
                          <Count value={img.counts.unknown} scanned={img.scanned} className="text-foreground" />
                        </TableCell>
                        <TableCell className="text-right text-sm">
                          <Count value={img.fixable} scanned={img.scanned} className="text-foreground" />
                        </TableCell>
                        <TableCell className="text-sm">
                          {img.scanned
                            ? <RelativeTime iso={img.scannedAt ?? ''} />
                            : <Badge className="bg-amber-500/15 font-medium text-amber-700 hover:bg-amber-500/15">Scan failed</Badge>}
                        </TableCell>
                      </TableRow>
                      {open && (
                        <TableRow className="bg-muted/30 hover:bg-muted/30">
                          <TableCell colSpan={9} className="py-3 pl-10 pr-6">
                            <div className="flex flex-col gap-3 text-xs">
                              <span className="font-mono" style={{ wordBreak: 'break-all' }}>{img.image}</span>
                              {!img.scanned && (
                                <p className="whitespace-normal text-amber-700" style={{ wordBreak: 'break-word' }}>
                                  The scan failed, so nothing is known about this image. {img.error}
                                </p>
                              )}
                              {f === 'loading' && <p className="text-muted-foreground">Loading findings...</p>}
                              {f === 'error' && <p className="text-destructive">The findings could not be loaded.</p>}
                              {Array.isArray(f) && f.length === 0 && (
                                <p className="text-muted-foreground">No known vulnerabilities in this image.</p>
                              )}
                              {Array.isArray(f) && (
                                <FindingsTable findings={f} showAll={showAll.has(img.image)}
                                  onShowAll={() => setShowAll(prev => new Set(prev).add(img.image))} />
                              )}
                            </div>
                          </TableCell>
                        </TableRow>
                      )}
                    </Fragment>
                  )
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </>
  )
}

// ── List, and the routes ────────────────────────────────────────────────────

export function RegistriesPage() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const toast = useToast()
  const navigate = useNavigate()
  // Which screen is up lives in the URL: the list, /new, /:id/edit, or /:id.
  const isNew = !!useMatch(`${BASE}/new`)
  const isEdit = !!useMatch(`${BASE}/:id/edit`)
  const { id } = useParams<{ id: string }>()

  const [registries, setRegistries] = useState<Registry[]>([])
  const [loaded, setLoaded] = useState(false)
  const [loadError, setLoadError] = useState('')
  const [saving, setSaving] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<Registry | null>(null)

  const load = useCallback(async () => {
    try {
      setRegistries(await registryApi.list())
      setLoadError('')
    } catch (e) {
      setLoadError(errorText(e, 'Failed to load registries'))
    } finally {
      setLoaded(true)
    }
  }, [])

  const anyRunning = registries.some(r => r.run.running)
  const onList = !isNew && !id
  useEffect(() => {
    load()
    if (!onList) return
    const timer = setInterval(load, anyRunning ? POLL_RUNNING_MS : POLL_IDLE_MS)
    return () => clearInterval(timer)
  }, [load, anyRunning, onList])

  const save = async (input: RegistryInput, existing?: Registry) => {
    setSaving(true)
    try {
      if (existing) await registryApi.update(existing.id, input)
      else await registryApi.create(input)
      toast.success(existing ? 'Registry saved. A new scan has started.' : 'Registry added. Its first scan has started.')
      await load()
      navigate(BASE)
    } catch (e) {
      toast.error(errorText(e, 'The registry could not be saved'))
    } finally {
      setSaving(false)
    }
  }

  const scan = async (r: Registry) => {
    try {
      await registryApi.scan(r.id)
      await load()
    } catch (e) {
      toast.error(errorText(e, 'The scan could not be started'))
    }
  }

  const remove = async () => {
    if (!deleteTarget) return
    try {
      await registryApi.delete(deleteTarget.id)
      await load()
    } catch (e) {
      toast.error(errorText(e, 'The registry could not be deleted'))
    } finally {
      setDeleteTarget(null)
    }
  }

  if (isAdmin && (isNew || isEdit)) {
    const editTarget = isEdit ? registries.find(r => r.id === id) : undefined
    if (isEdit && !editTarget) {
      return loaded
        ? <Alert><AlertDescription>This registry no longer exists. <Link to={BASE} className="underline underline-offset-2">Back to the list</Link></AlertDescription></Alert>
        : null
    }
    return (
      <>
        <div className="mb-6">
          <h4 className="text-xl font-semibold">{editTarget ? `Edit ${editTarget.name}` : 'Add Registry'}</h4>
        </div>
        <Card className="max-w-2xl">
          <CardContent className="pt-4">
            <RegistryForm
              key={editTarget?.id ?? 'new'}
              initial={editTarget
                ? {
                    id: editTarget.id, name: editTarget.name, type: editTarget.type, url: editTarget.url,
                    username: editTarget.username, password: '', filters: editTarget.filters,
                    intervalDays: editTarget.intervalDays, skipTLSVerify: editTarget.skipTLSVerify,
                    caCert: editTarget.caCert ?? '',
                  }
                : EMPTY}
              hasPassword={editTarget?.hasPassword ?? false}
              onSave={input => save(input, editTarget)}
              onCancel={() => navigate(BASE)}
              saving={saving}
            />
          </CardContent>
        </Card>
      </>
    )
  }

  if (id && !isEdit) return <RegistryImages key={id} id={id} isAdmin={isAdmin} />

  return (
    <>
      <div className="mb-4 flex items-start justify-between">
        <h4 className="text-xl font-semibold">Registries</h4>
        {isAdmin && <Button onClick={() => navigate(`${BASE}/new`)}>+ Add Registry</Button>}
      </div>

      {loadError && (
        <Alert variant="destructive" className="mb-4">
          <AlertDescription>{loadError}</AlertDescription>
        </Alert>
      )}

      <Card className="overflow-x-hidden">
        <CardContent className="p-0">
          {registries.length === 0 ? (
            <div className="py-10 text-center text-sm text-muted-foreground">
              {!loaded ? 'Loading...'
                : 'No registries yet. Add one to scan its images for vulnerabilities before they are deployed.'}
            </div>
          ) : (
            <Table className="table-fixed">
              <TableHeader>
                <TableRow>
                  <TableHead>Registry</TableHead>
                  <TableHead>Filters</TableHead>
                  <TableHead className="w-28">Schedule</TableHead>
                  <TableHead className="w-32">Last scan</TableHead>
                  <TableHead className="w-16 text-right">Images</TableHead>
                  <TableHead className="w-16 text-right">Critical</TableHead>
                  <TableHead className="w-16 text-right">High</TableHead>
                  <TableHead className="w-16 text-right">Failed</TableHead>
                  {isAdmin && <TableHead className="w-48" />}
                </TableRow>
              </TableHeader>
              <TableBody>
                {registries.map(r => {
                  const scanned = r.images - r.failed > 0
                  return (
                    <TableRow key={r.id} className="cursor-pointer hover:bg-muted/50" onClick={() => navigate(`${BASE}/${r.id}`)}>
                      <TableCell>
                        <div className="truncate text-sm font-medium" title={r.name}>{r.name}</div>
                        <div className="truncate font-mono text-xs text-muted-foreground" title={r.url}>{r.url}</div>
                      </TableCell>
                      <TableCell className="truncate font-mono text-xs" title={r.filters.join('\n')}>
                        {r.filters.join(', ')}
                      </TableCell>
                      <TableCell className="text-sm">{scheduleLabel(r.intervalDays)}</TableCell>
                      <TableCell><RunStatus registry={r} /></TableCell>
                      <TableCell className="text-right text-sm">{r.images}</TableCell>
                      <TableCell className="text-right text-sm">
                        <Count value={r.counts.critical} scanned={scanned} className="text-destructive" />
                      </TableCell>
                      <TableCell className="text-right text-sm">
                        <Count value={r.counts.high} scanned={scanned} className="text-orange-700" />
                      </TableCell>
                      <TableCell className="text-right text-sm">
                        <Count value={r.failed} scanned={r.images > 0} className="text-amber-700" />
                      </TableCell>
                      {isAdmin && (
                        <TableCell className="text-right" onClick={e => e.stopPropagation()}>
                          <Button variant="ghost" size="sm" className="h-7 text-xs"
                            onClick={() => scan(r)} disabled={r.run.running}>Scan now</Button>
                          <Button variant="ghost" size="sm" className="h-7 text-xs"
                            onClick={() => navigate(`${BASE}/${r.id}/edit`)}>Edit</Button>
                          <Button variant="ghost" size="sm" className="h-7 text-xs text-destructive hover:text-destructive"
                            onClick={() => setDeleteTarget(r)}>Delete</Button>
                        </TableCell>
                      )}
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <AlertDialog open={!!deleteTarget} onOpenChange={open => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Registry</AlertDialogTitle>
            <AlertDialogDescription>
              Delete <strong>{deleteTarget?.name}</strong> and the scan results kept for it? A scan in progress is stopped.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction variant="destructive" onClick={remove}>Delete</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
