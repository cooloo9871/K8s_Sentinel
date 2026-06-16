import { useCallback, useEffect, useState } from 'react'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import {
  Table, TableHeader, TableBody, TableRow, TableHead, TableCell,
} from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { vapApi, type VAPRecord, type VAPBindingRecord } from '../api/client'
import { YamlEditor } from '../components/YamlEditor'
import { useAuth } from '../layout/AuthContext'
import { useToast } from '../layout/AppToaster'
import { formatTWTime } from '../utils/time'
import { Input } from '@/components/ui/input'

type EditTarget = { kind: 'policy' | 'binding'; name?: string; yaml: string }

export function VAPPage() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const toast = useToast()

  const [policies, setPolicies] = useState<VAPRecord[]>([])
  const [bindings, setBindings] = useState<VAPBindingRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [editor, setEditor] = useState<EditTarget | null>(null)
  const [editorYaml, setEditorYaml] = useState('')
  const [editorValid, setEditorValid] = useState(true)
  const [saving, setSaving] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<{ kind: 'policy' | 'binding'; name: string } | null>(null)
  const [search, setSearch] = useState('')
  const [activeTab, setActiveTab] = useState<'policies' | 'bindings'>('policies')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [p, b] = await Promise.all([vapApi.listPolicies(), vapApi.listBindings()])
      setPolicies(p)
      setBindings(b)
    } catch { /* ignore */ }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  const openNew = (kind: 'policy' | 'binding') => {
    setEditorYaml('')
    setEditorValid(true)
    setEditor({ kind, yaml: '' })
  }

  const openEdit = async (kind: 'policy' | 'binding', name: string, rawYaml: string) => {
    setEditorYaml(rawYaml)
    setEditorValid(true)
    setEditor({ kind, name, yaml: rawYaml })
  }

  const handleSave = async () => {
    if (!editor || !editorValid) return
    setSaving(true)
    try {
      if (editor.kind === 'policy') {
        if (editor.name) await vapApi.updatePolicy(editor.name, editorYaml)
        else await vapApi.applyPolicy(editorYaml)
      } else {
        if (editor.name) await vapApi.updateBinding(editor.name, editorYaml)
        else await vapApi.applyBinding(editorYaml)
      }
      toast.success(`${editor.kind === 'policy' ? 'Policy' : 'Binding'} applied.`)
      setActiveTab(editor.kind === 'policy' ? 'policies' : 'bindings')
      setEditor(null)
      load()
    } catch (e: unknown) {
      toast.error((e as { response?: { data?: string } })?.response?.data || 'Failed to apply')
    } finally { setSaving(false) }
  }

  const handleDelete = async () => {
    if (!deleteTarget) return
    try {
      if (deleteTarget.kind === 'policy') await vapApi.deletePolicy(deleteTarget.name)
      else await vapApi.deleteBinding(deleteTarget.name)
      toast.success(`${deleteTarget.kind === 'policy' ? 'Policy' : 'Binding'} deleted.`)
      setDeleteTarget(null)
      load()
    } catch { toast.error('Failed to delete') }
  }

  // Editor view
  if (editor) {
    const title = editor.name
      ? `${isAdmin ? 'Edit' : 'View'} ${editor.kind === 'policy' ? 'Policy' : 'Binding'}`
      : `New ${editor.kind === 'policy' ? 'Policy' : 'Binding'}`
    return (
      <>
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h4 className="text-xl font-semibold">{title}</h4>
            {editor.name && <p className="text-sm text-muted-foreground">{editor.name}</p>}
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" onClick={() => setEditor(null)}>← Back</Button>
            {isAdmin && (
              <Button onClick={handleSave} disabled={!editorValid || saving}>
                {saving ? 'Applying...' : 'Apply'}
              </Button>
            )}
          </div>
        </div>
        <YamlEditor
          key={editor.name ?? 'new'}
          initialValue={editorYaml}
          readOnly={!isAdmin}
          onValueChange={(v, valid) => { setEditorYaml(v); setEditorValid(valid) }}
        />
      </>
    )
  }

  return (
    <>
      <div className="mb-6">
        <h4 className="text-xl font-semibold">Admission Policy</h4>
        <p className="text-sm text-muted-foreground">Manage Kubernetes ValidatingAdmissionPolicies and Bindings.</p>
      </div>

      <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as 'policies' | 'bindings')}>
        <TabsList variant="line" className="mb-4 w-full justify-start rounded-none border-b bg-transparent p-0">
          <TabsTrigger value="policies"
            className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent data-[state=active]:shadow-none">
            Policies
          </TabsTrigger>
          <TabsTrigger value="bindings"
            className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent data-[state=active]:shadow-none">
            Bindings
          </TabsTrigger>
        </TabsList>

        {/* Policies Tab */}
        <TabsContent value="policies">
          <div className="mb-4 flex items-center justify-between">
            <Input placeholder="Search by name..." value={search} onChange={e => setSearch(e.target.value)} className="h-8 w-56 text-sm" />
            {isAdmin && <Button size="sm" onClick={() => openNew('policy')}>+ New YAML</Button>}
          </div>
          <Card>
            <CardContent className="p-0">
              {loading ? (
                <div className="flex flex-col gap-2 p-4">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Failure Policy</TableHead>
                      <TableHead>Validations</TableHead>
                      <TableHead>Created By</TableHead>
                      <TableHead>Created Time</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {policies.filter(p => !search || p.name.toLowerCase().includes(search.toLowerCase())).length === 0 ? (
                      <TableRow><TableCell colSpan={7} className="py-10 text-center text-muted-foreground">No policies found</TableCell></TableRow>
                    ) : policies.filter(p => !search || p.name.toLowerCase().includes(search.toLowerCase())).map(p => (
                      <TableRow key={p.name}>
                        <TableCell className="font-medium">{p.name}</TableCell>
                        <TableCell>
                          <Badge variant={p.failurePolicy === 'Fail' ? 'destructive' : 'secondary'}>
                            {p.failurePolicy || '—'}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-muted-foreground">{p.validationCount}</TableCell>
                        <TableCell className="text-muted-foreground text-xs">{p.createdBy}</TableCell>
                        <TableCell className="text-muted-foreground">{formatTWTime(p.createdAt)}</TableCell>
                        <TableCell className="text-right">
                          <div className="flex justify-end gap-2">
                            <Button variant="outline" size="sm" onClick={() => openEdit('policy', p.name, p.rawYaml)}>
                              {isAdmin ? 'Edit' : 'View YAML'}
                            </Button>
                            {isAdmin && (
                              <Button variant="destructive" size="sm" onClick={() => setDeleteTarget({ kind: 'policy', name: p.name })}>Delete</Button>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Bindings Tab */}
        <TabsContent value="bindings">
          <div className="mb-4 flex items-center justify-between">
            <Input placeholder="Search by name..." value={search} onChange={e => setSearch(e.target.value)} className="h-8 w-56 text-sm" />
            {isAdmin && <Button size="sm" onClick={() => openNew('binding')}>+ New YAML</Button>}
          </div>
          <Card>
            <CardContent className="p-0">
              {loading ? (
                <div className="flex flex-col gap-2 p-4">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Policy</TableHead>
                      <TableHead>Validation Actions</TableHead>
                      <TableHead>Created By</TableHead>
                      <TableHead>Created Time</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {bindings.filter(b => !search || b.name.toLowerCase().includes(search.toLowerCase())).length === 0 ? (
                      <TableRow><TableCell colSpan={7} className="py-10 text-center text-muted-foreground">No bindings found</TableCell></TableRow>
                    ) : bindings.filter(b => !search || b.name.toLowerCase().includes(search.toLowerCase())).map(b => (
                      <TableRow key={b.name}>
                        <TableCell className="font-medium">{b.name}</TableCell>
                        <TableCell className="text-muted-foreground">{b.policyName}</TableCell>
                        <TableCell>
                          <div className="flex gap-1 flex-wrap">
                            {b.validationActions.map(a => (
                              <Badge key={a} variant={a === 'Deny' ? 'destructive' : 'secondary'} className="text-[10px]">{a}</Badge>
                            ))}
                          </div>
                        </TableCell>
                        <TableCell className="text-muted-foreground text-xs">{b.createdBy}</TableCell>
                        <TableCell className="text-muted-foreground">{formatTWTime(b.createdAt)}</TableCell>
                        <TableCell className="text-right">
                          <div className="flex justify-end gap-2">
                            <Button variant="outline" size="sm" onClick={() => openEdit('binding', b.name, b.rawYaml)}>
                              {isAdmin ? 'Edit' : 'View YAML'}
                            </Button>
                            {isAdmin && (
                              <Button variant="destructive" size="sm" onClick={() => setDeleteTarget({ kind: 'binding', name: b.name })}>Delete</Button>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <AlertDialog open={!!deleteTarget} onOpenChange={open => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete {deleteTarget?.kind === 'policy' ? 'Policy' : 'Binding'}</AlertDialogTitle>
            <AlertDialogDescription>Delete "{deleteTarget?.name}"? This cannot be undone.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction variant="destructive" onClick={handleDelete}>Delete</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
