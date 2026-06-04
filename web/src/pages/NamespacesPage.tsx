import { useEffect, useState } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from '@/components/ui/table'
import { Skeleton } from '@/components/ui/skeleton'
import { namespaceApi, policyApi } from '../api/client'
import { useToast } from '../layout/AppToaster'
import type { PolicyRecord } from '../api/types'

export function NamespacesPage() {
  const toast = useToast()
  const [namespaces, setNamespaces] = useState<string[]>([])
  const [policies, setPolicies] = useState<PolicyRecord[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([namespaceApi.list(), policyApi.list()])
      .then(([ns, p]) => {
        setNamespaces(ns)
        setPolicies(p)
      })
      .catch(() => toast.error('Failed to load namespaces'))
      .finally(() => setLoading(false))
  }, [])

  const policyCountByNs = (ns: string) =>
    policies.filter((p) => p.namespace === ns).length

  return (
    <>
      <h4 className="mb-6 text-lg font-semibold">Namespaces</h4>

      <Card>
        <CardContent className="p-0">
          {loading ? (
            <div className="flex flex-col gap-2 p-4">
              {Array.from({ length: 5 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full rounded-lg" />
              ))}
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Namespace</TableHead>
                  <TableHead className="text-center">Policies</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {namespaces.length === 0 ? (
                  <TableRow>
                    <TableCell
                      colSpan={2}
                      className="py-8 text-center text-muted-foreground"
                    >
                      No namespaces found
                    </TableCell>
                  </TableRow>
                ) : (
                  namespaces.map((ns) => (
                    <TableRow key={ns}>
                      <TableCell className="font-medium">{ns}</TableCell>
                      <TableCell className="text-center">
                        {policyCountByNs(ns)}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </>
  )
}
