import { useState } from 'react'
import MonacoEditor from '@monaco-editor/react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import yaml from 'js-yaml'

interface Props {
  initialValue?: string
  onValueChange?: (value: string, valid: boolean) => void
  readOnly?: boolean
}

export function YamlEditor({ initialValue = '', onValueChange, readOnly = false }: Props) {
  const [error, setError] = useState('')

  const handleChange = (v: string | undefined) => {
    if (readOnly || !onValueChange) return
    const text = v ?? ''
    let valid = true
    let errMsg = ''
    try {
      yaml.load(text)
    } catch (e: unknown) {
      valid = false
      errMsg = e instanceof Error ? e.message : 'Invalid YAML'
    }
    setError(errMsg)
    onValueChange(text, valid)
  }

  return (
    <div className="flex flex-col gap-2">
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <MonacoEditor
        height="500px"
        language="yaml"
        theme="vs-dark"
        defaultValue={initialValue}
        onChange={handleChange}
        options={{ minimap: { enabled: false }, fontSize: 13, readOnly }}
      />
    </div>
  )
}
