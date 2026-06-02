import { useState } from 'react'
import MonacoEditor from '@monaco-editor/react'
import { CAlert } from '@coreui/react'
import yaml from 'js-yaml'

interface Props {
  initialValue?: string
  onValueChange: (value: string, valid: boolean) => void
}

export function YamlEditor({ initialValue = '', onValueChange }: Props) {
  const [error, setError] = useState('')

  const handleChange = (v: string | undefined) => {
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
    <div>
      {error && (
        <CAlert color="danger" className="mb-2" style={{ fontSize: '0.8rem' }}>
          {error}
        </CAlert>
      )}
      <MonacoEditor
        height="500px"
        language="yaml"
        theme="vs-dark"
        defaultValue={initialValue}
        onChange={handleChange}
        options={{ minimap: { enabled: false }, fontSize: 13 }}
      />
    </div>
  )
}
