import MonacoEditor, { loader } from '@monaco-editor/react'
import * as monaco from 'monaco-editor/editor/editor.api'
import 'monaco-editor/features/register.all'
import 'monaco-editor/languages/definitions/yaml/register'
import EditorWorker from 'monaco-editor/editor/editor.worker?worker'

// Monaco ships inside the bundle. The loader's default is to fetch it from a
// CDN at runtime, which the Content-Security-Policy blocks and an air-gapped
// cluster cannot reach. Only the editor core and YAML are imported: the full
// package also bundles the TypeScript, CSS, HTML and JSON language services.
self.MonacoEnvironment = { getWorker: () => new EditorWorker() }
loader.config({ monaco })

export default MonacoEditor
