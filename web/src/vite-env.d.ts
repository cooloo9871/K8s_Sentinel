/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Stamped in at image build time; absent in a dev server run. */
  readonly VITE_APP_VERSION?: string
}
