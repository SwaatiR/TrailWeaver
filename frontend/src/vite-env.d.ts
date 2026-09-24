/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_TRAILWEAVER_API_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
