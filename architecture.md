# Architecture
React/TypeScript frontend → FastAPI API → SQLAlchemy database and non-public local file storage. SHA-256 is computed server-side from uploaded bytes. Custody events use canonical sorted-key compact JSON (`json-sortkeys-compact-v1`) and link each event to the previous event hash. This is a tamper-evident local hash chain, not a connected blockchain or independent consensus network.
