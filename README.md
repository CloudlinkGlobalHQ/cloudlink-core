# cloudlink-core

Shared state and core utilities for Cloudlink.

Notes:
- SQLite remains the default local state backend.
- When `DATABASE_URL` points at Postgres, subscription + plan state can be stored in Postgres first as an incremental migration step for production billing.
