PRAGMA foreign_keys = ON;
CREATE TABLE tenants (id TEXT PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE users (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), name TEXT NOT NULL, role TEXT NOT NULL);
CREATE INDEX users_tenant ON users(tenant_id);
CREATE TABLE api_tokens (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE documents (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), title TEXT NOT NULL, content TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX documents_tenant ON documents(tenant_id, id);
