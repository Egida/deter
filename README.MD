# Deter

[![Go Build](https://github.com/malwarebo/deter/actions/workflows/go-build.yml/badge.svg)](https://github.com/malwarebo/deter/actions/workflows/go-build.yml)

Automated DDoS mitigation for Cloudflare. Listens for Cloudflare DDoS webhook alerts, flips the zone into "Under Attack" mode, and signals a Cloudflare Worker to serve SHA-256 proof-of-work challenges to visitors until the attack ends.

## How it works

```
Cloudflare ──webhook──▶ Deter Server ──API──▶ Cloudflare (set "under_attack")
                              │
                              ▼
                         Workers KV (attack status)
                              │
                              ▼
                        Deter Worker ◀──HTTP──▶ Browser (PoW challenge)
```

1. Cloudflare sends a DDoS alert webhook to the server.
2. The server verifies the HMAC signature, parses the payload, and calls the Cloudflare API to set the zone's security level to `under_attack`.
3. It writes an `active` status to Workers KV so the edge worker knows an attack is happening.
4. The worker reads KV on each request. If active, it serves a proof-of-work challenge page. The browser computes a SHA-256 hash with the required difficulty, submits it back, and gets an HMAC-signed cookie that bypasses the challenge for 1 hour.
5. When the attack ends, Cloudflare sends another webhook. The server reverts the security level and sets KV to `inactive`.

Duplicate webhooks for the same zone are skipped (in-memory idempotency). Webhook timestamps older than 5 minutes are rejected to prevent replay attacks.

## Running the server

Requires Go 1.26+.

```bash
go build -o deter-server ./cmd/deter-server

export CF_API_TOKEN="your-cf-api-token"
export CF_ACCOUNT_ID="your-account-id"
export TARGET_ZONE_ID="your-zone-id"
export KV_NAMESPACE_ID="your-kv-namespace-id"
export CF_WEBHOOK_SECRET="your-webhook-secret"
./deter-server
```

## Deploying the worker

Requires [Wrangler](https://developers.cloudflare.com/workers/wrangler/).

1. Edit `worker/wrangler.toml` with your account ID, zone ID, and KV namespace ID.
2. Deploy:

```bash
cd worker
npx wrangler deploy
```

## Configuration

### Server (environment variables)

| Variable | Description | Default |
|----------|-------------|---------|
| `CF_API_TOKEN` | Cloudflare API token | *required* |
| `CF_ACCOUNT_ID` | Cloudflare account ID | *required* |
| `TARGET_ZONE_ID` | Zone ID to protect | *required* |
| `KV_NAMESPACE_ID` | KV namespace for attack status | *required* |
| `CF_WEBHOOK_SECRET` | HMAC secret for webhook signature verification | empty (verification skipped) |
| `LISTEN_ADDR` | Server listen address | `:8080` |
| `DEFAULT_SEC_LEVEL` | Security level to revert to after attack | `medium` |
| `KV_KEY_PREFIX` | Prefix for KV keys | `attack_status_zone_` |
| `WEBHOOK_TIMEOUT_SECONDS` | Timeout for webhook processing | `30` |

### Worker (wrangler.toml / env vars)

| Variable | Description | Default |
|----------|-------------|---------|
| `TARGET_ZONE_ID` | Zone ID (must match server config) | *required* |
| `KV_NAMESPACE` | KV namespace binding | *required* |
| `POW_DIFFICULTY` | Number of leading hex zeros required | `4` |
| `POW_SECRET` | HMAC secret for session cookies | `deter-pow-secret` |

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/cloudflare-webhook` | Receives Cloudflare DDoS alert webhooks |
| `GET` | `/health` | Returns `200 OK` |
